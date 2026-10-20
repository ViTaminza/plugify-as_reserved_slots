// as_reserved_slots — Plugify port of the Pisex admin_system module "Reserved_slots"
// ([AS] Reserved slots by ABKAM): keeps `public_slots` server slots free for players without the
// reserve flag.
//
// On every authorization of a human player:
//   * a player WITHOUT the reserve flag is kicked when more than public_slots non-reserve
//     players are connected;
//   * a player WITH the reserve flag kicks the first non-reserve player instead.
// The reserve permission is "reserve_flag" from reserved_slots.ini, checked as a core permission
// first and as a raw flag afterwards; the disconnect uses "kick_reason_id"
// (default 135 = NETWORK_DISCONNECT_REJECT_SERVERFULL, clamped to 39 = Kicked when negative).
//
// Porting notes:
//   * the original's engine->DisconnectClient is s2sdk::KickClient, which disconnects on the next
//     frame like the engine call did.
//   * gpGlobals->maxClients is pisexcompat's global-vars snapshot (refreshed every frame).
//   * s2sdk's OnClientAuthenticated is not delivered reliably (see plugins/perm_connector), so
//     the same handler also runs from a once-per-second reconcile
//     keyed by the slot's steamid. The first reconcile pass only records who is already online:
//     the original never re-evaluated players that were already connected, and doing so would
//     kick somebody right after a plugin reload on a full server.

#include <admin_api.hpp>

#include <pisex/pisex.hpp>

#include <plg/plugin.hpp>
#include <plg/string.hpp>
#include <plugin_export.h>
#include <s2sdk/s2sdk.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace {

// The object the ported module uses (the Pisex variable, now the consumer wrapper).
admin_system::AdminApi* g_pAdminApi = &admin_system::AdminApi::Get();

constexpr char kLogTag[] = "[as_reserved_slots]";
constexpr int kMaxSlots = 64;
constexpr char kConfigPath[] = "addons/configs/admin_system/reserved_slots.ini";

class AsReservedSlotsPlugin final : public plg::Plugin {
public:
	plg::PluginResult OnPluginStart() override;
	plg::PluginResult OnPluginUpdate(std::chrono::milliseconds dt) override;
	plg::PluginResult OnPluginEnd() override;

private:
	// The original ReservedSlotsConfig.
	struct Config {
		int publicSlots = 0;
		std::string reserveFlag = "@admin/reserve";
		int kickReasonId = 135; // NETWORK_DISCONNECT_REJECT_SERVERFULL
	};

	Config m_config;

	void LoadConfig();
	bool HasReserveAccess(int iSlot);
	int CountNonReservePlayers();
	int FindNonReservePlayerToKick(int avoidSlot);
	void KickClientForReserve(int iSlot, int iReasonId);
	void HandleClientAuthorized(int iSlot, uint64_t iSteamID64);

	// Once-per-second replacement for the (unreliable) s2sdk OnClientAuthenticated event.
	void ReconcileAuthorized();
	static constexpr auto kReconcileInterval = std::chrono::seconds(1);
	std::array<uint64_t, kMaxSlots> m_seenSteamIds{};
	bool m_seenSeeded = false;
	std::chrono::milliseconds m_sinceReconcile{0};
};

AsReservedSlotsPlugin g_asReservedSlotsPlugin;

// --- the ported module ------------------------------------------------------------------------

// The engine's maxClients from pisexcompat's global-vars snapshot, 0 when it is not available yet.
// The snapshot is only filled while a map is up: without one s2sdk's GetGameTime/GetGameFrameTime/
// GetMaxClients/GetGameTickCount print "Global Variables not initialized yet." (a server-console
// WARNING each) and answer defaults. OnPluginStart runs before the first map, so the pre-map
// LoadConfig() pass reads the file only and lets the deferred StartupServer pass - which runs from
// the first update with a map, after pisexcompat refreshed the snapshot - do the real computation.
int EngineMaxClients() {
	const pisex::GlobalVars* globals = pisex::IsGameReady() ? pisex::g_pUtils->GetCGlobalVars() : nullptr;
	return globals ? globals->maxClients : 0;
}

void AsReservedSlotsPlugin::LoadConfig() {
	m_config = Config{};

	if (const int iMaxClients = EngineMaxClients(); iMaxClients > 0) {
		m_config.publicSlots = iMaxClients > 2 ? iMaxClients - 2 : iMaxClients;
	}

	pisex::KeyValues::AutoDelete kv("ReservedSlots");
	if (!kv->LoadFromFile(kConfigPath)) {
		pisex::g_pUtils->ErrorLog("[%s] Failed to load %s, using defaults", kLogTag, kConfigPath);
		return;
	}

	// The default must live in its own object: GetString() hands the default pointer back when the
	// key is missing, and assigning that into the string it points into would be an overlapping
	// copy.
	const std::string defaultReserveFlag = m_config.reserveFlag;
	m_config.reserveFlag = kv->GetString("reserve_flag", defaultReserveFlag.c_str());
	m_config.publicSlots = kv->GetInt("public_slots", m_config.publicSlots);
	m_config.kickReasonId = kv->GetInt("kick_reason_id", m_config.kickReasonId);

	if (const int iMaxClients = EngineMaxClients(); iMaxClients > 0) {
		if (m_config.publicSlots < 0) {
			m_config.publicSlots = 0;
		}
		if (m_config.publicSlots > iMaxClients) {
			m_config.publicSlots = iMaxClients;
		}
	}

	if (m_config.kickReasonId < 0) {
		m_config.kickReasonId = 39;
	}
}

bool AsReservedSlotsPlugin::HasReserveAccess(int iSlot) {
	if (m_config.reserveFlag.empty()) {
		return false;
	}
	if (g_pAdminApi->HasPermission(iSlot, m_config.reserveFlag.c_str())) {
		return true;
	}
	return g_pAdminApi->HasFlag(iSlot, m_config.reserveFlag.c_str());
}

int AsReservedSlotsPlugin::CountNonReservePlayers() {
	const pisex::GlobalVars* globals = pisex::g_pUtils->GetCGlobalVars();
	if (!globals) {
		return 0;
	}
	int iCount = 0;
	for (int i = 0; i < globals->maxClients; ++i) {
		if (!pisex::g_pPlayers->IsConnected(i) || pisex::g_pPlayers->IsFakeClient(i)) {
			continue;
		}
		if (HasReserveAccess(i)) {
			continue;
		}
		++iCount;
	}
	return iCount;
}

int AsReservedSlotsPlugin::FindNonReservePlayerToKick(int avoidSlot) {
	const pisex::GlobalVars* globals = pisex::g_pUtils->GetCGlobalVars();
	if (!globals) {
		return -1;
	}
	for (int i = 0; i < globals->maxClients; ++i) {
		if (i == avoidSlot) {
			continue;
		}
		if (!pisex::g_pPlayers->IsConnected(i) || pisex::g_pPlayers->IsFakeClient(i)) {
			continue;
		}
		if (HasReserveAccess(i)) {
			continue;
		}
		return i;
	}
	return -1;
}

void AsReservedSlotsPlugin::KickClientForReserve(int iSlot, int iReasonId) {
	if (!pisex::g_pPlayers->IsConnected(iSlot)) {
		return;
	}
	if (!__s2sdk_KickClient) {
		pisex::g_pUtils->ErrorLog("[%s] Cannot kick slot %d: the s2sdk KickClient binding is missing", kLogTag,
								  iSlot);
		return;
	}
	// The original cast the reason to ENetworkDisconnectionReason and passed the slot's CPlayerSlot.
	s2sdk::KickClient(iSlot, static_cast<s2sdk::NetworkDisconnectionReason>(iReasonId), plg::string());
}

void AsReservedSlotsPlugin::HandleClientAuthorized(int iSlot, uint64_t iSteamID64) {
	if (iSlot < 0 || iSlot >= kMaxSlots) {
		return;
	}
	// The s2sdk event may report a 32-bit account id or 0 (see plugins/perm_connector); the slot's
	// own SteamID64 is what identifies the connection for the dedupe below - without it a
	// duplicate call would kick a second non-reserve player.
	const uint64_t canonical = pisex::g_pPlayers->GetSteamID64(iSlot);
	if (canonical != 0) {
		iSteamID64 = canonical;
	} else if (iSteamID64 < (1ull << 32)) {
		return; // not a SteamID64 yet - the reconcile pass picks the player up
	}
	if (iSteamID64 == 0 || m_seenSteamIds[static_cast<std::size_t>(iSlot)] == iSteamID64) {
		return; // already handled by the event or a previous reconcile pass
	}
	m_seenSteamIds[static_cast<std::size_t>(iSlot)] = iSteamID64;

	if (pisex::g_pPlayers->IsFakeClient(iSlot)) {
		return;
	}

	const pisex::GlobalVars* globals = pisex::g_pUtils->GetCGlobalVars();
	if (!globals) {
		return;
	}
	const int iMaxClients = globals->maxClients;
	if (iMaxClients <= 0) {
		return;
	}

	int iPublicSlots = m_config.publicSlots;
	if (iPublicSlots < 0) {
		iPublicSlots = 0;
	}
	if (iPublicSlots > iMaxClients) {
		iPublicSlots = iMaxClients;
	}

	const bool bHasReserve = HasReserveAccess(iSlot);
	const int iNonReserve = CountNonReservePlayers();

	if (!bHasReserve && iNonReserve > iPublicSlots) {
		KickClientForReserve(iSlot, m_config.kickReasonId);
		return;
	}

	if (bHasReserve && iNonReserve > iPublicSlots) {
		const int iTarget = FindNonReservePlayerToKick(iSlot);
		if (iTarget == -1) {
			return;
		}
		KickClientForReserve(iTarget, m_config.kickReasonId);
	}
}

void AsReservedSlotsPlugin::ReconcileAuthorized() {
	for (int iSlot = 0; iSlot < kMaxSlots; ++iSlot) {
		if (!pisex::g_pPlayers->IsConnected(iSlot)) {
			m_seenSteamIds[static_cast<std::size_t>(iSlot)] = 0;
			continue;
		}
		if (pisex::g_pPlayers->IsFakeClient(iSlot) || !pisex::g_pPlayers->IsAuthenticated(iSlot)) {
			continue;
		}
		const uint64_t steamid = pisex::g_pPlayers->GetSteamID64(iSlot);
		if (steamid == 0 || steamid == m_seenSteamIds[static_cast<std::size_t>(iSlot)]) {
			continue;
		}
		if (!m_seenSeeded) {
			m_seenSteamIds[static_cast<std::size_t>(iSlot)] = steamid;
			continue;
		}
		HandleClientAuthorized(iSlot, steamid);
	}
	m_seenSeeded = true;
}

// --- lifecycle ---------------------------------------------------------------------------------

plg::PluginResult AsReservedSlotsPlugin::OnPluginStart() {
	try {
		// "admin_system" makes pisexcompat resolve "addons/configs/admin_system/..." through the
		// shared <configs>/admin_system directory every admin plugin uses.
		pisex::Init("admin_system");

		pisex::g_pPlayers->HookOnClientAuthorized([](int iSlot, uint64_t iSteamID64) {
			g_asReservedSlotsPlugin.HandleClientAuthorized(iSlot, iSteamID64);
		});

		// The original loaded the config in StartupServer (when a map is running and the engine
		// globals exist). The config is also read right here: the s2sdk authorization event can
		// fire before the first update, and acting with an unloaded config (public_slots = 0)
		// would kick the joining player. The deferred pass re-reads the file with the real
		// maxClients once a map is running.
		LoadConfig();
		pisex::g_pUtils->StartupServer([] { g_asReservedSlotsPlugin.LoadConfig(); });

		m_sinceReconcile = kReconcileInterval;
		return {};
	} catch (const std::exception& ex) {
		pisex::g_pUtils->ErrorLog("[%s] OnPluginStart failed: %s", kLogTag, ex.what());
	} catch (...) {
		pisex::g_pUtils->ErrorLog("[%s] OnPluginStart failed with an unknown exception", kLogTag);
	}
	return {};
}

plg::PluginResult AsReservedSlotsPlugin::OnPluginUpdate(std::chrono::milliseconds dt) {
	try {
		pisex::Poll();
		m_sinceReconcile += dt;
		if (m_sinceReconcile >= kReconcileInterval) {
			m_sinceReconcile = std::chrono::milliseconds(0);
			ReconcileAuthorized();
		}
	} catch (const std::exception& ex) {
		pisex::g_pUtils->ErrorLog("[%s] OnPluginUpdate failed: %s", kLogTag, ex.what());
	} catch (...) {
		pisex::g_pUtils->ErrorLog("[%s] OnPluginUpdate failed with an unknown exception", kLogTag);
	}
	return {};
}

plg::PluginResult AsReservedSlotsPlugin::OnPluginEnd() {
	try {
		pisex::Shutdown();
	} catch (...) {
		// nothing left to do at unload
	}
	return {};
}

} // namespace

PLUGIFY_PLUGIN(PLUGIN_API, &g_asReservedSlotsPlugin)
