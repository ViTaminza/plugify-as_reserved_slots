// as_reserved_slots — Plugify port of the Pisex admin_system module "Reserved_slots"
// ([AS] Reserved slots by ABKAM): keeps `public_slots` server slots free for players without the
// reserve flag.
//
// Behaviour kept from the original:
//   * on every authorization of a human player a non-reserve player is kicked when more than
//     public_slots non-reserve players are connected;
//   * a player WITH the reserve flag kicks the first non-reserve player instead;
//   * the reserve permission is "reserve_flag" from reserved_slots.ini, checked as a core
//     permission first and as a raw flag afterwards;
//   * the disconnect uses "kick_reason_id" (default 135 = NETWORK_DISCONNECT_REJECT_SERVERFULL,
//     a negative value becomes 39 = Kicked);
//   * config defaults: public_slots = maxClients - 2 (maxClients for 1/2-slot servers), a missing
//     or malformed file keeps the defaults and logs the original's error line.
//
// Pure s2sdk, no pisexcompat and no s2guard (docs/PLUGIN_STANDARD.md §7). The safety rules of
// handoff/weaponskins/PITFALLS.md live in this file:
//   * A1/A7/C12 - OnPluginStart never returns Failed; OnPluginEnd symmetrically unregisters the
//     map, client-authenticated, client-connected and client-disconnect listeners and unhooks the
//     "player_disconnect" event, then drops the admin API pointer.
//   * B1/B2 - the map gate g_mapReady. The map listeners are registered in OnPluginStart;
//     readiness is latched by OnMapStart and by the first OnPluginUpdate of a plugin loaded into
//     a running map (unless an OnMapEnd was seen since OnPluginStart) and dropped by OnMapEnd.
//     No client, max-clients or admin call is made while the gate is shut, because s2sdk
//     dereferences a null client list before the first map and a torn-down one in the
//     OnMapEnd..OnMapStart window.
//   * map handover - an unfinished decision is parked in a PendingDecision keyed by SteamID64 +
//     map generation (not by slot), so an authentication event before OnMapEnd is not swallowed by
//     the next SeedAuthorized (public_slots would otherwise be bypassed). It survives exactly one
//     boundary and a bounded wall-clock age; nothing queries a client on the closed map. Before
//     the readiness gate, Reconcile observes every connected/authorized human and records the
//     canonical SteamID64 of an unseen one, which covers a missing OnClientAuthenticated callback;
//     a 0/32-bit auth event is only an AuthEventMarker until the canonical identity is readable.
//     Pending follows the SteamID64 into another slot across the boundary; seen follows the
//     identity too. The new map's seed skips a matching pending/marker identity, never kicks a
//     different/new occupant, and evaluates only after readiness + identity revalidation. Already
//     evaluated identities stay seen across the map, so reload/map never re-kicks them.
//   * C2 - every client access is behind 0 <= slot < 64 and the map gate; the plugin uses only
//     the client-object queries IsClientConnected/IsFakeClient/IsClientAuthorized/
//     GetClientSteamID64, so no entity handle is involved (C1's 0/-1 rule does not apply here).
//   * C11 - this module owns no console command (the original registered none); there is
//     therefore no command to remove on unload and no command source to filter.
//   * C13/A7 - "player_disconnect" is a game event hooked in Pre mode; its player-typed "userid"
//     field is read with s2sdk::GetEventPlayerSlot (never the raw int), and the handler only
//     clears local slot state - it makes no client call.
//
// The pisexcompat pieces are replaced by local code:
//   * pisex::Init("admin_system") -> the map listeners + admin_system::AdminApi pointer;
//   * pisex::g_pPlayers->HookOnClientAuthorized -> s2sdk OnClientAuthenticated_Register (plus the
//     once-per-second reconcile of PITFALLS B6), OnClientConnected/OnClientDisconnect for slot
//     reuse, and the "player_disconnect" event as a redundant state clear;
//   * pisex::KeyValues -> src/kv1.hpp + src/config.hpp (the .ini format is unchanged);
//   * pisex::g_pPlayers->IsConnected/IsFakeClient/IsAuthenticated/GetSteamID64 -> the guarded
//     wrappers below, each of which checks the map gate and its binding first;
//   * pisex::g_pUtils->GetCGlobalVars()->maxClients -> s2sdk::GetMaxClients (map-gated, clamped
//     to the 64 CS2 slots);
//   * pisex::g_pUtils->ErrorLog -> plg::Log(Severity::Error).
//
// Permission readiness (the admin_system::IsClientAdminDataReady contract):
//   admin_system loads a player's admin record ASYNCHRONOUSLY. Its producer export
//   IsClientAdminDataReady(slot, steamid) is true ONLY after the SELECT for exactly this
//   slot + SteamID64 + generation completed - including the definitive zero-row answer. false
//   covers pending, failed, missing core/binding, unknown identity and a reclaimed/reused slot.
//   This port therefore:
//     - keeps OnClientAuthenticated state-only (no client/permission query, no kick);
//     - builds one authoritative snapshot per reconcile of every relevant connected human. If any
//       identity is unknown or IsClientAdminDataReady is false, the WHOLE pass is abandoned:
//       no HasPermission/HasFlag, no KickClient, and the pending slot stays unseen for a retry;
//     - revalidates identity + IsClientAdminDataReady for the joining player and the chosen victim
//       immediately before KickClient(), so a slot reuse after the snapshot cannot inherit the
//       previous occupant's answer;
//     - treats missing bindings/IsCoreLoaded()==false the same way: fail-open/no kick, no
//       permission query, one log.
//   A true answer does NOT mean "this player is an admin": after true, HasPermission()/HasFlag()
//   may still answer false (zero rows), and that is the authoritative non-reserve case.

#include "config.hpp"

#include <admin_api.hpp>

#include <plg/plugin.hpp>
#include <plg/string.hpp>
#include <plugin_export.h>
#include <s2sdk/s2sdk.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>

namespace {

constexpr char kLogTag[] = "[as_reserved_slots]";
// CS2 has 64 player slots. The original iterated 0..gpGlobals->maxClients-1; the port clamps the
// engine value to this range so a bogus/oversized value can never touch an out-of-range slot.
constexpr int32_t kMaxSlots = 64;
constexpr auto kReconcileInterval = std::chrono::seconds(1);
// A pending decision may survive exactly one map boundary and at most this wall-clock age. The
// generation bound is the deterministic limit used by the tests; the age is a second guard.
constexpr auto kPendingMaxAge = std::chrono::minutes(10);

// The admin_system consumer API (the original's g_pAdminApi). Set in OnPluginStart and dropped in
// OnPluginEnd, so a callback the engine still holds for a moment cannot reach it (PITFALLS A7).
admin_system::AdminApi* g_pAdminApi = nullptr;

// --- PITFALLS B1/B2: the map gate ------------------------------------------------

bool g_mapReady = false;           // a map is up: s2sdk client/max-client calls are safe
bool g_mapEndedSinceStart = false; // OnMapEnd was seen since OnPluginStart
bool g_firstUpdateDone = false;    // the mid-map latch has already been decided
bool g_mapListeners = false;       // OnMapStart/OnMapEnd are registered with s2sdk
bool g_mapTransition = false;      // OnMapEnd seen, the next OnMapStart has not arrived yet

// Listener bookkeeping (PITFALLS A7: every registration has a matching removal).
bool g_authListener = false;
bool g_connectListener = false;
bool g_disconnectListener = false;
bool g_disconnectEventHooked = false;

// Rate limits for conditions that would otherwise log every frame.
bool g_loggedNoMapListeners = false;
bool g_loggedNoAuthBinding = false;
bool g_loggedNoConnectBinding = false;
bool g_loggedNoDisconnectBinding = false;
bool g_loggedNoClientBindings = false;
bool g_loggedNoAdminBindings = false;
bool g_loggedNoKickBinding = false;
bool g_loggedNoEventSlot = false;
bool g_loggedNoMaxClientsBinding = false;
bool g_loggedNoConfigsDir = false;

void LogMessage(std::string_view message, plg::Severity severity) {
	if (plg::Log) {
		plg::Log(message, severity, plg::source_location::current());
	}
}

void LogInfo(std::string_view message) {
	LogMessage(message, plg::Severity::Info);
}

void LogError(std::string_view message) {
	LogMessage(message, plg::Severity::Error);
}

void LogErrorOnce(bool& flag, std::string_view message) {
	if (flag) {
		return;
	}
	flag = true;
	LogError(message);
}

bool ValidSlot(int32_t slot) {
	return slot >= 0 && slot < kMaxSlots;
}

// --- guarded s2sdk access ---------------------------------------------------------

// The binding set every client query needs. All four are checked together so a missing binding
// makes the plugin fail soft instead of dereferencing a null function pointer.
bool ClientQueryBindingsAvailable() {
	const bool available = __s2sdk_IsClientConnected && __s2sdk_IsFakeClient &&
						   __s2sdk_IsClientAuthorized && __s2sdk_GetClientSteamID64;
	if (!available) {
		LogErrorOnce(g_loggedNoClientBindings,
					 std::string(kLogTag) +
							 " the s2sdk client bindings are unavailable - reserved slots are not enforced");
	}
	return available;
}

bool SafeIsClientConnected(int32_t slot) {
	if (!g_mapReady || !ValidSlot(slot) || __s2sdk_IsClientConnected == nullptr) {
		return false;
	}
	try {
		return s2sdk::IsClientConnected(slot);
	} catch (...) {
		return false;
	}
}

bool SafeIsFakeClient(int32_t slot) {
	if (!g_mapReady || !ValidSlot(slot) || __s2sdk_IsFakeClient == nullptr) {
		return false;
	}
	try {
		return s2sdk::IsFakeClient(slot);
	} catch (...) {
		return false;
	}
}

bool SafeIsClientAuthorized(int32_t slot) {
	if (!g_mapReady || !ValidSlot(slot) || __s2sdk_IsClientAuthorized == nullptr) {
		return false;
	}
	try {
		return s2sdk::IsClientAuthorized(slot);
	} catch (...) {
		return false;
	}
}

uint64_t SafeClientSteamID64(int32_t slot) {
	if (!g_mapReady || !ValidSlot(slot) || __s2sdk_GetClientSteamID64 == nullptr) {
		return 0;
	}
	try {
		return s2sdk::GetClientSteamID64(slot);
	} catch (...) {
		return 0;
	}
}

// The engine's maxClients, 0 when it cannot be read yet. GetMaxClients prints a warning and
// answers -1 before gpGlobals exists, so the map gate must already be open; 0 keeps the caller in
// the "not ready, retry" path without treating a missing value as a real slot count.
int32_t ReadMaxClients() {
	if (!g_mapReady || __s2sdk_GetMaxClients == nullptr) {
		if (__s2sdk_GetMaxClients == nullptr) {
			LogErrorOnce(g_loggedNoMaxClientsBinding,
						 std::string(kLogTag) +
								 " the s2sdk GetMaxClients binding is unavailable - reserved slots are not enforced");
		}
		return 0;
	}
	try {
		const int32_t maxClients = s2sdk::GetMaxClients();
		if (maxClients <= 0) {
			return 0;
		}
		return std::min(maxClients, kMaxSlots);
	} catch (...) {
		return 0;
	}
}

// --- admin_system access -----------------------------------------------------------

// admin_api.hpp::HasPermission()/HasFlag() return false when admin_system is not loaded. That is
// indistinguishable from "the player is not an admin", so the plugin must never use them before
// checking the bindings and the core's own readiness (see the comment at the top of this file).
bool AdminBindingsAvailable() {
	return __admin_system_GetPluginVersion && __admin_system_IsCoreLoaded &&
		   __admin_system_HasPermission && __admin_system_HasFlag &&
		   __admin_system_IsClientAdminDataReady;
}

bool AdminCoreReady() {
	return g_pAdminApi != nullptr && AdminBindingsAvailable() && g_pAdminApi->IsCoreLoaded();
}

// The producer's per-player completion bit. false covers every unknown state: missing binding,
// pending SELECT, failed SELECT, identity mismatch, slot reuse. The caller must not query
// HasPermission()/HasFlag() or kick while this is false (fail-open/no kick).
bool AdminDataReady(int32_t slot, uint64_t steamid) {
	if (!ValidSlot(slot) || steamid == 0 || __admin_system_IsClientAdminDataReady == nullptr) {
		return false;
	}
	try {
		return admin_system::IsClientAdminDataReady(slot, steamid);
	} catch (...) {
		return false;
	}
}

// The original's HasReserveAccess(): permission first, then the raw flag. The caller has already
// checked AdminCoreReady() and AdminDataReady() for this slot+SteamID, so a false answer means
// "this slot does not carry the flag", not "admin_system is missing" or "the SELECT is pending".
bool HasReserveAccess(const as_reserved_slots::Config& config, int32_t slot) {
	if (config.reserveFlag.empty() || !AdminCoreReady()) {
		return false;
	}
	if (g_pAdminApi->HasPermission(slot, config.reserveFlag.c_str())) {
		return true;
	}
	return g_pAdminApi->HasFlag(slot, config.reserveFlag.c_str());
}

// --- the authoritative per-tick client snapshot -------------------------------------
// Built once per reconcile pass, only after every relevant client's admin data is ready. It is
// the only source of truth for the count and the victim choice: if one connected human has no
// authoritative identity/readiness, the whole pass is abandoned without a single permission
// query or kick (fail-open).

struct ReadyClient {
	int32_t slot = -1;
	uint64_t steamid = 0;
	bool hasReserve = false;
};

struct ReadySnapshot {
	std::array<ReadyClient, static_cast<std::size_t>(kMaxSlots)> clients{};
	int32_t count = 0;
	bool complete = false;

	const ReadyClient* Find(int32_t slot) const {
		for (int32_t i = 0; i < count; ++i) {
			if (clients[static_cast<std::size_t>(i)].slot == slot) {
				return &clients[static_cast<std::size_t>(i)];
			}
		}
		return nullptr;
	}
};

// An authentication event / observed not-yet-evaluated identity. It is keyed by SteamID64, NOT by
// slot: a changelevel may move the same player to another slot and the decision must follow the
// identity. A reused slot therefore can never inherit the previous occupant's decision.
// mapGeneration survives exactly one OnMapEnd; created bounds it in wall-clock time. Only
// OnClientAuthenticated or the map-open ObserveNewClients() creates a record; OnMapEnd/OnMapStart
// and the reconcile prune them.
struct PendingDecision {
	uint64_t steamid = 0;
	uint64_t mapGeneration = 0;
	std::chrono::steady_clock::time_point created{};
	bool active = false;
};

bool DecisionWindowValid(uint64_t mapGeneration, std::chrono::steady_clock::time_point created,
						 uint64_t currentGeneration) {
	// Created on map N: valid on N and N+1, dropped on the second changelevel.
	if (mapGeneration + 1 < currentGeneration) {
		return false;
	}
	return std::chrono::steady_clock::now() - created <= kPendingMaxAge;
}

bool PendingIsValid(const PendingDecision& pending, uint64_t currentGeneration) {
	return pending.active && pending.steamid != 0 &&
		   DecisionWindowValid(pending.mapGeneration, pending.created, currentGeneration);
}

// An authentication event whose payload was 0/32-bit: it proves that a new connection is
// authenticating but carries no identity. It is state-only (no client query); when the canonical
// SteamID64 becomes readable, Seed/Observe either resolves it into a PendingDecision or discards
// it for a different occupant. Bounded by the same one-map/age rule as PendingDecision.
struct AuthEventMarker {
	uint64_t mapGeneration = 0;
	std::chrono::steady_clock::time_point created{};
	bool active = false;
};

bool MarkerIsValid(const AuthEventMarker& marker, uint64_t currentGeneration) {
	return marker.active &&
		   DecisionWindowValid(marker.mapGeneration, marker.created, currentGeneration);
}

// --- the plugin ---------------------------------------------------------------------

class AsReservedSlotsPlugin final : public plg::Plugin {
public:
	plg::PluginResult OnPluginStart() override;
	plg::PluginResult OnPluginUpdate(std::chrono::milliseconds dt) override;
	plg::PluginResult OnPluginEnd() override;

	// OnClientAuthenticated. State only: no client query, no permission query, no kick. The
	// decision is made by a reconcile only after IsClientAdminDataReady(slot, steamid) reports a
	// completed SELECT for exactly this slot + SteamID64.
	void OnClientAuthenticated(int32_t slot, uint64_t steamid);
	// OnClientConnected / OnClientDisconnect (and the player_disconnect event fallback): only
	// reset the slot's bookkeeping, so a reused slot is never mistaken for its previous occupant.
	void OnClientConnected(int32_t slot);
	void OnClientDisconnected(int32_t slot);
	// OnMapEnd/OnMapStart: state only, never a client call (PITFALLS B2). Pending decisions are
	// carried across exactly one map boundary; already evaluated players stay seen.
	void OnMapEnded();
	void OnMapStarted();

private:
	as_reserved_slots::Config m_config;
	bool m_configReady = false;
	int32_t m_maxClients = 0;

	// Per-slot bookkeeping keyed by the connection, not by the slot:
	//   m_seenSteamIds  - the identity this slot was last evaluated for (dedupe, survives a map
	//                     change only while the same identity is still in the slot);
	//   m_pending       - an authentication event/decision that has not completed yet (carried
	//                     across one map boundary, keyed by SteamID64 + generation);
	//   m_lastConnected - the slot was connected on the previous reconcile pass (reuse detection).
	std::array<uint64_t, static_cast<std::size_t>(kMaxSlots)> m_seenSteamIds{};
	// Pending decisions are keyed by SteamID64, not by slot: a changelevel may move the same
	// player to another slot. At most 64 (one per possible identity).
	std::array<PendingDecision, static_cast<std::size_t>(kMaxSlots)> m_pending{};
	// Last canonical identity observed for a slot, used to clear its identity-keyed pending record
	// on a normal disconnect (no client query in the disconnect callback).
	std::array<uint64_t, static_cast<std::size_t>(kMaxSlots)> m_lastIdentity{};
	// Last identity this slot held before the current connection; preserved across a map boundary
	// so Seed can tell a NEW occupant/new join from the reload seed of an already-online player.
	std::array<uint64_t, static_cast<std::size_t>(kMaxSlots)> m_previousIdentity{};
	// OnClientConnected fired since the last Seed/reconcile: state-only proof that this slot saw a
	// NEW connection (as opposed to an old/reload player that was already connected). It lets Seed
	// distinguish a new join from the reload seed of an existing player without querying anything.
	std::array<bool, static_cast<std::size_t>(kMaxSlots)> m_connectMarker{};
	// 0/32-bit OnClientAuthenticated payload: state-only proof of a new connection, resolved to a
	// PendingDecision when the canonical SteamID64 becomes readable.
	std::array<AuthEventMarker, static_cast<std::size_t>(kMaxSlots)> m_authMarker{};
	std::array<bool, static_cast<std::size_t>(kMaxSlots)> m_lastConnected{};
	uint64_t m_mapGeneration = 0;
	// Slots already disconnected by this reconcile pass. A kick is delivered on the next frame, so
	// without this the loop could count a just-kicked player again or pick it as the next victim.
	std::array<bool, static_cast<std::size_t>(kMaxSlots)> m_kickedThisPass{};
	bool m_seenSeeded = false;
	std::chrono::milliseconds m_sinceReconcile{0};

	enum class Evaluation {
		Done,     // a decision was made with authoritative data (kicked or allowed)
		NotReady  // missing/not-ready data, identity/reuse race or a failed kick: retry later
	};

	void ResetSlot(int32_t slot);
	void ResetSlotState();
	void ClearPendingForIdentity(uint64_t steamid);
	void SetPending(uint64_t steamid);
	bool HasPending(uint64_t steamid) const;
	int32_t FindSeenSlotByIdentity(uint64_t steamid) const;
	void MarkSeen(int32_t slot, uint64_t steamid);
	void SetAuthMarker(int32_t slot);
	void ClearAuthMarker(int32_t slot);
	bool HasAuthMarker(int32_t slot) const;
	void PrunePending();
	void ObserveNewClients(int32_t maxClients);
	void RegisterListeners();
	void UnregisterListeners();
	bool LoadConfigIfPossible();

	void ReconcileAuthorized();
	void SeedAuthorized(int32_t maxClients);
	bool BuildSnapshot(int32_t maxClients, ReadySnapshot& snapshot) const;
	bool RevalidateClient(int32_t slot, uint64_t steamid) const;
	Evaluation EvaluateSlot(int32_t slot, uint64_t steamid, const ReadySnapshot& snapshot);
	int CountNonReservePlayers(const ReadySnapshot& snapshot) const;
	const ReadyClient* FindNonReservePlayerToKick(int32_t avoidSlot, const ReadySnapshot& snapshot) const;
	bool KickClientForReserve(int32_t slot, uint64_t steamid, int reason);
};

AsReservedSlotsPlugin g_asReservedSlotsPlugin;

// --- the s2sdk callbacks (plain function pointers, called on the game thread) --------

// PITFALLS B1/B2: OnMapStart is the first live frame of the new map; OnMapEnd runs while the
// client list is being torn down and only parks state (no client query). Unfinished decisions
// survive that boundary; seen identities stay seen.
void OnMapStartListener() {
	g_mapReady = true;
	g_mapEndedSinceStart = false;
	g_mapTransition = false;
	try {
		g_asReservedSlotsPlugin.OnMapStarted();
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnMapStart failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnMapStart failed with an unknown exception");
	}
}

void OnMapEndListener() {
	g_mapReady = false;
	g_mapEndedSinceStart = true;
	g_mapTransition = true;
	try {
		g_asReservedSlotsPlugin.OnMapEnded();
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnMapEnd failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnMapEnd failed with an unknown exception");
	}
}

void OnClientAuthenticatedListener(int32_t slot, uint64_t steamid) {
	try {
		g_asReservedSlotsPlugin.OnClientAuthenticated(slot, steamid);
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnClientAuthenticated failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnClientAuthenticated failed with an unknown exception");
	}
}

void OnClientConnectedListener(int32_t slot) {
	try {
		g_asReservedSlotsPlugin.OnClientConnected(slot);
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnClientConnected failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnClientConnected failed with an unknown exception");
	}
}

void OnClientDisconnectListener(int32_t slot, s2sdk::NetworkDisconnectionReason reason) {
	(void)reason;
	try {
		g_asReservedSlotsPlugin.OnClientDisconnected(slot);
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnClientDisconnect failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnClientDisconnect failed with an unknown exception");
	}
}

// PITFALLS C13: "userid" of a game event is not a slot; GetEventPlayerSlot resolves it. The
// handler only clears local state, so it is safe even at a changelevel. It is a redundant safety
// net when OnClientDisconnect is not delivered.
s2sdk::ResultType OnPlayerDisconnectEvent(const plg::string& /*name*/, void* event, bool /*dontBroadcast*/) {
	try {
		if (g_pAdminApi == nullptr) {
			return s2sdk::ResultType::Continue;
		}
		if (event == nullptr) {
			return s2sdk::ResultType::Continue;
		}
		if (__s2sdk_GetEventPlayerSlot == nullptr) {
			LogErrorOnce(g_loggedNoEventSlot,
						 std::string(kLogTag) +
								 " the s2sdk GetEventPlayerSlot binding is unavailable - the player_disconnect fallback is disabled");
			return s2sdk::ResultType::Continue;
		}
		const int32_t slot = s2sdk::GetEventPlayerSlot(event, plg::string("userid"));
		if (ValidSlot(slot)) {
			g_asReservedSlotsPlugin.OnClientDisconnected(slot);
		}
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " player_disconnect failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " player_disconnect failed with an unknown exception");
	}
	// Continue: the engine's own disconnect handling and every other plugin's hook must run.
	return s2sdk::ResultType::Continue;
}

// --- lifecycle -------------------------------------------------------------------------

plg::PluginResult AsReservedSlotsPlugin::OnPluginStart() {
	try {
		g_pAdminApi = &admin_system::AdminApi::Get();

		g_mapReady = false;
		g_mapEndedSinceStart = false;
		g_firstUpdateDone = false;
		m_configReady = false;
		m_maxClients = 0;
		m_config = as_reserved_slots::Config{};
		ResetSlotState();

		g_loggedNoMapListeners = false;
		g_loggedNoAuthBinding = false;
		g_loggedNoConnectBinding = false;
		g_loggedNoDisconnectBinding = false;
		g_loggedNoClientBindings = false;
		g_loggedNoAdminBindings = false;
		g_loggedNoKickBinding = false;
		g_loggedNoEventSlot = false;
		g_loggedNoMaxClientsBinding = false;
		g_loggedNoConfigsDir = false;

		RegisterListeners();

		if (!AdminBindingsAvailable()) {
			LogErrorOnce(g_loggedNoAdminBindings,
						 std::string(kLogTag) +
							 " the admin_system bindings are unavailable - reserved slots are not enforced");
		} else if (g_pAdminApi != nullptr && !g_pAdminApi->IsCoreLoaded()) {
			// Not fatal: the core loads its database/config asynchronously; the reconcile retries.
			LogInfo(std::string(kLogTag) +
					" admin_system is not ready yet - reserved-slot checks start when it is");
		}
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnPluginStart failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnPluginStart failed with an unknown exception");
	}
	return {}; // never Failed (PITFALLS A1)
}

plg::PluginResult AsReservedSlotsPlugin::OnPluginUpdate(std::chrono::milliseconds dt) {
	try {
		// A plugin loaded into a running map never saw OnMapStart: its first update is the "map is
		// up" signal (PITFALLS B1). An OnMapEnd since OnPluginStart means the server is between
		// maps, so the latch waits for the next OnMapStart instead.
		if (!g_firstUpdateDone) {
			g_firstUpdateDone = true;
			if (g_mapListeners && !g_mapEndedSinceStart) {
				g_mapReady = true;
			}
		}

		if (!g_mapReady) {
			return {};
		}

		// The config is read after the first map exists: its default needs maxClients, and
		// GetMaxClients must not be called before a map (PITFALLS B1). Reading it is
		// a pure file operation; the plugin only enforces after it succeeded.
		if (!m_configReady && !LoadConfigIfPossible()) {
			return {};
		}

		// The first ready pass only records who is already online: the original never re-evaluated
		// players that were already connected, and doing so would kick somebody right after a
		// plugin reload on a full server (PITFALLS "fail soft").
		if (!m_seenSeeded) {
			ReconcileAuthorized();
			return {};
		}

		if (dt > std::chrono::milliseconds(0)) {
			m_sinceReconcile += dt;
		}
		if (m_sinceReconcile >= kReconcileInterval) {
			m_sinceReconcile = std::chrono::milliseconds(0);
			ReconcileAuthorized();
		}
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnPluginUpdate failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnPluginUpdate failed with an unknown exception");
	}
	return {};
}

plg::PluginResult AsReservedSlotsPlugin::OnPluginEnd() {
	try {
		UnregisterListeners();

		g_mapReady = false;
		g_mapEndedSinceStart = true;
		g_firstUpdateDone = false;

		// A stale callback (the engine may still hold the pointer for a moment) can no longer
		// reach the admin API, a client or a slot table (PITFALLS A7).
		g_pAdminApi = nullptr;
		m_configReady = false;
		m_maxClients = 0;
		m_config = as_reserved_slots::Config{};
		ResetSlotState();
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " OnPluginEnd failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " OnPluginEnd failed with an unknown exception");
	}
	return {};
}

// --- registration ------------------------------------------------------------------------

void AsReservedSlotsPlugin::RegisterListeners() {
	// The map listeners are the only way to learn that a client list exists/stopped existing. A
	// missing pair leaves the gate shut forever (no enforcement) instead of opening it blindly.
	if (!g_mapListeners && __s2sdk_OnMapStart_Register && __s2sdk_OnMapStart_Unregister &&
		__s2sdk_OnMapEnd_Register && __s2sdk_OnMapEnd_Unregister) {
		s2sdk::OnMapStart_Register(&OnMapStartListener);
		s2sdk::OnMapEnd_Register(&OnMapEndListener);
		g_mapListeners = true;
	} else if (!g_mapListeners) {
		LogErrorOnce(g_loggedNoMapListeners,
					 std::string(kLogTag) +
						 " the s2sdk map listeners are unavailable - reserved slots are not enforced");
	}

	// Each listener needs both its register and its unregister binding: registering a callback
	// that OnPluginEnd cannot remove would leave the engine calling into unloaded code after
	// `plg reload` (PITFALLS A7).
	if (!g_authListener && __s2sdk_OnClientAuthenticated_Register && __s2sdk_OnClientAuthenticated_Unregister) {
		s2sdk::OnClientAuthenticated_Register(&OnClientAuthenticatedListener);
		g_authListener = true;
	} else if (!g_authListener) {
		LogErrorOnce(g_loggedNoAuthBinding,
					 std::string(kLogTag) +
						 " the s2sdk OnClientAuthenticated binding is unavailable - the reconcile is the only path");
	}

	if (!g_connectListener && __s2sdk_OnClientConnected_Register && __s2sdk_OnClientConnected_Unregister) {
		s2sdk::OnClientConnected_Register(&OnClientConnectedListener);
		g_connectListener = true;
	} else if (!g_connectListener) {
		LogErrorOnce(g_loggedNoConnectBinding,
					 std::string(kLogTag) +
						 " the s2sdk OnClientConnected binding is unavailable - slot reuse is detected by the reconcile only");
	}

	if (!g_disconnectListener && __s2sdk_OnClientDisconnect_Register && __s2sdk_OnClientDisconnect_Unregister) {
		s2sdk::OnClientDisconnect_Register(&OnClientDisconnectListener);
		g_disconnectListener = true;
	} else if (!g_disconnectListener) {
		LogErrorOnce(g_loggedNoDisconnectBinding,
					 std::string(kLogTag) +
						 " the s2sdk OnClientDisconnect binding is unavailable - the reconcile/player_disconnect clear the slot");
	}

	// A redundant state clear for the case where the direct callback is missed. The event hook is
	// only installed together with its matching UnhookEvent (PITFALLS A7/C12).
	if (!g_disconnectEventHooked && __s2sdk_HookEvent && __s2sdk_UnhookEvent) {
		const s2sdk::EventHookError result =
				s2sdk::HookEvent("player_disconnect", &OnPlayerDisconnectEvent, s2sdk::HookMode::Pre);
		if (result == s2sdk::EventHookError::Okay) {
			g_disconnectEventHooked = true;
		} else {
			LogError(std::string(kLogTag) + " could not hook \"player_disconnect\"");
		}
	} else if (!g_disconnectEventHooked) {
		LogErrorOnce(g_loggedNoEventSlot,
					 std::string(kLogTag) +
						 " the s2sdk event bindings are unavailable - the player_disconnect fallback is disabled");
	}
}

void AsReservedSlotsPlugin::UnregisterListeners() {
	if (g_authListener) {
		if (__s2sdk_OnClientAuthenticated_Unregister) {
			s2sdk::OnClientAuthenticated_Unregister(&OnClientAuthenticatedListener);
		}
		g_authListener = false;
	}
	if (g_connectListener) {
		if (__s2sdk_OnClientConnected_Unregister) {
			s2sdk::OnClientConnected_Unregister(&OnClientConnectedListener);
		}
		g_connectListener = false;
	}
	if (g_disconnectListener) {
		if (__s2sdk_OnClientDisconnect_Unregister) {
			s2sdk::OnClientDisconnect_Unregister(&OnClientDisconnectListener);
		}
		g_disconnectListener = false;
	}
	if (g_disconnectEventHooked) {
		if (__s2sdk_UnhookEvent) {
			s2sdk::UnhookEvent("player_disconnect", &OnPlayerDisconnectEvent, s2sdk::HookMode::Pre);
		}
		g_disconnectEventHooked = false;
	}
	if (g_mapListeners) {
		if (__s2sdk_OnMapStart_Unregister) {
			s2sdk::OnMapStart_Unregister(&OnMapStartListener);
		}
		if (__s2sdk_OnMapEnd_Unregister) {
			s2sdk::OnMapEnd_Unregister(&OnMapEndListener);
		}
		g_mapListeners = false;
	}
}

// --- the config ---------------------------------------------------------------------------

bool AsReservedSlotsPlugin::LoadConfigIfPossible() {
	if (!g_mapReady || m_configReady) {
		return m_configReady;
	}

	const int32_t maxClients = ReadMaxClients();
	if (maxClients <= 0) {
		return false; // no map/no engine max yet: retry on a later frame
	}

	std::string configsDir;
	if (plg::GetConfigsDir) {
		configsDir = std::string(plg::GetConfigsDir());
	} else {
		LogErrorOnce(g_loggedNoConfigsDir,
					 std::string(kLogTag) +
						 " the plugify configs directory is unavailable - only the legacy path is checked");
	}

	const as_reserved_slots::ConfigLoadOutcome outcome =
			as_reserved_slots::LoadConfig(configsDir, maxClients);
	m_config = outcome.config;
	m_maxClients = maxClients;
	m_configReady = true;

	if (outcome.status != as_reserved_slots::ConfigLoadStatus::Loaded) {
		// The original's exact failure line; the defaults are already in m_config.
		LogError(std::string(kLogTag) + " Failed to load " + as_reserved_slots::kLegacyConfigPath +
				 ", using defaults");
	}
	return true;
}

// --- slot bookkeeping and the ported module ------------------------------------------------

void AsReservedSlotsPlugin::ResetSlot(int32_t slot) {
	if (!ValidSlot(slot)) {
		return;
	}
	const auto index = static_cast<std::size_t>(slot);
	ClearPendingForIdentity(m_lastIdentity[index]);
	m_lastIdentity[index] = 0;
	m_previousIdentity[index] = 0;
	m_connectMarker[index] = false;
	m_seenSteamIds[index] = 0;
	m_authMarker[index] = AuthEventMarker{};
	m_lastConnected[index] = false;
}

void AsReservedSlotsPlugin::ResetSlotState() {
	m_seenSteamIds.fill(0);
	m_pending.fill(PendingDecision{});
	m_lastIdentity.fill(0);
	m_previousIdentity.fill(0);
	m_connectMarker.fill(false);
	m_authMarker.fill(AuthEventMarker{});
	m_lastConnected.fill(false);
	m_kickedThisPass.fill(false);
	m_seenSeeded = false;
	m_sinceReconcile = std::chrono::milliseconds(0);
	m_mapGeneration = 0;
	g_mapTransition = false;
}

void AsReservedSlotsPlugin::ClearPendingForIdentity(uint64_t steamid) {
	if (steamid == 0) {
		return;
	}
	for (PendingDecision& pending : m_pending) {
		if (pending.active && pending.steamid == steamid) {
			pending = PendingDecision{};
		}
	}
}

void AsReservedSlotsPlugin::SetPending(uint64_t steamid) {
	if (steamid == 0) {
		return;
	}
	// Identity-keyed: an existing valid record keeps its original generation/deadline (the map
	// boundary must not be extended by mere re-observation). An expired one is replaced; a free
	// slot is used otherwise. At most 64 identities can ever be live.
	for (PendingDecision& pending : m_pending) {
		if (pending.active && pending.steamid == steamid) {
			if (PendingIsValid(pending, m_mapGeneration)) {
				return;
			}
			pending = PendingDecision{};
			break;
		}
	}
	for (PendingDecision& pending : m_pending) {
		if (!pending.active || !PendingIsValid(pending, m_mapGeneration)) {
			pending.steamid = steamid;
			pending.mapGeneration = m_mapGeneration;
			pending.created = std::chrono::steady_clock::now();
			pending.active = true;
			return;
		}
	}
	// Full (at most 64 clients): replace the oldest record.
	PendingDecision* oldest = &m_pending[0];
	for (PendingDecision& pending : m_pending) {
		if (pending.created < oldest->created) {
			oldest = &pending;
		}
	}
	oldest->steamid = steamid;
	oldest->mapGeneration = m_mapGeneration;
	oldest->created = std::chrono::steady_clock::now();
	oldest->active = true;
}

bool AsReservedSlotsPlugin::HasPending(uint64_t steamid) const {
	if (steamid == 0) {
		return false;
	}
	for (const PendingDecision& pending : m_pending) {
		if (pending.active && pending.steamid == steamid &&
			PendingIsValid(pending, m_mapGeneration)) {
			return true;
		}
	}
	return false;
}

int32_t AsReservedSlotsPlugin::FindSeenSlotByIdentity(uint64_t steamid) const {
	if (steamid == 0) {
		return -1;
	}
	for (int32_t slot = 0; slot < kMaxSlots; ++slot) {
		if (m_seenSteamIds[static_cast<std::size_t>(slot)] == steamid) {
			return slot;
		}
	}
	return -1;
}

void AsReservedSlotsPlugin::MarkSeen(int32_t slot, uint64_t steamid) {
	if (!ValidSlot(slot) || steamid == 0) {
		return;
	}
	// One seen identity: moving the same SteamID64 to another slot must not leave a stale seen
	// entry behind, and an already processed identity must not be evaluated again in the new slot.
	for (int32_t other = 0; other < kMaxSlots; ++other) {
		if (other != slot && m_seenSteamIds[static_cast<std::size_t>(other)] == steamid) {
			m_seenSteamIds[static_cast<std::size_t>(other)] = 0;
		}
	}
	m_lastIdentity[static_cast<std::size_t>(slot)] = steamid;
	m_previousIdentity[static_cast<std::size_t>(slot)] = steamid;
	m_seenSteamIds[static_cast<std::size_t>(slot)] = steamid;
	ClearPendingForIdentity(steamid);
	ClearAuthMarker(slot);
}

void AsReservedSlotsPlugin::SetAuthMarker(int32_t slot) {
	if (!ValidSlot(slot)) {
		return;
	}
	AuthEventMarker& marker = m_authMarker[static_cast<std::size_t>(slot)];
	marker.mapGeneration = m_mapGeneration;
	marker.created = std::chrono::steady_clock::now();
	marker.active = true;
}

void AsReservedSlotsPlugin::ClearAuthMarker(int32_t slot) {
	if (ValidSlot(slot)) {
		m_authMarker[static_cast<std::size_t>(slot)] = AuthEventMarker{};
	}
}

bool AsReservedSlotsPlugin::HasAuthMarker(int32_t slot) const {
	return ValidSlot(slot) &&
		   MarkerIsValid(m_authMarker[static_cast<std::size_t>(slot)], m_mapGeneration);
}

void AsReservedSlotsPlugin::PrunePending() {
	for (PendingDecision& pending : m_pending) {
		if (pending.active && !PendingIsValid(pending, m_mapGeneration)) {
			pending = PendingDecision{};
		}
	}
	for (AuthEventMarker& marker : m_authMarker) {
		if (marker.active && !MarkerIsValid(marker, m_mapGeneration)) {
			marker = AuthEventMarker{};
		}
	}
}

// Observation is the B6 safety net for a missing OnClientAuthenticated callback. It runs after the
// first seed, with a map open, BEFORE the admin readiness gate, and records a canonical-SteamID
// pending decision for every connected, authorized, non-fake client that has not been evaluated.
// It performs no permission query and no kick.
void AsReservedSlotsPlugin::ObserveNewClients(int32_t maxClients) {
	if (!g_mapReady || !ClientQueryBindingsAvailable()) {
		return;
	}
	for (int32_t slot = 0; slot < maxClients; ++slot) {
		const auto index = static_cast<std::size_t>(slot);
		if (!SafeIsClientConnected(slot) || SafeIsFakeClient(slot) || !SafeIsClientAuthorized(slot)) {
			continue;
		}
		const uint64_t steamid = SafeClientSteamID64(slot);
		if (steamid == 0) {
			continue; // canonical identity not readable yet; the marker stays for Seed
		}
		m_lastIdentity[index] = steamid;
		m_previousIdentity[index] = steamid;
		m_connectMarker[index] = false; // consumed by observation
		if (m_seenSteamIds[index] == steamid) {
			ClearPendingForIdentity(steamid);
			ClearAuthMarker(slot);
			continue;
		}
		if (FindSeenSlotByIdentity(steamid) >= 0) {
			// The same already-processed player moved to this slot (changelevel/reconnect without
			// a disconnect callback): do not evaluate them again.
			MarkSeen(slot, steamid);
			ClearAuthMarker(slot);
			continue;
		}
		if (HasPending(steamid)) {
			ClearAuthMarker(slot);
			continue;
		}
		ClearAuthMarker(slot);
		SetPending(steamid);
	}
}

void AsReservedSlotsPlugin::OnMapEnded() {
	// PITFALLS B2: no client query here. Seen identities and unfinished decisions survive the
	// changelevel; the latter are keyed by SteamID64 + generation and live for one boundary.
	++m_mapGeneration;
	g_mapTransition = true;
	PrunePending();
	m_lastIdentity.fill(0); // slot->identity hints belong to the old map/reporting slot
	// m_connectMarker is deliberately NOT cleared: a new connection observed just before OnMapEnd
	// must still be distinguishable from a reload player at the new map's first seed.
	m_lastConnected.fill(false);
	m_kickedThisPass.fill(false);
	m_seenSeeded = false;
	m_sinceReconcile = std::chrono::milliseconds(0);
}

void AsReservedSlotsPlugin::OnMapStarted() {
	g_mapTransition = false;
	PrunePending(); // wall-clock bound only: no client query on a just-started map
}

void AsReservedSlotsPlugin::OnClientConnected(int32_t slot) {
	if (g_pAdminApi == nullptr || !ValidSlot(slot)) {
		return;
	}
	// A connection callback does not identify the SteamID64 and must not query a client. Preserve
	// seen/pending: a changelevel reconnect keeps them, and identity checks in Seed/reconcile
	// discard a previous occupant's record when the slot is reused. Last identity is reset so a
	// quick disconnect of the new occupant cannot clear a pending record that now belongs to the
	// same SteamID64 in another slot; the record stays bounded by its generation/TTL.
	const auto index = static_cast<std::size_t>(slot);
	m_lastIdentity[index] = 0;
	m_connectMarker[index] = true;
	m_lastConnected[index] = true;
}

void AsReservedSlotsPlugin::OnClientDisconnected(int32_t slot) {
	if (g_pAdminApi == nullptr || !ValidSlot(slot)) {
		return;
	}
	// No client query: the client may already be gone (OnClientDisconnect/map shutdown).
	const auto index = static_cast<std::size_t>(slot);
	m_connectMarker[index] = false;
	m_lastConnected[index] = false;
	if (g_mapTransition || !m_seenSeeded) {
		// A changelevel disconnect (or one before the new map's first seed): keep a pending
		// decision/seen identity for the new map. The next Seed/reconcile clears it if the slot is
		// not re-occupied by the same SteamID64.
		return;
	}
	ResetSlot(slot);
}

void AsReservedSlotsPlugin::OnClientAuthenticated(int32_t slot, uint64_t steamid) {
	if (g_pAdminApi == nullptr || !ValidSlot(slot)) {
		return;
	}
	const auto index = static_cast<std::size_t>(slot);
	// B6: s2sdk documents the event value as a Steam account id or 0. It still proves a new
	// connection is authenticating; keep a state-only marker and let Seed/Observe resolve the
	// canonical SteamID64 later. No client query here.
	if (steamid < (1ull << 32)) {
		SetAuthMarker(slot);
		m_lastConnected[index] = true;
		return;
	}
	m_lastIdentity[index] = steamid;
	m_previousIdentity[index] = steamid;
	if (m_seenSteamIds[index] == steamid || FindSeenSlotByIdentity(steamid) >= 0) {
		// Already evaluated for this identity, possibly in another slot after a changelevel.
		MarkSeen(slot, steamid);
		ClearAuthMarker(slot);
		return;
	}
	if (HasPending(steamid)) {
		m_seenSteamIds[index] = 0; // normalize a moved identity
		ClearAuthMarker(slot);
		return; // duplicate authentication event for the same pending connection
	}
	m_seenSteamIds[index] = 0; // a new identity, not evaluated yet
	SetPending(steamid);
	ClearAuthMarker(slot);
	m_lastConnected[index] = true;

	// Deliberately no HasPermission()/KickClient() here: the decision waits for
	// IsClientAdminDataReady(slot, steamid) in the reconcile (see the file header).
}

void AsReservedSlotsPlugin::SeedAuthorized(int32_t maxClients) {
	for (int32_t slot = 0; slot < maxClients; ++slot) {
		const auto index = static_cast<std::size_t>(slot);
		if (!SafeIsClientConnected(slot)) {
			// Leave a pending decision for a player who may reconnect a moment after the new map
			// starts; generation/TTL and the identity check below bound it. The old slot hints are
			// stale once the slot is empty: clear them so they cannot shield a later new join.
			m_previousIdentity[index] = 0;
			m_connectMarker[index] = false;
			continue;
		}
		m_lastConnected[index] = true;
		if (SafeIsFakeClient(slot)) {
			ResetSlot(slot);
			m_lastConnected[index] = true;
			continue;
		}
		if (!SafeIsClientAuthorized(slot)) {
			continue;
		}
		const uint64_t steamid = SafeClientSteamID64(slot);
		if (steamid == 0) {
			continue; // no authoritative identity: never seed a decision for it
		}
		const bool connectedSinceLastSeed = m_connectMarker[index];
		const uint64_t previousIdentity = m_previousIdentity[index];
		m_connectMarker[index] = false;
		m_lastIdentity[index] = steamid;
		m_previousIdentity[index] = steamid;
		if (m_seenSteamIds[index] == steamid) {
			ClearPendingForIdentity(steamid); // already evaluated on this or the previous map
			ClearAuthMarker(slot);
			continue;
		}
		if (FindSeenSlotByIdentity(steamid) >= 0) {
			// The same already-processed player moved to another slot across the boundary.
			MarkSeen(slot, steamid);
			ClearAuthMarker(slot);
			continue;
		}
		if (HasPending(steamid)) {
			// The pending decision follows the SteamID64 into this slot across a changelevel.
			ClearAuthMarker(slot);
			continue; // do not seed: evaluate once all admin data is ready
		}
		if (HasAuthMarker(slot)) {
			ClearAuthMarker(slot);
			if (m_seenSteamIds[index] == 0) {
				if (previousIdentity == 0 || previousIdentity == steamid) {
					// A 0/32-bit auth event has now found its canonical identity: this is a new,
					// not-yet-evaluated player.
					SetPending(steamid);
					continue;
				}
				// The slot had a different previous occupant: seed the new occupant, do not kick it
				// from the old marker.
			}
			// The slot had a different, already-seen occupant: this is a new occupant. Seed it,
			// never kick it from the old marker.
		}
		if (connectedSinceLastSeed && m_seenSteamIds[index] == 0) {
			if (previousIdentity == 0 || previousIdentity == steamid) {
				// A connection event arrived after OnPluginStart / OnMapStart and this slot had no
				// different previous occupant: this is a NEW join, not a reload/map's already-online
				// player. Do not seed it away; evaluate it once the admin data is ready.
				SetPending(steamid);
				continue;
			}
			// The slot had a different previous occupant: seed the new occupant, never kick it from
			// the old slot state.
		}
		// A new occupant (or a reload): seed the already-online player and never kick at seed.
		MarkSeen(slot, steamid);
	}
	PrunePending();
}

bool AsReservedSlotsPlugin::BuildSnapshot(int32_t maxClients, ReadySnapshot& snapshot) const {
	snapshot = ReadySnapshot{};
	if (!g_mapReady || !m_configReady || !AdminCoreReady() || !ClientQueryBindingsAvailable()) {
		return false;
	}

	// Phase 1: authoritative identities of every relevant human. A missing SteamID64 means the
	// snapshot would be incomplete, so the whole pass is abandoned before any permission query.
	for (int32_t slot = 0; slot < maxClients; ++slot) {
		const auto index = static_cast<std::size_t>(slot);
		if (m_kickedThisPass[index]) {
			continue;
		}
		if (!SafeIsClientConnected(slot) || SafeIsFakeClient(slot) || !SafeIsClientAuthorized(slot)) {
			continue;
		}
		const uint64_t steamid = SafeClientSteamID64(slot);
		if (steamid == 0) {
			return false;
		}
		snapshot.clients[static_cast<std::size_t>(snapshot.count++)] = ReadyClient{slot, steamid, false};
	}

	// Phase 2: wait for the producer's per-player SELECT completion for every one of them. No
	// HasPermission/HasFlag/KickClient happens until this loop has passed for the whole snapshot.
	for (int32_t i = 0; i < snapshot.count; ++i) {
		const ReadyClient& client = snapshot.clients[static_cast<std::size_t>(i)];
		if (!AdminDataReady(client.slot, client.steamid)) {
			return false;
		}
	}

	// Phase 3: the permission/flag read is now authoritative for this tick.
	for (int32_t i = 0; i < snapshot.count; ++i) {
		ReadyClient& client = snapshot.clients[static_cast<std::size_t>(i)];
		client.hasReserve = HasReserveAccess(m_config, client.slot);
	}
	snapshot.complete = true;
	return true;
}

bool AsReservedSlotsPlugin::RevalidateClient(int32_t slot, uint64_t steamid) const {
	if (!g_mapReady || !m_configReady || !AdminCoreReady() || !ClientQueryBindingsAvailable()) {
		return false;
	}
	if (!SafeIsClientConnected(slot) || SafeIsFakeClient(slot) || !SafeIsClientAuthorized(slot)) {
		return false;
	}
	if (SafeClientSteamID64(slot) != steamid) {
		return false; // the slot was reused after the snapshot
	}
	return AdminDataReady(slot, steamid);
}

AsReservedSlotsPlugin::Evaluation AsReservedSlotsPlugin::EvaluateSlot(int32_t slot, uint64_t steamid,
																	   const ReadySnapshot& snapshot) {
	if (!snapshot.complete || !g_mapReady || !m_configReady || !AdminCoreReady()) {
		return Evaluation::NotReady;
	}
	const ReadyClient* self = snapshot.Find(slot);
	if (self == nullptr || self->steamid != steamid) {
		return Evaluation::NotReady;
	}
	// The joining player's identity/readiness is authoritative for the snapshot it was built for;
	// re-check it immediately before the decision (and again inside KickClientForReserve()).
	if (!RevalidateClient(slot, steamid)) {
		return Evaluation::NotReady;
	}
	if (m_maxClients <= 0) {
		return Evaluation::NotReady;
	}

	int32_t publicSlots = m_config.publicSlots;
	if (publicSlots < 0) {
		publicSlots = 0;
	}
	if (publicSlots > m_maxClients) {
		publicSlots = m_maxClients;
	}

	const bool hasReserve = self->hasReserve;
	// The snapshot's permission answer is confirmed once more for the joining player. A change
	// between the snapshot and this point means the snapshot is stale: retry instead of acting.
	if (HasReserveAccess(m_config, slot) != hasReserve) {
		return Evaluation::NotReady;
	}
	const int nonReserve = CountNonReservePlayers(snapshot);

	if (!hasReserve && nonReserve > publicSlots) {
		return KickClientForReserve(slot, steamid, m_config.kickReasonId) ? Evaluation::Done
																		 : Evaluation::NotReady;
	}
	if (hasReserve && nonReserve > publicSlots) {
		const ReadyClient* target = FindNonReservePlayerToKick(slot, snapshot);
		if (target == nullptr) {
			return Evaluation::Done; // no eligible victim: the reserve player still joins
		}
		// Revalidate the victim's identity/readiness and permission right before the engine call:
		// the slot may have been reused and the snapshot's "non-reserve" answer may be stale.
		if (!RevalidateClient(target->slot, target->steamid)) {
			return Evaluation::NotReady;
		}
		if (HasReserveAccess(m_config, target->slot)) {
			return Evaluation::NotReady;
		}
		if (!KickClientForReserve(target->slot, target->steamid, m_config.kickReasonId)) {
			return Evaluation::NotReady;
		}
		MarkSeen(target->slot, target->steamid);
		return Evaluation::Done;
	}
	return Evaluation::Done;
}

int AsReservedSlotsPlugin::CountNonReservePlayers(const ReadySnapshot& snapshot) const {
	int count = 0;
	for (int32_t i = 0; i < snapshot.count; ++i) {
		const ReadyClient& client = snapshot.clients[static_cast<std::size_t>(i)];
		if (m_kickedThisPass[static_cast<std::size_t>(client.slot)]) {
			continue;
		}
		if (!client.hasReserve) {
			++count;
		}
	}
	return count;
}

const ReadyClient* AsReservedSlotsPlugin::FindNonReservePlayerToKick(int32_t avoidSlot,
																 const ReadySnapshot& snapshot) const {
	for (int32_t i = 0; i < snapshot.count; ++i) {
		const ReadyClient& client = snapshot.clients[static_cast<std::size_t>(i)];
		if (client.slot == avoidSlot || m_kickedThisPass[static_cast<std::size_t>(client.slot)]) {
			continue;
		}
		if (!client.hasReserve) {
			return &client;
		}
	}
	return nullptr;
}

bool AsReservedSlotsPlugin::KickClientForReserve(int32_t slot, uint64_t steamid, int reason) {
	if (!g_mapReady || !m_configReady || !ValidSlot(slot)) {
		return false;
	}
	// Defense in depth: EvaluateSlot() already checked this, but the one function that calls the
	// engine's DisconnectClient must itself refuse to run while the admin core/readiness is
	// unavailable and must re-validate the exact identity it is about to disconnect.
	if (!AdminCoreReady()) {
		return false;
	}
	const auto index = static_cast<std::size_t>(slot);
	if (m_kickedThisPass[index]) {
		return false;
	}
	if (!RevalidateClient(slot, steamid)) {
		return false;
	}
	if (__s2sdk_IsClientConnected == nullptr || __s2sdk_KickClient == nullptr) {
		LogErrorOnce(g_loggedNoKickBinding,
					 std::string(kLogTag) +
						 " the s2sdk KickClient/IsClientConnected binding is unavailable - not kicking");
		return false;
	}
	try {
		if (!s2sdk::IsClientConnected(slot)) {
			return false;
		}
		// The original cast the reason to ENetworkDisconnectionReason and passed the slot's
		// CPlayerSlot; s2sdk::KickClient disconnects on the next frame like the engine call did.
		// The empty message keeps the original's DisconnectClient(reason) behaviour.
		s2sdk::KickClient(slot, static_cast<s2sdk::NetworkDisconnectionReason>(reason), plg::string());
		m_kickedThisPass[index] = true;
		LogInfo(std::string(kLogTag) + " kicked slot " + std::to_string(slot) + " (reason " +
				std::to_string(reason) + ")");
		return true;
	} catch (const std::exception& ex) {
		LogError(std::string(kLogTag) + " KickClient failed: " + ex.what());
	} catch (...) {
		LogError(std::string(kLogTag) + " KickClient failed with an unknown exception");
	}
	return false;
}

void AsReservedSlotsPlugin::ReconcileAuthorized() {
	if (!g_mapReady || !ClientQueryBindingsAvailable()) {
		return;
	}
	const int32_t maxClients = m_maxClients > 0 ? std::min(m_maxClients, kMaxSlots) : 0;
	if (maxClients <= 0) {
		return;
	}

	PrunePending();
	if (!m_seenSeeded) {
		SeedAuthorized(maxClients);
		m_seenSeeded = true;
		// First-seed only marks already-online/reload players seen. Observation after it (and in
		// later passes) records the B6 case - a new connected human whose auth callback was
		// missing/0/32-bit - as a canonical PendingDecision without any permission or kick.
		ObserveNewClients(maxClients);
		return;
	}

	// B6 observation happens BEFORE the readiness gate: if admin data is still pending, the new
	// client still gets a canonical pending decision that survives a map change.
	ObserveNewClients(maxClients);

	// The readiness binding and the core are preconditions for every permission query below.
	// When either is unavailable the plugin never calls HasPermission/HasFlag/KickClient.
	if (!AdminCoreReady()) {
		return;
	}

	m_kickedThisPass.fill(false);
	ReadySnapshot snapshot;
	if (!BuildSnapshot(maxClients, snapshot)) {
		// At least one relevant client has no authoritative identity/readiness yet. Fail open: no
		// permission query, no kick, every pending slot stays unseen for the next reconcile.
		return;
	}

	for (int32_t slot = 0; slot < maxClients; ++slot) {
		const auto index = static_cast<std::size_t>(slot);

		if (m_kickedThisPass[index]) {
			continue;
		}
		if (!SafeIsClientConnected(slot)) {
			// Do not discard a carried pending decision here: a client may reconnect a moment
			// after OnMapStart. OnClientDisconnect clears it in normal operation; the map
			// generation/TTL and the identity check below bound a stale one.
			m_lastConnected[index] = false;
			continue;
		}

		// The direct connect callback is not needed for correctness: the seed/identity checks
		// below treat a previously-unseen identity as new. Do not clear seen/pending here - that
		// would lose a decision carried across a changelevel.
		if (!m_lastConnected[index]) {
			m_lastConnected[index] = true;
		}

		if (SafeIsFakeClient(slot)) {
			ResetSlot(slot);
			m_lastConnected[index] = true;
			continue;
		}
		if (!SafeIsClientAuthorized(slot)) {
			continue;
		}

		// Decisions use the canonical SteamID64 only.
		const uint64_t steamid = SafeClientSteamID64(slot);
		if (steamid == 0) {
			continue;
		}
		m_lastIdentity[index] = steamid;
		m_previousIdentity[index] = steamid;
		if (steamid == m_seenSteamIds[index] || FindSeenSlotByIdentity(steamid) >= 0) {
			// Already evaluated for this identity, possibly in another slot after a changelevel.
			MarkSeen(slot, steamid);
			ClearAuthMarker(slot);
			continue;
		}
		if (HasAuthMarker(slot)) {
			ClearAuthMarker(slot);
			SetPending(steamid);
		} else if (!HasPending(steamid)) {
			// Observation runs before the readiness gate, but keep the decision invariant here too.
			SetPending(steamid);
		}

		const ReadyClient* candidate = snapshot.Find(slot);
		if (candidate == nullptr || candidate->steamid != steamid) {
			continue;
		}

		const Evaluation result = EvaluateSlot(slot, steamid, snapshot);
		if (result == Evaluation::Done) {
			MarkSeen(slot, steamid);
		}
		// NotReady: keep the slot unseen/pending and retry on the next reconcile pass.
	}
}
} // namespace

PLUGIFY_PLUGIN(PLUGIN_API, &g_asReservedSlotsPlugin)
