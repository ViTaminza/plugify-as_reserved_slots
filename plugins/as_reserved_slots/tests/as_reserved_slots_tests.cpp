// as_reserved_slots tests — no engine: the plugin TU is compiled in (its handlers live in an
// anonymous namespace) and every __s2sdk_* / __admin_system_* binding slot is a recording fake.
//
// Covered:
//   * src/kv1.hpp + src/config.hpp — the self-contained KV1 reader (production file shape,
//     comments, escapes, BOM, directives, malformed files rejected whole), the original's getter
//     semantics, the config candidate walk (legacy/metamod, <configs>/admin_system,
//     <configs>/as_reserved_slots) and the exact defaults/clamps: public_slots = maxClients - 2,
//     [0, maxClients], kick_reason_id < 0 -> 39;
//   * PITFALLS B1/B2 — the map gate: no client/max-clients/permission call before the first map,
//     none between OnMapEnd and the next OnMapStart, none inside OnMapEnd itself; a plugin loaded
//     into a running map latches readiness on its first update, an OnMapEnd seen before that
//     update keeps the gate shut;
//   * PITFALLS B6 — the first reconcile pass only seeds who is already online (a plugin reload on
//     a full server kicks nobody), later joins are evaluated; OnClientAuthenticated,
//     OnClientConnected, OnClientDisconnect and the player_disconnect event (GetEventPlayerSlot,
//     never the raw "userid") keep the per-slot identity fresh across reuse;
//   * map handover — an auth/pending decision is carried through OnMapEnd/OnMapStart, keyed by
//     SteamID64 + generation: auth -> MapEnd -> MapStart -> ready produces exactly one correct
//     kick; a new occupant/reused slot never inherits the old pending id; the record expires after
//     one boundary; seen players are not re-kicked on map/reload; a normal disconnect clears it;
//   * B6 observation — an unseen connected human whose OnClientAuthenticated callback is missing
//     is recorded as a canonical pending decision before the readiness gate; 0/32-bit auth
//     payloads are markers until the canonical id is readable; pending and seen identities follow
//     the same SteamID64 into another slot across a changelevel;
//   * the ported module — non-reserve join over public_slots is kicked, a reserve join kicks the
//     first non-reserve player, bots/fake clients are never counted/kicked, reserve access is
//     permission OR flag, empty reserve_flag disables the reserve set, kick_reason_id is preserved;
//   * the security fail-soft rule — with missing admin_system bindings, IsCoreLoaded() == false,
//     a missing admin-core binding, a missing client/identity binding or no usable maxClients,
//     a full server produces ZERO KickClient calls; once the core becomes ready the unseen slot is
//     retried and only then evaluated;
//   * admin_system::IsClientAdminDataReady — a pending or failed SELECT produces zero permission
//     queries and zero kicks; a pending candidate aborts the whole snapshot; readiness is
//     revalidated immediately before KickClient(); reuse before and after the snapshot never uses
//     the previous occupant's answer; a true zero-row answer is the authoritative non-admin case;
//   * PITFALLS A7/C12 — OnPluginEnd unregisters every listener/hook and drops the admin API; stale
//     auth/connect/disconnect/event callbacks do nothing; a reload re-registers once; a missing
//     unregister binding means the corresponding register is never made;
//   * PITFALLS C11 — the module owns no ConCommand, so no command is registered or removed.
//
// Run by ./test.sh (build/tests/as_reserved_slots_tests).

#include "../src/plugin.cpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <initializer_list>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {

int g_checks = 0;
int g_failures = 0;

void Check(bool condition, std::string_view what) {
	++g_checks;
	if (!condition) {
		++g_failures;
		std::printf("FAIL: %s\n", std::string(what).c_str());
	}
}

void CheckEq(std::string_view actual, std::string_view expected, std::string_view what) {
	++g_checks;
	if (actual != expected) {
		++g_failures;
		std::printf("FAIL: %s (got '%s', expected '%s')\n", std::string(what).c_str(),
					std::string(actual).c_str(), std::string(expected).c_str());
	}
}

void CheckEqInt(int64_t actual, int64_t expected, std::string_view what) {
	++g_checks;
	if (actual != expected) {
		++g_failures;
		std::printf("FAIL: %s (got %lld, expected %lld)\n", std::string(what).c_str(),
					static_cast<long long>(actual), static_cast<long long>(expected));
	}
}

std::string ToStd(const plg::string& text) {
	return std::string(text.data(), text.size());
}

// --- the fake plugify host ---------------------------------------------------------

std::string g_configsDir;

plg::string FakeGetConfigsDir() {
	return plg::string(g_configsDir.c_str());
}

struct FakeLogEntry {
	plg::Severity severity = plg::Severity::Info;
	std::string message;
};

std::vector<FakeLogEntry> g_logs;

void FakeLog(std::string_view message, plg::Severity severity, const plg::source_location& /*location*/) {
	g_logs.push_back(FakeLogEntry{severity, std::string(message)});
}

bool Logged(plg::Severity severity, std::string_view needle) {
	for (const FakeLogEntry& entry : g_logs) {
		if (entry.severity == severity && entry.message.find(needle) != std::string::npos) {
			return true;
		}
	}
	return false;
}

// --- the fake map lifecycle ---------------------------------------------------------

s2sdk::OnMapStartCallback g_onMapStart = nullptr;
s2sdk::OnMapEndCallback g_onMapEnd = nullptr;
int g_mapStartRegisters = 0;
int g_mapStartUnregisters = 0;
int g_mapEndRegisters = 0;
int g_mapEndUnregisters = 0;

void FakeMapStartRegister(s2sdk::OnMapStartCallback callback) {
	g_onMapStart = callback;
	++g_mapStartRegisters;
}

void FakeMapStartUnregister(s2sdk::OnMapStartCallback callback) {
	if (g_onMapStart == callback) {
		g_onMapStart = nullptr;
	}
	++g_mapStartUnregisters;
}

void FakeMapEndRegister(s2sdk::OnMapEndCallback callback) {
	g_onMapEnd = callback;
	++g_mapEndRegisters;
}

void FakeMapEndUnregister(s2sdk::OnMapEndCallback callback) {
	if (g_onMapEnd == callback) {
		g_onMapEnd = nullptr;
	}
	++g_mapEndUnregisters;
}

void MapStart() {
	if (g_onMapStart != nullptr) {
		g_onMapStart();
	}
}

void MapEnd() {
	if (g_onMapEnd != nullptr) {
		g_onMapEnd();
	}
}

// --- the fake client lifecycle ------------------------------------------------------

s2sdk::OnClientAuthenticatedCallback g_onAuth = nullptr;
s2sdk::OnClientConnectedCallback g_onConnect = nullptr;
s2sdk::OnClientDisconnectCallback g_onDisconnect = nullptr;
int g_authRegisters = 0;
int g_authUnregisters = 0;
int g_connectRegisters = 0;
int g_connectUnregisters = 0;
int g_disconnectRegisters = 0;
int g_disconnectUnregisters = 0;

void FakeAuthRegister(s2sdk::OnClientAuthenticatedCallback callback) {
	g_onAuth = callback;
	++g_authRegisters;
}

void FakeAuthUnregister(s2sdk::OnClientAuthenticatedCallback callback) {
	if (g_onAuth == callback) {
		g_onAuth = nullptr;
	}
	++g_authUnregisters;
}

void FakeConnectRegister(s2sdk::OnClientConnectedCallback callback) {
	g_onConnect = callback;
	++g_connectRegisters;
}

void FakeConnectUnregister(s2sdk::OnClientConnectedCallback callback) {
	if (g_onConnect == callback) {
		g_onConnect = nullptr;
	}
	++g_connectUnregisters;
}

void FakeDisconnectRegister(s2sdk::OnClientDisconnectCallback callback) {
	g_onDisconnect = callback;
	++g_disconnectRegisters;
}

void FakeDisconnectUnregister(s2sdk::OnClientDisconnectCallback callback) {
	if (g_onDisconnect == callback) {
		g_onDisconnect = nullptr;
	}
	++g_disconnectUnregisters;
}

void FireAuth(int32_t slot, uint64_t steamid) {
	if (g_onAuth != nullptr) {
		g_onAuth(slot, steamid);
	}
}

void FireConnect(int32_t slot) {
	if (g_onConnect != nullptr) {
		g_onConnect(slot);
	}
}

void FireDisconnect(int32_t slot) {
	if (g_onDisconnect != nullptr) {
		g_onDisconnect(slot, s2sdk::NetworkDisconnectionReason::DisconnectByUser);
	}
}

// --- the fake player_disconnect event ------------------------------------------------

struct FakeEventHook {
	std::string name;
	s2sdk::EventCallback callback = nullptr;
	s2sdk::HookMode mode = s2sdk::HookMode::Pre;
};

std::vector<FakeEventHook> g_eventHooks;
int g_hookCalls = 0;
int g_unhookCalls = 0;
s2sdk::EventHookError g_hookResult = s2sdk::EventHookError::Okay;
int32_t g_eventSlot = -1;
std::string g_eventKey;
int g_getEventSlotCalls = 0;
int g_fakeEvent = 0;

s2sdk::EventHookError FakeHookEvent(const plg::string& name, s2sdk::EventCallback callback,
									s2sdk::HookMode mode) {
	++g_hookCalls;
	if (g_hookResult != s2sdk::EventHookError::Okay) {
		return g_hookResult;
	}
	g_eventHooks.push_back(FakeEventHook{ToStd(name), callback, mode});
	return s2sdk::EventHookError::Okay;
}

s2sdk::EventHookError FakeUnhookEvent(const plg::string& name, s2sdk::EventCallback callback,
									  s2sdk::HookMode mode) {
	++g_unhookCalls;
	for (auto it = g_eventHooks.begin(); it != g_eventHooks.end(); ++it) {
		if (it->name == ToStd(name) && it->callback == callback && it->mode == mode) {
			g_eventHooks.erase(it);
			return s2sdk::EventHookError::Okay;
		}
	}
	return s2sdk::EventHookError::InvalidEvent;
}

int32_t FakeGetEventPlayerSlot(void* /*event*/, const plg::string& key) {
	++g_getEventSlotCalls;
	g_eventKey = ToStd(key);
	return g_eventSlot;
}

s2sdk::ResultType FirePlayerDisconnectEvent(int32_t slot) {
	for (const FakeEventHook& hook : g_eventHooks) {
		if (hook.name == "player_disconnect" && hook.callback != nullptr) {
			g_eventSlot = slot;
			return hook.callback(plg::string("player_disconnect"), &g_fakeEvent, false);
		}
	}
	return s2sdk::ResultType::Continue;
}

bool HasEventHook(const std::string& name, s2sdk::HookMode mode) {
	for (const FakeEventHook& hook : g_eventHooks) {
		if (hook.name == name && hook.mode == mode) {
			return true;
		}
	}
	return false;
}

// --- the fake client layer ----------------------------------------------------------

struct FakeClient {
	bool connected = false;
	bool authorized = false;
	bool fake = false;
	uint64_t steamid = 0;
};

std::array<FakeClient, 64> g_clients;
int32_t g_maxClients = 10;

int g_connectedCalls = 0;
int g_fakeCalls = 0;
int g_authorizedCalls = 0;
int g_steamCalls = 0;
int g_maxClientsCalls = 0;
std::vector<int32_t> g_queriedSlots;

struct FakeKick {
	int32_t slot = 0;
	s2sdk::NetworkDisconnectionReason reason = s2sdk::NetworkDisconnectionReason::Invalid;
	std::string message;
};

std::vector<FakeKick> g_kicks;

const FakeClient& Client(int32_t slot) {
	static const FakeClient empty;
	return slot >= 0 && slot < static_cast<int32_t>(g_clients.size())
			   ? g_clients[static_cast<std::size_t>(slot)]
			   : empty;
}

bool FakeIsClientConnected(int32_t slot) {
	++g_connectedCalls;
	g_queriedSlots.push_back(slot);
	return Client(slot).connected;
}

bool FakeIsFakeClient(int32_t slot) {
	++g_fakeCalls;
	g_queriedSlots.push_back(slot);
	return Client(slot).fake;
}

bool FakeIsClientAuthorized(int32_t slot) {
	++g_authorizedCalls;
	g_queriedSlots.push_back(slot);
	return Client(slot).authorized;
}

uint64_t FakeGetClientSteamID64(int32_t slot) {
	++g_steamCalls;
	g_queriedSlots.push_back(slot);
	return Client(slot).steamid;
}

int32_t FakeGetMaxClients() {
	++g_maxClientsCalls;
	return g_maxClients;
}

void FakeKickClient(int32_t slot, s2sdk::NetworkDisconnectionReason reason, const plg::string& message) {
	g_kicks.push_back(FakeKick{slot, reason, ToStd(message)});
}

// --- the fake admin_system bindings -------------------------------------------------

bool g_coreLoaded = true;
std::set<int32_t> g_permissionSlots;
std::set<int32_t> g_flagSlots;
std::vector<std::pair<int32_t, std::string>> g_permissionChecks;
std::vector<std::pair<int32_t, std::string>> g_flagChecks;

// IsClientAdminDataReady(slot, steamid): default true (a completed SELECT, including the
// definitive zero-row answer); tests override a specific slot+identity to pending/failed.
bool g_adminDataReadyDefault = true;
std::map<std::pair<int32_t, uint64_t>, bool> g_adminDataReady;
std::vector<std::pair<int32_t, uint64_t>> g_adminDataChecks;
std::map<std::pair<int32_t, uint64_t>, int> g_adminDataCalls;
std::set<std::pair<int32_t, uint64_t>> g_adminDataFailSecondCall;
std::map<std::pair<int32_t, uint64_t>, int> g_adminDataFailFromCall;

// Reuse-after-snapshot hook: after the snapshot read permissions for this slot, the fake changes
// the client's identity (the real engine cannot do this inside one game-thread pass; this drives
// the consumer's revalidation path deterministically).
bool g_reuseAfterSnapshotArmed = false;
int32_t g_reuseAfterSnapshotSlot = -1;
uint64_t g_reuseAfterSnapshotNewId = 0;

void SetAdminDataReady(int32_t slot, uint64_t steamid, bool ready) {
	g_adminDataReady[{slot, steamid}] = ready;
}

bool AdminDataReadyCalled(int32_t slot, uint64_t steamid) {
	for (const auto& check : g_adminDataChecks) {
		if (check.first == slot && check.second == steamid) {
			return true;
		}
	}
	return false;
}

float FakeGetPluginVersion() {
	return 1.0f;
}

bool FakeIsCoreLoaded() {
	return g_coreLoaded;
}

bool FakeIsClientAdminDataReady(int32_t slot, uint64_t steamid) {
	g_adminDataChecks.emplace_back(slot, steamid);
	const std::pair<int32_t, uint64_t> key{slot, steamid};
	++g_adminDataCalls[key];
	if (g_adminDataFailSecondCall.count(key) != 0 && g_adminDataCalls[key] >= 2) {
		return false;
	}
	const auto failFrom = g_adminDataFailFromCall.find(key);
	if (failFrom != g_adminDataFailFromCall.end() && g_adminDataCalls[key] >= failFrom->second) {
		return false;
	}
	const auto it = g_adminDataReady.find(key);
	return it == g_adminDataReady.end() ? g_adminDataReadyDefault : it->second;
}

bool FakeHasPermission(int32_t slot, const plg::string& permission) {
	g_permissionChecks.emplace_back(slot, ToStd(permission));
	const bool allowed = g_permissionSlots.count(slot) != 0;

	if (g_reuseAfterSnapshotArmed && slot == g_reuseAfterSnapshotSlot) {
		g_reuseAfterSnapshotArmed = false;
		g_clients[static_cast<std::size_t>(slot)].steamid = g_reuseAfterSnapshotNewId;
		g_adminDataReady[{slot, g_reuseAfterSnapshotNewId}] = false;
	}
	return allowed;
}

bool FakeHasFlag(int32_t slot, const plg::string& flag) {
	g_flagChecks.emplace_back(slot, ToStd(flag));
	return g_flagSlots.count(slot) != 0;
}

// --- installing/resetting the fake world --------------------------------------------

void InstallFakes() {
	plg::GetConfigsDir = &FakeGetConfigsDir;
	plg::Log = &FakeLog;

	__s2sdk_OnMapStart_Register = &FakeMapStartRegister;
	__s2sdk_OnMapStart_Unregister = &FakeMapStartUnregister;
	__s2sdk_OnMapEnd_Register = &FakeMapEndRegister;
	__s2sdk_OnMapEnd_Unregister = &FakeMapEndUnregister;

	__s2sdk_OnClientAuthenticated_Register = &FakeAuthRegister;
	__s2sdk_OnClientAuthenticated_Unregister = &FakeAuthUnregister;
	__s2sdk_OnClientConnected_Register = &FakeConnectRegister;
	__s2sdk_OnClientConnected_Unregister = &FakeConnectUnregister;
	__s2sdk_OnClientDisconnect_Register = &FakeDisconnectRegister;
	__s2sdk_OnClientDisconnect_Unregister = &FakeDisconnectUnregister;

	__s2sdk_HookEvent = &FakeHookEvent;
	__s2sdk_UnhookEvent = &FakeUnhookEvent;
	__s2sdk_GetEventPlayerSlot = &FakeGetEventPlayerSlot;

	__s2sdk_IsClientConnected = &FakeIsClientConnected;
	__s2sdk_IsFakeClient = &FakeIsFakeClient;
	__s2sdk_IsClientAuthorized = &FakeIsClientAuthorized;
	__s2sdk_GetClientSteamID64 = &FakeGetClientSteamID64;
	__s2sdk_GetMaxClients = &FakeGetMaxClients;
	__s2sdk_KickClient = &FakeKickClient;

	__admin_system_GetPluginVersion = &FakeGetPluginVersion;
	__admin_system_IsCoreLoaded = &FakeIsCoreLoaded;
	__admin_system_HasPermission = &FakeHasPermission;
	__admin_system_HasFlag = &FakeHasFlag;
	__admin_system_IsClientAdminDataReady = &FakeIsClientAdminDataReady;
}

// --- the throw-away config workspace ------------------------------------------------

std::string g_baseDir;

std::string AdminConfigPath() {
	return g_baseDir + "/configs/admin_system/reserved_slots.ini";
}

std::string PluginConfigPath() {
	return g_baseDir + "/configs/as_reserved_slots/reserved_slots.ini";
}

void WriteFile(const std::string& path, std::string_view text) {
	std::error_code error;
	std::filesystem::create_directories(std::filesystem::path(path).parent_path(), error);
	std::FILE* file = std::fopen(path.c_str(), "wb");
	if (file == nullptr) {
		std::printf("FAIL: could not write %s\n", path.c_str());
		++g_failures;
		return;
	}
	std::fwrite(text.data(), 1, text.size(), file);
	std::fclose(file);
}

void RemoveConfigFiles() {
	std::error_code error;
	std::filesystem::remove_all(g_baseDir + "/configs", error);
}

// --- the fake world reset -----------------------------------------------------------

void ResetWorld() {
	g_clients.fill(FakeClient{});
	g_maxClients = 10;
	g_connectedCalls = 0;
	g_fakeCalls = 0;
	g_authorizedCalls = 0;
	g_steamCalls = 0;
	g_maxClientsCalls = 0;
	g_queriedSlots.clear();
	g_kicks.clear();

	g_permissionSlots.clear();
	g_flagSlots.clear();
	g_permissionChecks.clear();
	g_flagChecks.clear();
	g_adminDataReady.clear();
	g_adminDataChecks.clear();
	g_adminDataCalls.clear();
	g_adminDataFailSecondCall.clear();
	g_adminDataFailFromCall.clear();
	g_adminDataReadyDefault = true;
	g_reuseAfterSnapshotArmed = false;
	g_reuseAfterSnapshotSlot = -1;
	g_reuseAfterSnapshotNewId = 0;
	g_coreLoaded = true;

	g_onMapStart = nullptr;
	g_onMapEnd = nullptr;
	g_mapStartRegisters = 0;
	g_mapStartUnregisters = 0;
	g_mapEndRegisters = 0;
	g_mapEndUnregisters = 0;

	g_onAuth = nullptr;
	g_onConnect = nullptr;
	g_onDisconnect = nullptr;
	g_authRegisters = 0;
	g_authUnregisters = 0;
	g_connectRegisters = 0;
	g_connectUnregisters = 0;
	g_disconnectRegisters = 0;
	g_disconnectUnregisters = 0;

	g_eventHooks.clear();
	g_hookCalls = 0;
	g_unhookCalls = 0;
	g_hookResult = s2sdk::EventHookError::Okay;
	g_eventSlot = -1;
	g_eventKey.clear();
	g_getEventSlotCalls = 0;

	g_logs.clear();
	RemoveConfigFiles();

	g_configsDir = g_baseDir + "/configs";
	InstallFakes();

	g_mapReady = false;
	g_mapEndedSinceStart = false;
	g_firstUpdateDone = false;
}

// Stops whatever a previous test left behind and starts the next test from an empty fake world.
void PrepareTest() {
	g_asReservedSlotsPlugin.OnPluginEnd();
	ResetWorld();
}

void FinishTest() {
	g_asReservedSlotsPlugin.OnPluginEnd();
	ResetWorld();
}

// --- helpers -------------------------------------------------------------------------

void StartPlugin() {
	const plg::PluginResult result = g_asReservedSlotsPlugin.OnPluginStart();
	Check(result.GetCode() == plg::PluginCode::Ok, "OnPluginStart returns Ok (never Failed)");
}

void EnterMap() {
	MapStart();
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
}

void Advance(std::chrono::milliseconds dt) {
	g_asReservedSlotsPlugin.OnPluginUpdate(dt);
}

void AddClient(int32_t slot, uint64_t steamid, bool fake = false, bool authorized = true) {
	Check(slot >= 0 && slot < 64, "test client slot in range");
	if (slot < 0 || slot >= 64) {
		return;
	}
	g_clients[static_cast<std::size_t>(slot)] =
			FakeClient{true, authorized, fake, steamid};
}

void RemoveClient(int32_t slot) {
	if (slot >= 0 && slot < 64) {
		g_clients[static_cast<std::size_t>(slot)] = FakeClient{};
	}
}

uint64_t AuthSteamId(int32_t slot) {
	return (1ull << 60) | static_cast<uint64_t>(slot);
}

int KickCount() {
	return static_cast<int>(g_kicks.size());
}

bool Kicked(int32_t slot) {
	for (const FakeKick& kick : g_kicks) {
		if (kick.slot == slot) {
			return true;
		}
	}
	return false;
}

int PermissionCheckCount() {
	return static_cast<int>(g_permissionChecks.size());
}

int KickReasonAt() {
	return g_kicks.empty() ? 0 : static_cast<int>(g_kicks[0].reason);
}

// --- src/kv1.hpp + src/config.hpp ----------------------------------------------------

void TestConfigReader() {
	std::printf("-- KV1 reader and config semantics\n");

	as_reserved_slots::Config config;
	const std::string_view production = R"(
// The live Pisex file, comments included.
"ReservedSlots"
{
    "reserve_flag"     "@admin/reserve" // Флаг для зарезервированных слотов
    "public_slots"     "30"             // Количество общедоступных слотов
    "kick_reason_id"   "135"            // NETWORK_DISCONNECT_REJECT_SERVERFULL
})";
	Check(as_reserved_slots::LoadConfigFromText(production, 64, config), "the production file parses");
	CheckEq(config.reserveFlag, "@admin/reserve", "reserve_flag");
	CheckEqInt(config.publicSlots, 30, "public_slots");
	CheckEqInt(config.kickReasonId, 135, "kick_reason_id");

	// Unquoted tokens, escapes, a BOM and the single top-level block merge.
	std::string bom = "\xEF\xBB\xBF";
	bom += R"("ReservedSlots" { reserve_flag "@admin\\reserve" public_slots 7 kick_reason_id 41 })";
	Check(as_reserved_slots::LoadConfigFromText(bom, 10, config), "unquoted/BOM file parses");
	CheckEq(config.reserveFlag, "@admin\\reserve", "escaped reserve flag");
	CheckEqInt(config.publicSlots, 7, "unquoted public_slots");
	CheckEqInt(config.kickReasonId, 41, "unquoted kick_reason_id");

	// #base/#include/#define are skipped, not followed.
	Check(as_reserved_slots::LoadConfigFromText(
			  R"(#base "admin_system/base.ini"
#include "shared.ini"
#define RESERVED
"ReservedSlots" { "public_slots" "5" })",
			  10, config),
		  "preprocessor lines are skipped");
	CheckEqInt(config.publicSlots, 5, "public_slots after preprocessor lines");

	// Missing keys keep the original's defaults (maxClients - 2).
	Check(as_reserved_slots::LoadConfigFromText(R"("ReservedSlots" { })", 10, config),
		  "empty block parses");
	CheckEqInt(config.publicSlots, 8, "default public_slots = maxClients - 2");
	CheckEq(config.reserveFlag, "@admin/reserve", "default reserve_flag");
	CheckEqInt(config.kickReasonId, 135, "default kick_reason_id");

	// GetInt: from_chars then the original's atoi fallback; an empty value keeps the default.
	const std::optional<as_reserved_slots::KvNode> root = as_reserved_slots::ParseKv1(
			R"("ReservedSlots" { "a" "12" "b" "1.5" "c" "abc" "d" "-3" "e" "" "f" "12x" })");
	Check(root.has_value(), "getter fixture parses");
	if (root) {
		CheckEqInt(root->GetInt("a", 99), 12, "GetInt plain");
		CheckEqInt(root->GetInt("b", 99), 1, "GetInt atoi fallback");
		CheckEqInt(root->GetInt("c", 99), 0, "GetInt non-numeric");
		CheckEqInt(root->GetInt("d", 99), -3, "GetInt negative");
		CheckEqInt(root->GetInt("e", 99), 99, "GetInt empty keeps the default");
		CheckEqInt(root->GetInt("f", 99), 12, "GetInt trailing junk");
		CheckEqInt(root->GetInt("missing", 99), 99, "GetInt missing key");
		CheckEqInt(root->GetInt("A", 99), 12, "GetInt case-insensitive");
	}

	// Two top-level blocks: nothing is merged (Valve only merges a single root block).
	Check(as_reserved_slots::LoadConfigFromText(
			  R"("One" { "public_slots" "1" } "Two" { "public_slots" "2" })", 10, config),
		  "two blocks parse");
	CheckEqInt(config.publicSlots, 8, "two blocks keep the default");

	// A malformed file is rejected whole and leaves the caller's config untouched.
	as_reserved_slots::Config untouched;
	untouched.publicSlots = 42;
	untouched.reserveFlag = "keep";
	untouched.kickReasonId = 7;
	Check(!as_reserved_slots::LoadConfigFromText(R"("ReservedSlots" { "public_slots" "1")", 10, untouched),
		  "missing '}' is rejected");
	Check(!as_reserved_slots::LoadConfigFromText(R"("ReservedSlots" { "public_slots" "1 })", 10, untouched),
		  "unterminated string is rejected");
	Check(!as_reserved_slots::LoadConfigFromText(R"("ReservedSlots" { "public_slots" "1" } })", 10, untouched),
		  "stray '}' is rejected");
	CheckEqInt(untouched.publicSlots, 42, "a rejected file leaves public_slots untouched");
	CheckEq(untouched.reserveFlag, "keep", "a rejected file leaves reserve_flag untouched");
	CheckEqInt(untouched.kickReasonId, 7, "a rejected file leaves kick_reason_id untouched");

	// Empty input is an empty root, not malformed: the defaults stay.
	Check(as_reserved_slots::LoadConfigFromText("", 10, config), "empty text parses");
	CheckEqInt(config.publicSlots, 8, "empty text keeps the default");

	// The original's clamps: public_slots in [0, maxClients], kick_reason_id < 0 -> 39.
	Check(as_reserved_slots::LoadConfigFromText(
			  R"("ReservedSlots" { "public_slots" "-5" "kick_reason_id" "-7" })", 10, config),
		  "negative values parse");
	CheckEqInt(config.publicSlots, 0, "negative public_slots becomes 0");
	CheckEqInt(config.kickReasonId, 39, "negative kick_reason_id becomes 39");
	Check(as_reserved_slots::LoadConfigFromText(
			  R"("ReservedSlots" { "public_slots" "50" })", 10, config),
		  "oversized public_slots parses");
	CheckEqInt(config.publicSlots, 10, "public_slots is clamped to maxClients");
	Check(as_reserved_slots::LoadConfigFromText(
			  R"("ReservedSlots" { "public_slots" "7" })", 0, config),
		  "maxClients 0 still parses");
	CheckEqInt(config.publicSlots, 7, "maxClients 0 does not clamp");

	CheckEqInt(as_reserved_slots::DefaultPublicSlots(1), 1, "1-slot default");
	CheckEqInt(as_reserved_slots::DefaultPublicSlots(2), 2, "2-slot default");
	CheckEqInt(as_reserved_slots::DefaultPublicSlots(10), 8, "10-slot default");
	CheckEqInt(as_reserved_slots::DefaultPublicSlots(64), 62, "64-slot default");
	CheckEqInt(as_reserved_slots::DefaultPublicSlots(0), 0, "0-slot default");

	// An explicitly empty reserve_flag is kept (the original disables the reserve set).
	Check(as_reserved_slots::LoadConfigFromText(R"("ReservedSlots" { "reserve_flag" "" })", 10, config),
		  "empty reserve_flag parses");
	Check(config.reserveFlag.empty(), "empty reserve_flag stays empty");
}

void TestConfigPaths() {
	std::printf("-- config candidates and the file walk\n");

	const std::vector<std::string> candidates =
			as_reserved_slots::ConfigCandidates("/srv/cs2/game/csgo/addons/plugify/configs");
	CheckEqInt(static_cast<int64_t>(candidates.size()), 3, "three candidates");
	if (candidates.size() == 3) {
		CheckEq(candidates[0], as_reserved_slots::kLegacyConfigPath, "the Metamod spelling is first");
		CheckEq(candidates[1], "/srv/cs2/game/csgo/addons/plugify/configs/admin_system/reserved_slots.ini",
				"admin_system candidate");
		CheckEq(candidates[2], "/srv/cs2/game/csgo/addons/plugify/configs/as_reserved_slots/reserved_slots.ini",
				"plugin-folder candidate");
	}
	const std::vector<std::string> trailing = as_reserved_slots::ConfigCandidates("/srv/configs/");
	CheckEqInt(static_cast<int64_t>(trailing.size()), 3, "three candidates with a trailing slash");
	CheckEq(trailing[1], "/srv/configs/admin_system/reserved_slots.ini", "trailing slash admin_system");
	CheckEq(trailing[2], "/srv/configs/as_reserved_slots/reserved_slots.ini", "trailing slash plugin");

	const std::vector<std::string> noDir = as_reserved_slots::ConfigCandidates("");
	CheckEqInt(static_cast<int64_t>(noDir.size()), 1, "only the legacy candidate without a configs dir");
	CheckEq(noDir[0], as_reserved_slots::kLegacyConfigPath, "legacy candidate without a configs dir");

	RemoveConfigFiles();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "3" })");
	WriteFile(PluginConfigPath(), R"("ReservedSlots" { "public_slots" "4" })");
	CheckEq(as_reserved_slots::ResolveConfigPath(g_configsDir), AdminConfigPath(),
			"the admin_system file wins over the plugin folder");
	RemoveConfigFiles();
	WriteFile(PluginConfigPath(), R"("ReservedSlots" { "public_slots" "4" })");
	CheckEq(as_reserved_slots::ResolveConfigPath(g_configsDir), PluginConfigPath(),
			"the plugin folder is the fallback");
	RemoveConfigFiles();
	Check(as_reserved_slots::ResolveConfigPath(g_configsDir).empty(), "no file -> no resolved path");

	as_reserved_slots::ConfigLoadOutcome outcome = as_reserved_slots::LoadConfig(g_configsDir, 10);
	Check(outcome.status == as_reserved_slots::ConfigLoadStatus::Missing, "missing status");
	CheckEqInt(outcome.config.publicSlots, 8, "missing file -> default public_slots");

	WriteFile(PluginConfigPath(), R"("ReservedSlots" { "public_slots" "4" "kick_reason_id" "41" })");
	outcome = as_reserved_slots::LoadConfig(g_configsDir, 10);
	Check(outcome.status == as_reserved_slots::ConfigLoadStatus::Loaded, "loaded status");
	CheckEqInt(outcome.config.publicSlots, 4, "loaded public_slots");
	CheckEqInt(outcome.config.kickReasonId, 41, "loaded kick_reason_id");
	CheckEq(outcome.path, PluginConfigPath(), "loaded path");

	WriteFile(PluginConfigPath(), R"("ReservedSlots" { "public_slots" "4")");
	outcome = as_reserved_slots::LoadConfig(g_configsDir, 10);
	Check(outcome.status == as_reserved_slots::ConfigLoadStatus::Malformed, "malformed status");
	CheckEqInt(outcome.config.publicSlots, 8, "malformed file -> default public_slots");
	CheckEqInt(outcome.config.kickReasonId, 135, "malformed file -> default kick_reason_id");
}

// --- the plugin's config walk --------------------------------------------------------

void TestPluginConfigWalk() {
	std::printf("-- the plugin's config walk\n");

	// Loaded admin_system file (the production layout).
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" {
		"reserve_flag" "@admin/reserve"
		"public_slots" "2"
		"kick_reason_id" "41"
	})");
	AddClient(0, 1000);
	AddClient(1, 1001);
	StartPlugin();
	EnterMap();
	AddClient(2, 1002);
	FireConnect(2);
	FireAuth(2, 1002);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the loaded config enforces public_slots 2");
	Check(Kicked(2), "the joining non-reserve player is kicked");
	CheckEqInt(static_cast<int64_t>(KickReasonAt()),
			   static_cast<int64_t>(s2sdk::NetworkDisconnectionReason::Kickbanadded),
			   "the configured kick reason is used (41)");
	FinishTest();

	// The plugin's own folder is the fallback.
	PrepareTest();
	WriteFile(PluginConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 2000);
	StartPlugin();
	EnterMap();
	AddClient(1, 2001);
	FireAuth(1, 2001);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the plugin-folder config is used");
	Check(Kicked(1), "the player over the fallback config is kicked");
	FinishTest();

	// A malformed file keeps the defaults (maxClients - 2) and logs the original's line.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1")");
	for (int32_t slot = 0; slot < 8; ++slot) {
		AddClient(slot, 3000 + static_cast<uint64_t>(slot));
	}
	StartPlugin();
	EnterMap();
	AddClient(8, 4000);
	FireAuth(8, 4000);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the malformed file falls back to maxClients - 2");
	Check(Kicked(8), "the ninth non-reserve player is kicked with public_slots 8");
	Check(Logged(plg::Severity::Error, "Failed to load addons/configs/admin_system/reserved_slots.ini, using defaults"),
		  "the original's failure line is logged");
	FinishTest();

	// No file at all: the same safe defaults, not public_slots = 0.
	PrepareTest();
	for (int32_t slot = 0; slot < 8; ++slot) {
		AddClient(slot, 5000 + static_cast<uint64_t>(slot));
	}
	StartPlugin();
	EnterMap();
	AddClient(8, 6000);
	FireAuth(8, 6000);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a missing file uses maxClients - 2");
	Check(Kicked(8), "a missing file does not act like public_slots 0");
	FinishTest();

	// The host reports no configs directory: the relative legacy path is the only candidate and
	// does not exist here, so the defaults still apply.
	PrepareTest();
	plg::GetConfigsDir = nullptr;
	for (int32_t slot = 0; slot < 8; ++slot) {
		AddClient(slot, 7000 + static_cast<uint64_t>(slot));
	}
	StartPlugin();
	EnterMap();
	AddClient(8, 8000);
	FireAuth(8, 8000);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "no configs dir -> defaults");
	Check(Logged(plg::Severity::Error, "the plugify configs directory is unavailable"),
		  "a missing configs dir is logged");
	FinishTest();
}

// --- B1/B2: the map gate -------------------------------------------------------------

void TestStartAndMapGate() {
	std::printf("-- start and the map gate\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	StartPlugin();

	CheckEqInt(g_mapStartRegisters, 1, "OnMapStart registered once");
	CheckEqInt(g_mapEndRegisters, 1, "OnMapEnd registered once");
	CheckEqInt(g_authRegisters, 1, "OnClientAuthenticated registered once");
	CheckEqInt(g_connectRegisters, 1, "OnClientConnected registered once");
	CheckEqInt(g_disconnectRegisters, 1, "OnClientDisconnect registered once");
	CheckEqInt(g_hookCalls, 1, "player_disconnect hooked once");
	Check(HasEventHook("player_disconnect", s2sdk::HookMode::Pre), "player_disconnect is a Pre hook");
	Check(!g_mapReady, "the gate is shut on plugin start");
	CheckEqInt(g_maxClientsCalls, 0, "GetMaxClients is not called before a map");
	CheckEqInt(g_connectedCalls, 0, "no client query before a map");

	// An auth event before the first map only records state; it must not query clients or kick.
	AddClient(0, 1111222233334444ull);
	FireAuth(0, 1111222233334444ull);
	CheckEqInt(g_connectedCalls, 0, "the auth callback makes no client query");
	CheckEqInt(KickCount(), 0, "the auth callback never kicks");
	CheckEqInt(PermissionCheckCount(), 0, "the auth callback never checks permissions");

	MapStart();
	Check(g_mapReady, "OnMapStart opens the gate");
	CheckEqInt(g_maxClientsCalls, 0, "OnMapStart itself calls no max-clients query");
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	CheckEqInt(g_maxClientsCalls, 1, "the first ready update reads maxClients once");
	Check(g_mapReady, "the gate stays open");
	CheckEqInt(KickCount(), 0, "seeding never kicks an already-online player");

	// The pending auth is evaluated on the next reconcile (not in the auth callback).
	Advance(std::chrono::seconds(1));
	CheckEqInt(PermissionCheckCount() > 0 ? 1 : 0, 1, "the reconcile evaluates the pending player");
	CheckEqInt(KickCount(), 0, "one player on a two-public-slot server is not kicked");

	// OnMapEnd must not touch a client.
	const int connectedBefore = g_connectedCalls;
	const int maxBefore = g_maxClientsCalls;
	MapEnd();
	Check(!g_mapReady, "OnMapEnd closes the gate");
	CheckEqInt(g_connectedCalls, connectedBefore, "OnMapEnd makes no client query");
	CheckEqInt(g_maxClientsCalls, maxBefore, "OnMapEnd makes no max-clients query");

	Advance(std::chrono::seconds(1));
	CheckEqInt(g_connectedCalls, connectedBefore, "no client query while the gate is shut");
	CheckEqInt(g_maxClientsCalls, maxBefore, "no max-clients query while the gate is shut");

	MapStart();
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	Check(g_mapReady, "the next OnMapStart reopens the gate");
	FinishTest();
}

void TestMidMapStart() {
	std::printf("-- a plugin loaded into a running map\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	// Three players are already online (over public_slots): the first pass must only seed them.
	for (int32_t slot = 0; slot < 3; ++slot) {
		AddClient(slot, 9000 + static_cast<uint64_t>(slot));
	}
	StartPlugin();
	Check(!g_mapReady, "the gate is shut before the first update");
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	Check(g_mapReady, "the first update of a mid-map load opens the gate");
	CheckEqInt(KickCount(), 0, "existing players are seeded, not kicked");
	CheckEqInt(g_maxClientsCalls, 1, "the config is loaded on the first ready update");

	// A player who authenticates after the seed is evaluated.
	AddClient(3, 9003);
	FireConnect(3);
	FireAuth(3, 9003);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a new player over the seeded population is evaluated");
	Check(Kicked(3), "the new non-reserve player is kicked");
	FinishTest();
}

void TestMapChangeWindowStart() {
	std::printf("-- OnPluginStart inside the map-change window\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 1100);
	StartPlugin();
	MapEnd(); // the plugin started between maps
	Check(!g_mapReady, "OnMapEnd keeps the gate shut");
	const int connectedBefore = g_connectedCalls;
	const int maxBefore = g_maxClientsCalls;
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	Check(!g_mapReady, "the first update does not latch readiness after an OnMapEnd");
	CheckEqInt(g_connectedCalls, connectedBefore, "no client query in the map-change window");
	CheckEqInt(g_maxClientsCalls, maxBefore, "no max-clients query in the map-change window");

	MapStart();
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	Check(g_mapReady, "the next OnMapStart opens the gate");
	CheckEqInt(g_maxClientsCalls, 1, "the config is loaded after the new map");
	FinishTest();
}

// --- the ported module: reserved/full ------------------------------------------------

void TestNonReserveFull() {
	std::printf("-- non-reserve players and public_slots\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 1200);
	AddClient(1, 1201);
	AddClient(5, 0, /*fake=*/true); // a bot never counts
	g_permissionSlots.insert(3);
	AddClient(3, 1203); // reserve player, already online
	StartPlugin();
	EnterMap();
	CheckEqInt(KickCount(), 0, "seed does not kick the already-online population");

	// The third non-reserve player (count includes the newcomer) is kicked.
	AddClient(4, 1204);
	FireConnect(4);
	FireAuth(4, 1204);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "one kick for the player over public_slots");
	Check(Kicked(4), "the joining non-reserve player is kicked, not the reserve player");
	CheckEqInt(static_cast<int64_t>(KickReasonAt()),
			   static_cast<int64_t>(s2sdk::NetworkDisconnectionReason::RejectServerfull),
			   "the default reason is 135 (RejectServerfull)");
	Check(g_kicks.empty() || g_kicks[0].message.empty(), "the engine kick carries no message");

	// Count == public_slots must not kick.
	FireDisconnect(4);
	RemoveClient(4);
	FireDisconnect(1);
	RemoveClient(1);
	AddClient(6, 1206);
	FireAuth(6, 1206);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "exactly public_slots non-reserve players are allowed");

	// public_slots = 0: any non-reserve player is over the limit.
	FinishTest();
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	AddClient(0, 1300);
	StartPlugin();
	EnterMap();
	AddClient(1, 1301);
	FireAuth(1, 1301);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "public_slots 0 kicks the first new non-reserve player");
	Check(Kicked(1), "the kicked slot is the newcomer");
	FinishTest();
}

void TestReserveFull() {
	std::printf("-- reserve players and the first non-reserve victim\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 1400);
	AddClient(1, 1401);
	AddClient(2, 1402);
	AddClient(7, 0, /*fake=*/true);
	g_permissionSlots.insert(5);
	AddClient(5, 1405); // a reserve admin, already online
	StartPlugin();
	EnterMap();
	CheckEqInt(KickCount(), 0, "seed never kicks");

	// A reserve player joins over the limit: the first non-reserve (slot 0) is kicked.
	g_flagSlots.insert(6);
	AddClient(6, 1406);
	FireConnect(6);
	FireAuth(6, 1406);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a reserve join kicks exactly one player");
	Check(Kicked(0), "the first non-reserve player is kicked");
	Check(!Kicked(5) && !Kicked(6), "reserve players are never the target");
	Check(!Kicked(7), "a bot is never the target");

	// count <= public_slots: a reserve join kicks nobody.
	FinishTest();
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 1500);
	g_permissionSlots.insert(1);
	AddClient(1, 1501);
	StartPlugin();
	EnterMap();
	g_flagSlots.insert(2);
	AddClient(2, 1502);
	FireAuth(2, 1502);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a reserve join below the limit kicks nobody");

	// Empty reserve_flag: a player who would otherwise be reserve is treated as non-reserve.
	FinishTest();
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" "reserve_flag" "" })");
	AddClient(0, 1600);
	AddClient(1, 1601);
	g_permissionSlots.insert(2);
	AddClient(2, 1602);
	StartPlugin();
	EnterMap();
	AddClient(3, 1603);
	FireAuth(3, 1603);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "an empty reserve_flag disables the reserve set");
	Check(Kicked(3), "the joining player is kicked as a non-reserve player");
	FinishTest();
}

void TestKickReasonAndMissingKick() {
	std::printf("-- kick_reason_id and a missing kick binding\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" "kick_reason_id" "41" })");
	AddClient(0, 1700);
	StartPlugin();
	EnterMap();
	AddClient(1, 1701);
	FireAuth(1, 1701);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "one kick with a custom reason");
	CheckEqInt(static_cast<int64_t>(KickReasonAt()),
			   static_cast<int64_t>(s2sdk::NetworkDisconnectionReason::Kickbanadded),
			   "the custom reason 41 is preserved");
	FinishTest();

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" "kick_reason_id" "-5" })");
	AddClient(0, 1800);
	StartPlugin();
	EnterMap();
	AddClient(1, 1801);
	FireAuth(1, 1801);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a negative reason still kicks");
	CheckEqInt(static_cast<int64_t>(KickReasonAt()),
			   static_cast<int64_t>(s2sdk::NetworkDisconnectionReason::Kicked),
			   "a negative reason becomes 39 (Kicked)");
	FinishTest();

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 1900);
	StartPlugin();
	EnterMap();
	AddClient(1, 1901);
	FireAuth(1, 1901);
	__s2sdk_KickClient = nullptr;
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a missing KickClient binding is fail-soft");
	Check(Logged(plg::Severity::Error, "KickClient/IsClientConnected binding is unavailable"),
		  "the missing kick binding is logged");
	FinishTest();
}

// --- slots and maxClients ------------------------------------------------------------

void TestSlotsAndMaxClients() {
	std::printf("-- slots and maxClients bounds\n");

	// maxClients 2: slot 2 is a valid s2sdk slot but outside the walked range.
	PrepareTest();
	g_maxClients = 2;
	AddClient(0, 2000);
	AddClient(1, 2001);
	AddClient(2, 2002);
	StartPlugin();
	EnterMap();
	CheckEqInt(g_maxClientsCalls, 1, "maxClients 2 is read once");
	bool queriedSlot2 = false;
	for (const int32_t queried : g_queriedSlots) {
		queriedSlot2 = queriedSlot2 || queried == 2;
	}
	Check(!queriedSlot2, "slot 2 is outside maxClients and not seeded");
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "slot 2 is never evaluated with maxClients 2");
	CheckEqInt(g_clients[2].steamid, 2002, "the out-of-range client fixture is unchanged");
	FinishTest();

	// maxClients 1000 is clamped to the 64 CS2 slots: slot 64 is never queried.
	PrepareTest();
	g_maxClients = 1000;
	StartPlugin();
	EnterMap();
	g_queriedSlots.clear();
	Advance(std::chrono::seconds(1));
	bool outOfRange = false;
	for (const int32_t slot : g_queriedSlots) {
		outOfRange = outOfRange || slot < 0 || slot >= 64;
	}
	Check(!outOfRange, "no slot outside 0..63 is queried");
	FinishTest();

	// No usable maxClients yet: no config, no client query, no kick. Once it appears, load.
	PrepareTest();
	g_maxClients = 0;
	AddClient(0, 2100);
	StartPlugin();
	MapStart();
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	CheckEqInt(g_connectedCalls, 0, "maxClients 0 leaves the config unloaded and clients untouched");
	CheckEqInt(KickCount(), 0, "maxClients 0 never kicks");
	g_maxClients = 10;
	Advance(std::chrono::milliseconds(16));
	CheckEqInt(g_maxClientsCalls, 2, "the config is retried after maxClients appears");
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the seeded player is not kicked after the retry");
	FinishTest();

	// maxClients -1 behaves like "not ready".
	PrepareTest();
	g_maxClients = -1;
	AddClient(0, 2200);
	StartPlugin();
	MapStart();
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	CheckEqInt(g_connectedCalls, 0, "maxClients -1 leaves clients untouched");
	CheckEqInt(KickCount(), 0, "maxClients -1 never kicks");
	FinishTest();

	// GetMaxClients binding missing: no config, no kick; restored -> load.
	PrepareTest();
	AddClient(0, 2300);
	__s2sdk_GetMaxClients = nullptr;
	StartPlugin();
	MapStart();
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	CheckEqInt(g_connectedCalls, 0, "a missing GetMaxClients leaves clients untouched");
	CheckEqInt(KickCount(), 0, "a missing GetMaxClients never kicks");
	Check(Logged(plg::Severity::Error, "GetMaxClients binding is unavailable"),
		  "the missing max-clients binding is logged");
	__s2sdk_GetMaxClients = &FakeGetMaxClients;
	Advance(std::chrono::milliseconds(16));
	CheckEqInt(g_maxClientsCalls, 1, "the config is retried after the binding is restored");
	FinishTest();

	// Out-of-range callback slots are ignored and cause no client query.
	PrepareTest();
	StartPlugin();
	EnterMap();
	const int connectedBefore = g_connectedCalls;
	FireAuth(-1, 111);
	FireAuth(64, 112);
	FireConnect(-1);
	FireConnect(64);
	FireDisconnect(-1);
	FireDisconnect(64);
	FirePlayerDisconnectEvent(-1);
	FirePlayerDisconnectEvent(64);
	CheckEqInt(g_connectedCalls, connectedBefore, "out-of-range callbacks make no client query");
	CheckEqInt(KickCount(), 0, "out-of-range callbacks never kick");
	FinishTest();
}

// --- auth/connect ordering and reuse -------------------------------------------------

void TestAuthOrderingAndReuse() {
	std::printf("-- auth/connect ordering and slot reuse\n");

	// Auth only records the new connection; the kick happens on the next reconcile.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 2400);
	AddClient(1, 2401);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireConnect(2);
	FireAuth(2, AuthSteamId(2));
	CheckEqInt(KickCount(), 0, "the auth callback itself does not kick");
	CheckEqInt(PermissionCheckCount(), 0, "the auth callback itself does not check permissions");
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the reconcile evaluates the auth-pending slot");
	Check(Kicked(2), "the over-limit newcomer is kicked");

	// A duplicate auth for the same connection is deduped: no second kick.
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a duplicate auth does not kick a second player");
	FinishTest();

	// Same slot, same SteamID64 after a disconnect: it is a new connection and is evaluated again.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 2500);
	AddClient(1, 2501);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireConnect(2);
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "first connection is kicked");
	FireDisconnect(2);
	RemoveClient(2);
	AddClient(2, AuthSteamId(2)); // the same player reconnects into the same slot
	FireConnect(2);
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 2, "the same SteamID64 reconnecting is evaluated again");
	FinishTest();

	// Slot reuse with a different SteamID64.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 2600);
	AddClient(1, 2601);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireConnect(2);
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the first occupant is kicked");
	FireDisconnect(2);
	RemoveClient(2);
	AddClient(2, AuthSteamId(3));
	FireConnect(2);
	FireAuth(2, AuthSteamId(3));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 2, "a reused slot with a new SteamID64 is evaluated again");
	Check(Kicked(2), "the new occupant is the one evaluated");
	FinishTest();

	// No auth/connect callbacks: the reconcile still picks the authorized client up.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 2700);
	AddClient(1, 2701);
	StartPlugin();
	EnterMap();
	AddClient(2, 2702);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the reconcile covers a missed auth callback");
	FinishTest();

	// An unauthenticated client is not evaluated.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	AddClient(2, 2800, /*fake=*/false, /*authorized=*/false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "an unauthenticated client is not evaluated");
	FinishTest();

	// A client with no SteamID64 is left alone (identity not ready).
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	AddClient(2, 0);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a client without SteamID64 is never kicked");
	FinishTest();

	// The player_disconnect event clears the slot even if OnClientDisconnect was missed.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 2900);
	AddClient(1, 2901);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the first connection is kicked");
	CheckEqInt(g_getEventSlotCalls, 0, "no event yet");
	Check(FirePlayerDisconnectEvent(2) == s2sdk::ResultType::Continue,
		  "player_disconnect returns Continue");
	CheckEqInt(g_getEventSlotCalls, 1, "GetEventPlayerSlot is used");
	CheckEq(g_eventKey, "userid", "the player-typed event field is userid");
	RemoveClient(2);
	AddClient(2, AuthSteamId(2));
	FireConnect(2);
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 2, "the event cleared the slot for the reconnect");
	FinishTest();
}

// A reconcile pass can see several new players at once. A kick is delivered on the next frame,
// so the pass must not select a just-kicked slot again or kick the same player twice.
void TestBurstNoDuplicateKicks() {
	std::printf("-- a burst of joins does not duplicate a kick\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	AddClient(0, AuthSteamId(0));
	AddClient(1, AuthSteamId(1));
	AddClient(2, AuthSteamId(2));
	FireAuth(0, AuthSteamId(0));
	FireAuth(1, AuthSteamId(1));
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 3, "each over-limit newcomer is kicked once");
	std::set<int32_t> unique;
	for (const FakeKick& kick : g_kicks) {
		unique.insert(kick.slot);
	}
	CheckEqInt(static_cast<int64_t>(unique.size()), 3, "the three kicks target distinct slots");

	// A reserve player first in slot order kicks a lower non-reserve victim; the victim must not be
	// selected again later in the same pass.
	FinishTest();
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	g_permissionSlots.insert(0);
	StartPlugin();
	EnterMap();
	AddClient(0, AuthSteamId(0)); // reserve
	AddClient(1, AuthSteamId(1));
	AddClient(2, AuthSteamId(2));
	FireAuth(0, AuthSteamId(0));
	FireAuth(1, AuthSteamId(1));
	FireAuth(2, AuthSteamId(2));
	Advance(std::chrono::seconds(1));
	std::set<int32_t> victims;
	for (const FakeKick& kick : g_kicks) {
		victims.insert(kick.slot);
	}
	Check(victims.count(1) <= 1, "the first victim is not kicked twice in one pass");
	Check(victims.count(2) <= 1, "the second non-reserve player is not kicked twice in one pass");
	Check(!Kicked(0), "the reserve player is never kicked");
	CheckEqInt(static_cast<int64_t>(g_kicks.size()), static_cast<int64_t>(victims.size()),
			   "every kick in the pass targets a distinct slot");
	FinishTest();
}

// --- security fail-soft ---------------------------------------------------------------

void TestSecurityFailSoft() {
	std::printf("-- permission/identity fail-soft\n");

	// A full server: two non-reserve players, public_slots 1, a third player joining.
	// Every missing admin binding must produce zero kicks and zero permission checks.
	auto fullServer = [](const std::function<void()>& breakAdmin) {
		PrepareTest();
		WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
		AddClient(0, 3000);
		AddClient(1, 3001);
		StartPlugin();
		EnterMap();
		AddClient(2, AuthSteamId(2));
		FireAuth(2, AuthSteamId(2));
		breakAdmin();
		Advance(std::chrono::seconds(1));
		Advance(std::chrono::seconds(1));
		const bool noKicks = KickCount() == 0;
		const bool noPermissions = PermissionCheckCount() == 0;
		Check(noKicks, "a missing admin state produces zero kicks on a full server");
		Check(noPermissions, "a missing admin state produces zero permission checks");
		Check(g_adminDataChecks.empty(), "a missing admin state produces zero readiness queries");
		FinishTest();
	};

	fullServer([] {
		__admin_system_GetPluginVersion = nullptr; // admin_system not loaded at all
		__admin_system_IsCoreLoaded = nullptr;
		__admin_system_HasPermission = nullptr;
		__admin_system_HasFlag = nullptr;
		__admin_system_IsClientAdminDataReady = nullptr;
	});
	fullServer([] { __admin_system_GetPluginVersion = nullptr; });
	fullServer([] { __admin_system_IsCoreLoaded = nullptr; });
	fullServer([] { __admin_system_HasPermission = nullptr; });
	fullServer([] { __admin_system_HasFlag = nullptr; });
	fullServer([] { __admin_system_IsClientAdminDataReady = nullptr; });
	fullServer([] { g_coreLoaded = false; });

	// The core becomes ready later: the slot was left unseen and is retried.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 3100);
	AddClient(1, 3101);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	g_coreLoaded = false;
	Advance(std::chrono::seconds(1));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "an unloaded core never kicks");
	g_coreLoaded = true;
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the pending slot is retried once the core is ready");
	Check(Kicked(2), "the retried slot is the joining player");
	FinishTest();

	// Missing identity/query bindings: no kick, no crash.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 3200);
	AddClient(1, 3201);
	StartPlugin();
	EnterMap();
	AddClient(2, 3202);
	FireAuth(2, 3202);
	__s2sdk_GetClientSteamID64 = nullptr;
	Advance(std::chrono::seconds(1));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a missing identity binding never kicks");
	Check(Logged(plg::Severity::Error, "the s2sdk client bindings are unavailable"),
		  "the missing client bindings are logged");
	FinishTest();

	// Missing IsClientConnected: also fail-soft.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 3300);
	AddClient(1, 3301);
	StartPlugin();
	EnterMap();
	AddClient(2, 3302);
	FireAuth(2, 3302);
	__s2sdk_IsClientConnected = nullptr;
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a missing IsClientConnected never kicks");
	FinishTest();

	// No usable config/maxClients: no kick (covered in TestSlotsAndMaxClients too).
	PrepareTest();
	AddClient(0, 3400);
	AddClient(1, 3401);
	StartPlugin();
	MapStart();
	__s2sdk_GetMaxClients = nullptr;
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	AddClient(2, 3402);
	FireAuth(2, 3402);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a missing max-clients binding never kicks");
	FinishTest();
}

// --- IsClientAdminDataReady: delayed/failed/stale SELECT ------------------------------

void TestAdminDataReadiness() {
	std::printf("-- IsClientAdminDataReady: delayed/failed/stale SELECT\n");

	// The joining player's SELECT is still in flight: no permission query, no kick, retry.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 5000);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(2, AuthSteamId(2), false);
	Advance(std::chrono::seconds(1));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a pending self SELECT never kicks");
	CheckEqInt(PermissionCheckCount(), 0, "a pending self SELECT performs no permission query");
	Check(AdminDataReadyCalled(2, AuthSteamId(2)), "IsClientAdminDataReady was asked for self");
	SetAdminDataReady(2, AuthSteamId(2), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the decision is made once self becomes ready");
	Check(Kicked(2), "the delayed read kicks the over-limit newcomer");
	FinishTest();

	// A failed SELECT (Ready == false forever) is fail-open: no kick, no permission query.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 5100);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(2, AuthSteamId(2), false);
	Advance(std::chrono::seconds(1));
	Advance(std::chrono::seconds(1));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a failed SELECT never kicks");
	CheckEqInt(PermissionCheckCount(), 0, "a failed SELECT performs no permission query");
	FinishTest();

	// A pending candidate (not the joining player) also aborts the whole decision.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 5200);
	AddClient(1, 5201);
	StartPlugin();
	EnterMap();
	g_flagSlots.insert(2);
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(0, 5200, false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a pending candidate aborts the reserve decision");
	CheckEqInt(PermissionCheckCount(), 0, "a pending candidate blocks all permission queries");
	SetAdminDataReady(0, 5200, true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the reserve decision resumes when the candidate is ready");
	Check(Kicked(0), "the ready candidate is the non-reserve victim");
	FinishTest();

	// Ready == true is the definitive zero-row answer, not "this player is an admin".
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	AddClient(3, AuthSteamId(3));
	FireAuth(3, AuthSteamId(3));
	Advance(std::chrono::seconds(1));
	Check(AdminDataReadyCalled(3, AuthSteamId(3)), "the zero-row answer is queried");
	CheckEqInt(KickCount(), 1, "a ready non-admin is counted and kicked as non-reserve");
	Check(Kicked(3), "the zero-row slot is the kicked newcomer");
	FinishTest();

	// Reuse before the snapshot: the answer for the old identity must not be used for the new one.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	const uint64_t oldId = AuthSteamId(4);
	const uint64_t newId = AuthSteamId(5);
	AddClient(2, oldId);
	FireConnect(2);
	FireAuth(2, oldId);
	SetAdminDataReady(2, oldId, false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the old identity is not ready");
	FireDisconnect(2);
	RemoveClient(2);
	AddClient(2, newId);
	FireConnect(2);
	FireAuth(2, newId);
	SetAdminDataReady(2, oldId, true); // a stale ready answer for the previous occupant
	SetAdminDataReady(2, newId, false);
	g_adminDataChecks.clear();
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a stale ready answer for the old identity does not kick");
	Check(AdminDataReadyCalled(2, newId), "readiness is asked for the current identity");
	SetAdminDataReady(2, newId, true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the new identity is evaluated once its SELECT is ready");
	Check(Kicked(2), "the reused slot is kicked under the new identity");
	FinishTest();

	// Reuse after the snapshot: the identity changes after its permissions were read. The
	// consumer's revalidation/identity check must abandon the stale snapshot instead of kicking.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 5300);
	AddClient(1, 5301);
	StartPlugin();
	EnterMap();
	g_flagSlots.insert(2);
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	const uint64_t reusedId = AuthSteamId(6);
	g_reuseAfterSnapshotArmed = true;
	g_reuseAfterSnapshotSlot = 2;
	g_reuseAfterSnapshotNewId = reusedId;
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "an identity change after the snapshot never kicks from the stale data");
	g_adminDataChecks.clear();
	SetAdminDataReady(2, reusedId, true);
	Advance(std::chrono::seconds(1));
	Check(AdminDataReadyCalled(2, reusedId), "the new identity is re-read on the next pass");
	CheckEqInt(KickCount(), 1, "the reserve decision resumes for the stable new identity");
	Check(Kicked(0), "the first non-reserve player is the victim of the re-evaluated reserve join");
	FinishTest();

	// Readiness is revalidated between the snapshot and the kick: a second false aborts the kick.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 5400);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	g_adminDataFailSecondCall.insert({2, AuthSteamId(2)});
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a readiness flip after the snapshot aborts the self kick");
	CheckEqInt(PermissionCheckCount() > 0 ? 1 : 0, 1,
			   "the snapshot phase did reach permissions before the revalidation failed");
	g_adminDataFailSecondCall.clear();
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the retry kicks once readiness is stable");
	Check(Kicked(2), "the stable self is kicked");
	FinishTest();

	// The same revalidation applies to the selected victim.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 5500);
	AddClient(1, 5501);
	StartPlugin();
	EnterMap();
	g_flagSlots.insert(2);
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	g_adminDataFailSecondCall.insert({0, 5500});
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a victim readiness flip aborts the kick");
	g_adminDataFailSecondCall.clear();
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the victim is kicked after a stable readiness re-check");
	Check(Kicked(0), "the selected non-reserve victim is kicked");
	FinishTest();

	// The final check inside KickClientForReserve(): snapshot and the outer decision pass see a
	// ready value, the third read (immediately before the engine call) flips to false.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 5600);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	g_adminDataFailFromCall[{2, AuthSteamId(2)}] = 3;
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a readiness flip immediately before KickClient aborts the kick");
	g_adminDataFailFromCall.clear();
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the final-check retry kicks when readiness is stable");
	Check(Kicked(2), "the stable self is kicked after the final revalidation passes");
	FinishTest();
}

// --- carrying an unfinished decision across OnMapEnd/OnMapStart -----------------------

void TestMapChangeCarry() {
	std::printf("-- pending decisions across a map change\n");

	// Control without a map change: exactly one kick once the SELECT is ready.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6000);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(2, AuthSteamId(2), false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "control: pending before the map change does not kick");
	SetAdminDataReady(2, AuthSteamId(2), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "control: exactly one kick without a map change");
	Check(Kicked(2), "control: the over-limit newcomer is the victim");
	FinishTest();

	// auth -> MapEnd -> MapStart -> ready: the pending decision survives exactly one boundary.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6100);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(2, AuthSteamId(2), false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the pre-change pending player is not evaluated while not ready");
	MapEnd();
	MapStart();
	Advance(std::chrono::milliseconds(16)); // new map seed
	CheckEqInt(KickCount(), 0, "the new-map seed does not kick the carried pending player");
	SetAdminDataReady(2, AuthSteamId(2), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "exactly one kick after the carried decision becomes ready");
	Check(Kicked(2), "the carried pending player is the one kicked");
	FinishTest();

	// Slot reuse/new SteamID64 before the new map's seed: the old pending record is stale and
	// must not kick the new occupant.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	const uint64_t oldId = AuthSteamId(4);
	const uint64_t newId = AuthSteamId(5);
	AddClient(2, oldId);
	FireConnect(2);
	FireAuth(2, oldId);
	SetAdminDataReady(2, oldId, false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the old pending identity is not ready");
	MapEnd();
	MapStart();
	RemoveClient(2);
	AddClient(2, newId);
	FireConnect(2);
	Advance(std::chrono::milliseconds(16)); // seed sees the new occupant, clears the old pending
	FireAuth(2, newId); // must be ignored: the new id was seeded, not re-evaluated
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a reused slot/new SteamID64 gets no stale kick");
	Check(!Kicked(2), "the new occupant is not kicked from the previous occupant's pending state");

	// A genuinely new player after the map still goes through the normal (ready) path.
	AddClient(3, AuthSteamId(6));
	FireAuth(3, AuthSteamId(6));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a new player after the map is still enforced normally");
	Check(Kicked(3) && !Kicked(2), "only the new over-limit player is kicked");
	FinishTest();

	// The pending record is bounded by the map generation: after two boundaries it is gone and
	// the connected player is seeded, not kicked.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(2, AuthSteamId(2), false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "pending decision is not ready");
	MapEnd();
	MapStart();
	Advance(std::chrono::milliseconds(16)); // seed skips the carried pending
	CheckEqInt(KickCount(), 0, "first boundary keeps the pending decision");
	MapEnd(); // second boundary prunes it
	MapStart();
	Advance(std::chrono::milliseconds(16)); // now seeded as an existing player
	SetAdminDataReady(2, AuthSteamId(2), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a pending decision older than one boundary is dropped");
	FinishTest();

	// Already seen players are not kicked again after a map change; new joins are still enforced.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	AddClient(0, 6200);
	StartPlugin();
	EnterMap();
	CheckEqInt(KickCount(), 0, "seeded existing player is not kicked");
	MapEnd();
	MapStart();
	Advance(std::chrono::milliseconds(16));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the previously seen player is not kicked again after the map change");
	AddClient(1, AuthSteamId(7));
	FireAuth(1, AuthSteamId(7));
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a new join after the map change is still evaluated");
	Check(Kicked(1) && !Kicked(0), "only the new non-reserve player is kicked");
	FinishTest();

	// A seen player who disconnects during the changelevel and reconnects after the new map's seed
	// must not be evaluated again: the seen identity survives the boundary.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	AddClient(0, 6250);
	StartPlugin();
	EnterMap();
	CheckEqInt(KickCount(), 0, "seen baseline is not kicked");
	MapEnd();
	FireDisconnect(0); // during the transition: the seen identity must survive
	RemoveClient(0);
	MapStart();
	Advance(std::chrono::milliseconds(16)); // seed sees no client, keeps the seen identity
	AddClient(0, 6250);
	FireConnect(0);
	FireAuth(0, 6250);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a reconnecting already-seen player is not kicked again");
	Check(!Kicked(0), "the seen identity is not re-evaluated after the map change");
	FinishTest();

	// A pending player may be absent at the new map's seed and reconnect shortly after; the
	// decision survives (bounded by generation/TTL) and is evaluated with the new identity.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6300);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(2, AuthSteamId(2), false);
	Advance(std::chrono::seconds(1));
	MapEnd();
	RemoveClient(2); // not reconnected when the new map is seeded
	MapStart();
	Advance(std::chrono::milliseconds(16));
	CheckEqInt(KickCount(), 0, "absent pending player is not seeded away immediately");
	AddClient(2, AuthSteamId(2));
	FireConnect(2);
	FireAuth(2, AuthSteamId(2)); // duplicate of the carried pending event
	SetAdminDataReady(2, AuthSteamId(2), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the late reconnect is evaluated from the carried decision");
	Check(Kicked(2), "the late reconnecting player is the victim");
	FinishTest();

	// A normal disconnect clears the pending decision; after a map change the same identity is
	// merely seeded as an existing player (fail-open), not kicked from the old pending state.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(2));
	FireAuth(2, AuthSteamId(2));
	SetAdminDataReady(2, AuthSteamId(2), false);
	Advance(std::chrono::seconds(1));
	FireDisconnect(2); // normal disconnect, not a map transition
	RemoveClient(2);
	MapEnd();
	MapStart();
	AddClient(2, AuthSteamId(2));
	// Deliberately no FireConnect: this block isolates the "pending was cleared" property. A real
	// reconnect with a connection event is a new join and is covered by TestObservedNewClients.
	Advance(std::chrono::milliseconds(16)); // seed: no pending, so it is an existing player
	SetAdminDataReady(2, AuthSteamId(2), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a normal disconnect clears the pending decision");
	FinishTest();

	// Reload: the new instance seeds the already-online player and never re-kicks it.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	AddClient(0, 6400);
	StartPlugin();
	EnterMap();
	CheckEqInt(KickCount(), 0, "reload baseline: seeded player is not kicked");
	g_asReservedSlotsPlugin.OnPluginEnd();
	g_asReservedSlotsPlugin.OnPluginStart();
	EnterMap();
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a reload seeds the already-online player, no repeat kick");
	FinishTest();
}

// --- B6 observation: missing/0/32-bit auth and SteamID-across-slot migration -----------

void TestObservedNewClients() {
	std::printf("-- B6 observation, markers and SteamID-across-slot migration\n");

	// A new connection that happens before the first seed (reload/map-load window) with a missing
	// auth callback must not be seeded away as if it were a reload player.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6550); // already online before Start: no connection callback, the reload player
	StartPlugin();
	MapStart();
	AddClient(2, AuthSteamId(15));
	FireConnect(2); // a new connection event, but no OnClientAuthenticated
	SetAdminDataReady(2, AuthSteamId(15), false);
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16)); // first seed
	CheckEqInt(KickCount(), 0, "a new join during the first-seed window is not kicked yet");
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the new join waits for its pending admin SELECT");
	SetAdminDataReady(2, AuthSteamId(15), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the new join is evaluated once its data is ready");
	Check(Kicked(2) && !Kicked(0), "only the new joining player is kicked, not the reload player");
	FinishTest();

	// No OnClientAuthenticated at all: the new connected human is still observed on the old map,
	// gets a canonical pending decision, survives the changelevel and is kicked once ready.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6600);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(8)); // no FireAuth: the B6 path
	SetAdminDataReady(2, AuthSteamId(8), false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "a missing auth callback does not kick while the SELECT is pending");
	Check(AdminDataReadyCalled(2, AuthSteamId(8)), "the observed newcomer reaches readiness");
	MapEnd();
	MapStart();
	Advance(std::chrono::milliseconds(16)); // seed must not swallow the observed client
	CheckEqInt(KickCount(), 0, "the observed newcomer is not seeded away on the new map");
	SetAdminDataReady(2, AuthSteamId(8), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the observed missing-callback newcomer is kicked once ready");
	Check(Kicked(2), "the observed slot is the victim");
	FinishTest();

	// Auth callback with a 0 payload: state-only marker, resolved to canonical at the new map seed.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6700);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(9));
	FireAuth(2, 0);
	SetAdminDataReady(2, AuthSteamId(9), false);
	MapEnd();
	MapStart();
	Advance(std::chrono::milliseconds(16)); // Seed resolves the marker with the canonical SteamID
	CheckEqInt(KickCount(), 0, "the 0-payload marker does not kick while the SELECT is pending");
	SetAdminDataReady(2, AuthSteamId(9), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the 0-payload auth marker is resolved and kicked once ready");
	Check(Kicked(2), "the 0-payload marker slot is the victim");
	FinishTest();

	// Auth callback with a 32-bit account id: same marker path.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6800);
	StartPlugin();
	EnterMap();
	AddClient(2, AuthSteamId(10));
	FireAuth(2, 12345); // a 32-bit account id, not a SteamID64
	SetAdminDataReady(2, AuthSteamId(10), false);
	MapEnd();
	MapStart();
	Advance(std::chrono::milliseconds(16));
	CheckEqInt(KickCount(), 0, "the 32-bit auth marker does not kick while the SELECT is pending");
	SetAdminDataReady(2, AuthSteamId(10), true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the 32-bit auth marker is resolved and kicked once ready");
	Check(Kicked(2), "the 32-bit marker slot is the victim");
	FinishTest();

	// The old pending slot is reused by a DIFFERENT player while the same SteamID64 moves to
	// another slot: the identity-keyed pending must follow the moved player and must not be
	// overwritten by the new occupant.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6950);
	StartPlugin();
	EnterMap();
	const uint64_t movingId = AuthSteamId(13);
	const uint64_t newOccupantId = AuthSteamId(14);
	AddClient(2, movingId);
	FireAuth(2, movingId);
	SetAdminDataReady(2, movingId, false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the moving identity starts pending");
	MapEnd();
	RemoveClient(2);
	MapStart();
	AddClient(2, newOccupantId); // old slot reused by a different player
	AddClient(3, movingId);      // the pending identity moved to another slot
	FireConnect(2);
	FireConnect(3);
	Advance(std::chrono::milliseconds(16)); // seed: new occupant seeded, moved identity stays pending
	CheckEqInt(KickCount(), 0, "neither the new occupant nor the pending identity is seeded/kicked");
	SetAdminDataReady(2, movingId, true);
	SetAdminDataReady(3, movingId, true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the moved pending identity is evaluated once");
	Check(Kicked(3) && !Kicked(2), "the moved identity is kicked, the new occupant is not");
	FinishTest();

	// An already processed SteamID64 moves to another slot across the changelevel: the seen
	// identity follows it and the player is not evaluated (and therefore not kicked) again.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "0" })");
	const uint64_t seenMovedId = AuthSteamId(12);
	AddClient(0, seenMovedId);
	StartPlugin();
	EnterMap();
	CheckEqInt(KickCount(), 0, "seen-identity baseline is not kicked");
	MapEnd();
	RemoveClient(0);
	MapStart();
	Advance(std::chrono::milliseconds(16)); // seed absent, keeps the seen identity
	AddClient(1, seenMovedId);
	FireConnect(1);
	FireAuth(1, seenMovedId);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "an already-seen SteamID64 in a new slot is not kicked again");
	Check(!Kicked(0) && !Kicked(1), "neither slot of the moved seen identity is kicked");
	FinishTest();

	// The same SteamID64 moves to another slot across the changelevel: the pending decision is
	// migrated by identity, so the new slot is evaluated and the old one is not kicked.
	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "1" })");
	AddClient(0, 6900);
	StartPlugin();
	EnterMap();
	const uint64_t movedId = AuthSteamId(11);
	AddClient(2, movedId);
	FireAuth(2, movedId);
	SetAdminDataReady(2, movedId, false);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 0, "the old slot is not ready yet");
	MapEnd();
	RemoveClient(2);
	MapStart();
	AddClient(3, movedId); // same player, different slot on the new map
	FireConnect(3);
	FireAuth(3, movedId);
	Advance(std::chrono::milliseconds(16)); // Seed adopts the pending by SteamID64
	CheckEqInt(KickCount(), 0, "the moved identity is not seeded away on the new slot");
	SetAdminDataReady(2, movedId, true);
	SetAdminDataReady(3, movedId, true);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "the moved SteamID64 is evaluated once in the new slot");
	Check(Kicked(3) && !Kicked(2), "the new slot is the victim; the old slot is not kicked");
	FinishTest();
}

// --- bots ---------------------------------------------------------------------------

void TestBots() {
	std::printf("-- bots are never counted or kicked\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 0, /*fake=*/true);
	AddClient(1, 0, /*fake=*/true);
	g_permissionSlots.insert(0); // even a "reserve" bot must not matter
	AddClient(2, 3500);
	AddClient(3, 3501);
	StartPlugin();
	EnterMap();
	AddClient(4, 3502);
	FireAuth(4, 3502);
	Advance(std::chrono::seconds(1));
	CheckEqInt(KickCount(), 1, "a bot does not fill a public slot");
	Check(Kicked(4), "the joining human is kicked as the third non-reserve human");
	Check(!Kicked(0) && !Kicked(1), "bots are never kicked");
	FinishTest();
}

// --- teardown and reload -------------------------------------------------------------

void TestTeardownAndReload() {
	std::printf("-- teardown, stale callbacks and reload\n");

	PrepareTest();
	WriteFile(AdminConfigPath(), R"("ReservedSlots" { "public_slots" "2" })");
	AddClient(0, 3600);
	StartPlugin();
	EnterMap();
	Check(g_pAdminApi != nullptr, "the admin API is set after start");

	g_asReservedSlotsPlugin.OnPluginEnd();
	CheckEqInt(g_mapStartUnregisters, 1, "map start unregistered once");
	CheckEqInt(g_mapEndUnregisters, 1, "map end unregistered once");
	CheckEqInt(g_authUnregisters, 1, "OnClientAuthenticated unregistered once");
	CheckEqInt(g_connectUnregisters, 1, "OnClientConnected unregistered once");
	CheckEqInt(g_disconnectUnregisters, 1, "OnClientDisconnect unregistered once");
	CheckEqInt(g_unhookCalls, 1, "player_disconnect unhooked once");
	Check(!HasEventHook("player_disconnect", s2sdk::HookMode::Pre), "the event hook is gone");
	Check(!g_mapReady, "OnPluginEnd closes the gate");
	Check(g_pAdminApi == nullptr, "OnPluginEnd drops the admin API");
	Check(!g_mapListeners && !g_authListener && !g_connectListener && !g_disconnectListener &&
				  !g_disconnectEventHooked,
		  "all registration flags are cleared");

	// Stale callbacks after unload do nothing.
	const int connectedBefore = g_connectedCalls;
	const int permissionBefore = PermissionCheckCount();
	FireAuth(0, 3600);
	FireConnect(0);
	FireDisconnect(0);
	FirePlayerDisconnectEvent(0);
	Advance(std::chrono::seconds(1));
	CheckEqInt(g_connectedCalls, connectedBefore, "stale callbacks make no client query");
	CheckEqInt(PermissionCheckCount(), permissionBefore, "stale callbacks check no permissions");
	CheckEqInt(KickCount(), 0, "stale callbacks never kick");

	// Reload re-registers everything exactly once and works again.
	StartPlugin();
	CheckEqInt(g_mapStartRegisters, 2, "reload registers OnMapStart again");
	CheckEqInt(g_authRegisters, 2, "reload registers OnClientAuthenticated again");
	CheckEqInt(g_hookCalls, 2, "reload hooks player_disconnect again");
	EnterMap();
	Check(g_mapReady, "the reloaded plugin opens the gate");
	FinishTest();
}

void TestMissingUnregisterBindings() {
	std::printf("-- a register without an unregister binding is skipped\n");

	PrepareTest();
	__s2sdk_OnClientAuthenticated_Unregister = nullptr;
	StartPlugin();
	CheckEqInt(g_authRegisters, 0, "OnClientAuthenticated is not registered without an unregister");
	Check(!g_authListener, "the auth flag stays false");
	Check(Logged(plg::Severity::Error, "OnClientAuthenticated binding is unavailable"),
		  "the missing auth pair is logged");
	CheckEqInt(g_authUnregisters, 0, "nothing is unregistered");
	FinishTest();

	PrepareTest();
	__s2sdk_OnMapEnd_Unregister = nullptr;
	StartPlugin();
	CheckEqInt(g_mapStartRegisters, 0, "the map listeners are not registered without both unregisters");
	Check(!g_mapListeners, "the map listener flag stays false");
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	Check(!g_mapReady, "the gate can never open without the map listeners");
	FinishTest();

	// No unregister for the connect/disconnect pair: they are skipped too.
	PrepareTest();
	__s2sdk_OnClientConnected_Unregister = nullptr;
	__s2sdk_OnClientDisconnect_Unregister = nullptr;
	StartPlugin();
	CheckEqInt(g_connectRegisters, 0, "OnClientConnected is skipped without an unregister");
	CheckEqInt(g_disconnectRegisters, 0, "OnClientDisconnect is skipped without an unregister");
	Check(!g_connectListener && !g_disconnectListener, "the lifecycle flags stay false");
	FinishTest();

	// HookEvent without UnhookEvent: not hooked.
	PrepareTest();
	__s2sdk_UnhookEvent = nullptr;
	StartPlugin();
	CheckEqInt(g_hookCalls, 0, "player_disconnect is not hooked without UnhookEvent");
	Check(!g_disconnectEventHooked, "the event flag stays false");
	FinishTest();

	// A failed HookEvent is logged and leaves no hook.
	PrepareTest();
	g_hookResult = s2sdk::EventHookError::InvalidEvent;
	StartPlugin();
	Check(!g_disconnectEventHooked, "a rejected hook is not recorded");
	Check(Logged(plg::Severity::Error, "could not hook \"player_disconnect\""),
		  "a rejected hook is logged");
	FinishTest();
}

void TestNoBindingsAtAll() {
	std::printf("-- start with every engine binding missing\n");

	PrepareTest();
	__s2sdk_OnMapStart_Register = nullptr;
	__s2sdk_OnMapStart_Unregister = nullptr;
	__s2sdk_OnMapEnd_Register = nullptr;
	__s2sdk_OnMapEnd_Unregister = nullptr;
	__s2sdk_OnClientAuthenticated_Register = nullptr;
	__s2sdk_OnClientAuthenticated_Unregister = nullptr;
	__s2sdk_OnClientConnected_Register = nullptr;
	__s2sdk_OnClientConnected_Unregister = nullptr;
	__s2sdk_OnClientDisconnect_Register = nullptr;
	__s2sdk_OnClientDisconnect_Unregister = nullptr;
	__s2sdk_HookEvent = nullptr;
	__s2sdk_UnhookEvent = nullptr;
	__s2sdk_GetEventPlayerSlot = nullptr;
	__s2sdk_IsClientConnected = nullptr;
	__s2sdk_IsFakeClient = nullptr;
	__s2sdk_IsClientAuthorized = nullptr;
	__s2sdk_GetClientSteamID64 = nullptr;
	__s2sdk_GetMaxClients = nullptr;
	__s2sdk_KickClient = nullptr;
	__admin_system_GetPluginVersion = nullptr;
	__admin_system_IsCoreLoaded = nullptr;
	__admin_system_HasPermission = nullptr;
	__admin_system_HasFlag = nullptr;
	__admin_system_IsClientAdminDataReady = nullptr;

	StartPlugin();
	Check(!g_mapReady, "no map gate without the map listeners");
	Check(!g_mapListeners && !g_authListener && !g_connectListener && !g_disconnectListener &&
				  !g_disconnectEventHooked,
		  "nothing is registered without the bindings");
	CheckEqInt(g_mapStartRegisters, 0, "no map start registration");
	CheckEqInt(g_authRegisters, 0, "no auth registration");
	CheckEqInt(g_hookCalls, 0, "no event hook");
	g_asReservedSlotsPlugin.OnPluginUpdate(std::chrono::milliseconds(16));
	CheckEqInt(g_connectedCalls, 0, "no client query without the bindings");
	CheckEqInt(g_maxClientsCalls, 0, "no max-clients query without the bindings");
	g_asReservedSlotsPlugin.OnPluginEnd();
	CheckEqInt(g_mapStartUnregisters, 0, "nothing to unregister");
	CheckEqInt(g_authUnregisters, 0, "nothing to unregister (auth)");
	FinishTest();
}

void TestPlayerDisconnectEventFallback() {
	std::printf("-- player_disconnect fallback\n");

	PrepareTest();
	StartPlugin();
	EnterMap();
	Check(HasEventHook("player_disconnect", s2sdk::HookMode::Pre), "the Pre hook is installed");

	// A missing GetEventPlayerSlot is fail-soft and does not crash the handler.
	__s2sdk_GetEventPlayerSlot = nullptr;
	Check(FirePlayerDisconnectEvent(0) == s2sdk::ResultType::Continue,
		  "a missing GetEventPlayerSlot still returns Continue");
	Check(Logged(plg::Severity::Error, "GetEventPlayerSlot binding is unavailable"),
		  "the missing event slot binding is logged");
	__s2sdk_GetEventPlayerSlot = &FakeGetEventPlayerSlot;

	// A null event is ignored.
	for (const FakeEventHook& hook : g_eventHooks) {
		if (hook.name == "player_disconnect" && hook.callback != nullptr) {
			Check(hook.callback(plg::string("player_disconnect"), nullptr, false) ==
						  s2sdk::ResultType::Continue,
				  "a null event returns Continue");
		}
	}
	FinishTest();
}

} // namespace

int main() {
	g_baseDir = "/tmp/as_reserved_slots_tests_" + std::to_string(static_cast<long long>(getpid()));
	std::error_code error;
	std::filesystem::remove_all(g_baseDir, error);
	std::filesystem::create_directories(g_baseDir, error);

	std::printf("as_reserved_slots tests (fake s2sdk/admin_system bindings, no engine)\n");

	ResetWorld();
	InstallFakes();

	TestConfigReader();
	TestConfigPaths();
	TestPluginConfigWalk();
	TestStartAndMapGate();
	TestMidMapStart();
	TestMapChangeWindowStart();
	TestNonReserveFull();
	TestReserveFull();
	TestKickReasonAndMissingKick();
	TestSlotsAndMaxClients();
	TestAuthOrderingAndReuse();
	TestBurstNoDuplicateKicks();
	TestSecurityFailSoft();
	TestAdminDataReadiness();
	TestMapChangeCarry();
	TestObservedNewClients();
	TestBots();
	TestTeardownAndReload();
	TestMissingUnregisterBindings();
	TestNoBindingsAtAll();
	TestPlayerDisconnectEventFallback();

	std::filesystem::remove_all(g_baseDir, error);
	std::printf("as_reserved_slots_tests: %d checks, %d failures\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
