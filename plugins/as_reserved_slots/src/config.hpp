// as_reserved_slots — where reserved_slots.ini is read from and what its keys mean.
//
// docs/PLUGIN_STANDARD.md §7: no pisexcompat. The original module read the Pisex file
// "addons/configs/admin_system/reserved_slots.ini" through hl2sdk's KeyValues; the port keeps the
// file format and the original's getter/default/clamp semantics. The file is looked up in this
// order:
//
//   1. "addons/configs/admin_system/reserved_slots.ini" as given (the pisexcompat candidate the
//      original was written for; on a Metamod tree this is the real path);
//   2. <plg::GetConfigsDir()>/admin_system/reserved_slots.ini - the directory every admin module
//      shares and where the package ships the production file;
//   3. <plg::GetConfigsDir()>/as_reserved_slots/reserved_slots.ini - the plugin's own folder
//      (PLUGIN_STANDARD §3), for a standalone/exported repository.
//
// There is no translation/phrase file: the original module had no chat output and no phrases. Its
// only user-visible effect is the engine disconnect reason, so no language lookup (core.cfg ->
// GetServerLanguage -> "en") is involved here.

#pragma once

#include "kv1.hpp"

#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace as_reserved_slots {

// The path the original logged on failure (kept verbatim for log parity).
inline constexpr char kLegacyConfigPath[] = "addons/configs/admin_system/reserved_slots.ini";
inline constexpr std::string_view kAdminSystemDir = "admin_system";
inline constexpr std::string_view kPluginDir = "as_reserved_slots";
inline constexpr std::string_view kConfigFileName = "reserved_slots.ini";

struct Config {
	int publicSlots = 0;
	std::string reserveFlag = "@admin/reserve";
	int kickReasonId = 135; // NETWORK_DISCONNECT_REJECT_SERVERFULL
};

enum class ConfigLoadStatus {
	Loaded,   // the file was read and its keys applied
	Missing,  // no candidate exists
	Malformed // a candidate exists but is not valid KV1
};

struct ConfigLoadOutcome {
	Config config;
	ConfigLoadStatus status = ConfigLoadStatus::Missing;
	std::string path; // the candidate that was read, empty when nothing existed
};

inline std::string JoinPath(std::string_view base, std::string_view name) {
	if (base.empty()) {
		return std::string(name);
	}
	if (name.empty()) {
		return std::string(base);
	}
	std::string out(base);
	if (out.back() != '/') {
		out.push_back('/');
	}
	if (name.front() == '/') {
		name.remove_prefix(1);
	}
	out.append(name);
	return out;
}

inline bool FileExists(const std::string& path) {
	if (path.empty()) {
		return false;
	}
	std::ifstream file(path, std::ios::binary);
	return file.good();
}

// The original's default before the file is read: maxClients - 2, but never below the slot count
// for the smallest servers (maxClients 1/2 -> maxClients).
inline int DefaultPublicSlots(int maxClients) {
	if (maxClients <= 0) {
		return 0;
	}
	return maxClients > 2 ? maxClients - 2 : maxClients;
}

inline Config MakeDefaultConfig(int maxClients) {
	Config config;
	config.publicSlots = DefaultPublicSlots(maxClients);
	return config;
}

// The original's getters, in the same order and with the same defaults. `maxClients` is used only
// for the default public_slots; the clamps happen in FinalizeConfig().
inline void ApplyOverrides(const KvNode& root, Config& config) {
	// Keep the default in its own object: GetString() returns the default view when the key is
	// missing, and the new value is built before it is assigned over config.reserveFlag.
	const std::string defaultReserveFlag = config.reserveFlag;
	config.reserveFlag = std::string(root.GetString("reserve_flag", defaultReserveFlag));
	config.publicSlots = root.GetInt("public_slots", config.publicSlots);
	config.kickReasonId = root.GetInt("kick_reason_id", config.kickReasonId);
}

// The original's post-load validation: public_slots is clamped to [0, maxClients] (only when the
// engine gave a usable maximum - without one the plugin does not enforce at all) and a negative
// kick reason becomes 39 (Kicked), because the engine cannot take a negative reason.
inline void FinalizeConfig(Config& config, int maxClients) {
	if (maxClients > 0) {
		if (config.publicSlots < 0) {
			config.publicSlots = 0;
		}
		if (config.publicSlots > maxClients) {
			config.publicSlots = maxClients;
		}
	}
	if (config.kickReasonId < 0) {
		config.kickReasonId = 39;
	}
}

// Parse `text` and replace `out` with the original's defaults plus its keys. False (and `out`
// untouched) when the text is malformed.
inline bool LoadConfigFromText(std::string_view text, int maxClients, Config& out) {
	const std::optional<KvNode> root = ParseKv1(text);
	if (!root) {
		return false;
	}
	Config config = MakeDefaultConfig(maxClients);
	ApplyOverrides(*root, config);
	FinalizeConfig(config, maxClients);
	out = config;
	return true;
}

inline std::vector<std::string> ConfigCandidates(std::string_view configsDir) {
	std::vector<std::string> candidates;
	candidates.emplace_back(kLegacyConfigPath);
	if (configsDir.empty()) {
		return candidates;
	}
	candidates.push_back(JoinPath(JoinPath(configsDir, kAdminSystemDir), kConfigFileName));
	candidates.push_back(JoinPath(JoinPath(configsDir, kPluginDir), kConfigFileName));
	return candidates;
}

// The first candidate that exists. Empty when none does (the caller then keeps the defaults and
// logs the original's failure line).
inline std::string ResolveConfigPath(std::string_view configsDir) {
	for (const std::string& candidate : ConfigCandidates(configsDir)) {
		if (FileExists(candidate)) {
			return candidate;
		}
	}
	return {};
}

// The complete load: the original's defaults, the first existing file's keys, then its clamps.
// The returned config is always usable (defaults on Missing/Malformed); status/path let the
// caller log the original's one failure line.
inline ConfigLoadOutcome LoadConfig(std::string_view configsDir, int maxClients) {
	ConfigLoadOutcome outcome;
	outcome.config = MakeDefaultConfig(maxClients);
	outcome.path = ResolveConfigPath(configsDir);
	if (outcome.path.empty()) {
		outcome.status = ConfigLoadStatus::Missing;
		FinalizeConfig(outcome.config, maxClients);
		return outcome;
	}

	const std::optional<KvNode> root = LoadKv1File(outcome.path);
	if (!root) {
		outcome.status = ConfigLoadStatus::Malformed;
		FinalizeConfig(outcome.config, maxClients);
		return outcome;
	}

	ApplyOverrides(*root, outcome.config);
	FinalizeConfig(outcome.config, maxClients);
	outcome.status = ConfigLoadStatus::Loaded;
	return outcome;
}

} // namespace as_reserved_slots
