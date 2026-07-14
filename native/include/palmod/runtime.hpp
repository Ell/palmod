#pragma once

#include "palmod/action_queue.hpp"
#include "palmod/build_profile.hpp"
#include "palmod/command_router.hpp"
#include "palmod/control_server.hpp"
#include "palmod/hook_backend.hpp"
#include "palmod/player_directory.hpp"
#include "palmod/plugin_runtime.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>

namespace palmod {

struct RuntimeConfig {
  int profile_fd{-1};
  std::string expected_profile_sha256;
  std::filesystem::path plugin_directory;
  std::filesystem::path control_socket;
  bool enable_control{true};
};

inline constexpr char kEnvProfileFd[] = "PALMOD_PROFILE_FD";
inline constexpr char kEnvProfileSha256[] = "PALMOD_PROFILE_SHA256";
inline constexpr char kEnvPluginDirectory[] = "PALMOD_PLUGIN_DIR";
inline constexpr char kEnvControlSocket[] = "PALMOD_CONTROL_SOCKET";

enum class RuntimeState { Cold, Starting, UnsupportedBuild, Running, Failed, Stopped };

class Runtime {
 public:
  explicit Runtime(std::unique_ptr<HookBackend> backend =
                       make_default_hook_backend());
  ~Runtime();
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  bool start(const RuntimeConfig& config, std::string& error);
  void stop();
  bool on_chat(std::string_view text, std::string player,
               std::uint64_t player_handle, AuthState auth);
  void on_game_tick(const std::function<void(const SemanticAction&)>& executor);
  // Fan an event out to subscribed plugins (async). Game hooks decode their
  // payload into a PluginEvent and call this; returns how many plugins accepted.
  std::size_t deliver_event(const PluginEvent& event);
  bool wait_plugins_idle(std::chrono::milliseconds timeout);
  RuntimeState state() const { return state_.load(); }
  std::string status_json() const;
  ActionQueue& actions() { return actions_; }
  PlayerDirectory& players() { return players_; }

  static Runtime& process();
  static RuntimeConfig config_from_environment();

 private:
  struct PluginSet;
  bool reload_plugins(std::string& error);
  void install_generic_hooks(const BuildProfile& profile);
  void execute_action_on_game_thread(const SemanticAction& action);
  std::string control_request(std::string_view packet, uid_t peer_uid);
  // Background thread: polls the plugin directory's file mtimes and reloads on
  // change, so editing a plugin applies without restarting the server.
  void start_plugin_watch();
  static std::string state_name(RuntimeState state);

  mutable std::mutex mu_;
  std::atomic<RuntimeState> state_{RuntimeState::Cold};
  std::string last_error_;
  std::optional<BuildFingerprint> fingerprint_;
  std::optional<BuildProfile> profile_;
  ActionQueue actions_;
  PlayerDirectory players_;
  mutable std::shared_mutex plugins_mu_;
  std::unique_ptr<PluginSet> plugin_set_;
  std::filesystem::path plugin_directory_;
  std::unique_ptr<HookBackend> hooks_;
  ControlServer control_;
  std::thread plugin_watch_thread_;
  std::condition_variable plugin_watch_cv_;
  std::mutex plugin_watch_mu_;
  bool plugin_watch_stop_{false};
};

void start_process_runtime_async();

}  // namespace palmod
