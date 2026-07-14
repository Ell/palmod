#pragma once

#include "palmod/action_queue.hpp"
#include "palmod/command_router.hpp"
#include "palmod/reflection_reader.hpp"
#include "palmod/types.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace palmod {

struct PluginManifest {
  std::uint32_t schema_version{0};
  std::string id;
  std::string version;
  std::filesystem::path directory;
  std::filesystem::path entrypoint;
  std::size_t memory_limit_bytes{32U * 1024U * 1024U};
  std::size_t instruction_limit{250000};
  std::vector<CommandSpec> commands;

  static std::optional<PluginManifest> load(const std::filesystem::path& path,
                                            std::string& error);
};

struct PluginStatus {
  std::string id;
  std::string version;
  bool running{false};
  std::string error;
  std::size_t queued{0};
};

struct PluginLoadReport {
  std::size_t discovered{0};
  std::size_t loaded{0};
  std::vector<std::string> errors;
  bool ok() const { return errors.empty() && discovered == loaded; }
};

class PluginRuntime {
 public:
  explicit PluginRuntime(ActionQueue& actions);
  ~PluginRuntime();

  PluginRuntime(const PluginRuntime&) = delete;
  PluginRuntime& operator=(const PluginRuntime&) = delete;

  std::size_t load_directory(const std::filesystem::path& root,
                             CommandRouter& router);
  PluginLoadReport load_directory_report(const std::filesystem::path& root,
                                         CommandRouter& router);
  bool dispatch(CommandInvocation invocation);
  // Fan out an event to every subscribed plugin. Returns how many accepted it.
  std::size_t deliver_event(const PluginEvent& event);
  // The union of every loaded plugin's event subscriptions (canonical, lowercase
  // keys). The runtime uses this to decide which generic game hooks to install.
  std::set<std::string, std::less<>> subscribed_event_kinds() const;
  std::vector<PluginStatus> statuses() const;
  bool wait_idle(std::chrono::milliseconds timeout);
  void stop();
  // Give plugins read-side reflection (`pal.find_object`/`find_all_of`/`get`).
  // Set before loading plugins; absent = those APIs return nil.
  void set_reflection_reader(ReflectionReader reader);
  static constexpr bool lua_available() {
#if PALMOD_HAS_LUA
    return true;
#else
    return false;
#endif
  }

 private:
  class Instance;
  ActionQueue& actions_;
  ReflectionReader reader_;
  mutable std::mutex mu_;
  std::map<std::string, std::unique_ptr<Instance>, std::less<>> plugins_;
};

}  // namespace palmod
