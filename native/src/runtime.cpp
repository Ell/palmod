#include "palmod/runtime.hpp"

#include "palmod/json.hpp"
#include "palmod/json_log.hpp"
#include "palmod/sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <pthread.h>
#include <sstream>
#include <shared_mutex>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

namespace palmod {
namespace {

constexpr std::size_t kMaxProfileBytes = 4U * 1024U * 1024U;

std::string lower(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return text;
}

bool fixed_equal(std::string_view left, std::string_view right) {
  if (left.size() != right.size()) return false;
  unsigned difference = 0;
  for (std::size_t i = 0; i < left.size(); ++i) {
    difference |= static_cast<unsigned>(static_cast<unsigned char>(left[i]) ^
                                        static_cast<unsigned char>(right[i]));
  }
  return difference == 0;
}

std::optional<std::string> read_sealed_profile(int inherited_fd,
                                               std::string& error) {
  if (inherited_fd < 3) {
    error = "PALMOD_PROFILE_FD must name an inherited descriptor >= 3";
    return std::nullopt;
  }
  const int descriptor_flags = fcntl(inherited_fd, F_GETFD);
  if (descriptor_flags < 0) {
    error = "PALMOD_PROFILE_FD is not open: " + std::string(std::strerror(errno));
    return std::nullopt;
  }
  if ((descriptor_flags & FD_CLOEXEC) != 0) {
    error = "PALMOD_PROFILE_FD must be inherited without FD_CLOEXEC";
    return std::nullopt;
  }
  const int seals = fcntl(inherited_fd, F_GET_SEALS);
  constexpr int kRequiredSeals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
  if (seals < 0 || (seals & kRequiredSeals) != kRequiredSeals) {
    error = "PALMOD_PROFILE_FD must be a fully sealed memfd";
    return std::nullopt;
  }
  struct stat status{};
  if (fstat(inherited_fd, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_size <= 0 || static_cast<std::uint64_t>(status.st_size) > kMaxProfileBytes) {
    error = "sealed profile size must be between 1 byte and 4 MiB";
    return std::nullopt;
  }
  const int fd = fcntl(inherited_fd, F_DUPFD_CLOEXEC, 3);
  if (fd < 0) {
    error = "cannot duplicate profile memfd: " + std::string(std::strerror(errno));
    return std::nullopt;
  }
  std::string contents(static_cast<std::size_t>(status.st_size), '\0');
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const ssize_t count = pread(fd, contents.data() + offset, contents.size() - offset,
                                static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      error = "cannot read complete profile memfd";
      close(fd);
      return std::nullopt;
    }
    offset += static_cast<std::size_t>(count);
  }
  close(fd);
  return contents;
}

std::string sha256_text(std::string_view text) {
  Sha256 hash;
  hash.update(std::as_bytes(std::span(text.data(), text.size())));
  return hex(hash.finish());
}

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

struct ExpectedByte {
  std::byte value{};
  bool wildcard{false};
};

std::optional<std::vector<ExpectedByte>> parse_expected_bytes(
    std::string_view pattern, std::string& error) {
  std::vector<ExpectedByte> result;
  std::size_t cursor = 0;
  while (cursor < pattern.size()) {
    while (cursor < pattern.size() && std::isspace(static_cast<unsigned char>(pattern[cursor]))) ++cursor;
    if (cursor == pattern.size()) break;
    if (pattern[cursor] == '?') {
      ++cursor;
      if (cursor < pattern.size() && pattern[cursor] == '?') ++cursor;
      result.push_back({std::byte{0}, true});
    } else {
      if (cursor + 1 >= pattern.size()) {
        error = "anchor byte pattern has an incomplete hex byte";
        return std::nullopt;
      }
      const int high = hex_digit(pattern[cursor]);
      const int low_digit = hex_digit(pattern[cursor + 1]);
      if (high < 0 || low_digit < 0) {
        error = "anchor byte pattern contains non-hex text";
        return std::nullopt;
      }
      result.push_back({static_cast<std::byte>((high << 4) | low_digit), false});
      cursor += 2;
    }
    if (result.size() > 512) {
      error = "anchor byte pattern exceeds 512 bytes";
      return std::nullopt;
    }
  }
  if (result.empty()) {
    error = "anchor byte pattern is empty";
    return std::nullopt;
  }
  return result;
}

bool verify_anchors(const BuildProfile& profile, std::string& error) {
  for (const auto& [name, anchor] : profile.hooks) {
    auto expected = parse_expected_bytes(anchor.expected_bytes, error);
    if (!expected) {
      error = "anchor '" + name + "': " + error;
      return false;
    }
    if (anchor.rva > std::numeric_limits<std::uint64_t>::max() - profile.image_base) {
      error = "anchor '" + name + "' address overflows";
      return false;
    }
    const std::uint64_t address = profile.image_base + anchor.rva;
    std::vector<std::byte> actual(expected->size());
    iovec local{actual.data(), actual.size()};
    iovec remote{reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)), actual.size()};
    const ssize_t read = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (read != static_cast<ssize_t>(actual.size())) {
      error = "cannot read anchor '" + name + "' from the live image";
      return false;
    }
    for (std::size_t i = 0; i < actual.size(); ++i) {
      if (!(*expected)[i].wildcard && (*expected)[i].value != actual[i]) {
        error = "live bytes do not match anchor '" + name + "'";
        return false;
      }
    }
  }
  return true;
}

std::string request_id_json(const json::Value& id) {
  if (id.string()) return json::stringify(id);
  if (id.integer()) return json::stringify(id);
  return "null";
}

std::string response_error(std::string_view id, std::string_view code,
                           std::string_view message) {
  return "{\"id\":" + std::string(id) +
         ",\"ok\":false,\"error\":{\"code\":\"" + json::escape(code) +
         "\",\"message\":\"" + json::escape(message) + "\"}}";
}

std::optional<std::string> control_command_line(const json::Object& params,
                                                std::string& error) {
  const auto* command = json::get(params, "command");
  const auto* args = json::get(params, "args");
  if (!command || !command->string() || command->string()->empty() ||
      !args || !args->array()) {
    error = "command.invoke requires string command and string-array args";
    return std::nullopt;
  }
  if (command->string()->size() > 32 || args->array()->size() > 32) {
    error = "control command exceeds command limits";
    return std::nullopt;
  }
  std::string line = "/" + *command->string();
  for (const auto& value : *args->array()) {
    if (!value.string() || value.string()->size() > 512) {
      error = "command.invoke args must be strings of at most 512 bytes";
      return std::nullopt;
    }
    line += " \"";
    for (const char c : *value.string()) {
      if (c == '\0' || (static_cast<unsigned char>(c) < 0x20U && c != '\t')) {
        error = "command.invoke argument contains a control byte";
        return std::nullopt;
      }
      if (c == '\\' || c == '"') line += '\\';
      line += c;
    }
    line += '"';
  }
  if (line.size() > 2048) {
    error = "encoded command exceeds 2048 bytes";
    return std::nullopt;
  }
  return line;
}

void* bootstrap_thread(void*) {
  std::string error;
  Runtime::process().start(Runtime::config_from_environment(), error);
  if (!error.empty()) {
    JsonLog::instance().write(JsonLog::Level::Error, "bootstrap.failed", error);
  }
  return nullptr;
}

}  // namespace

struct Runtime::PluginSet {
  explicit PluginSet(ActionQueue& actions) : plugins(actions) {}
  CommandRouter commands;
  PluginRuntime plugins;
};

Runtime::Runtime(std::unique_ptr<HookBackend> backend)
    : plugin_set_(std::make_unique<PluginSet>(actions_)),
      hooks_(std::move(backend)) {}

Runtime::~Runtime() { stop(); }

bool Runtime::start(const RuntimeConfig& config, std::string& error) {
  RuntimeState expected = RuntimeState::Cold;
  if (!state_.compare_exchange_strong(expected, RuntimeState::Starting)) {
    error = "runtime can only be started once";
    return false;
  }
  const auto fail = [&](RuntimeState state, std::string message) {
    {
      std::scoped_lock lock(mu_);
      last_error_ = message;
    }
    state_.store(state);
    error = std::move(message);
    return false;
  };
  if (std::getenv("PALMOD_PROFILE") != nullptr) {
    return fail(RuntimeState::Failed, "PALMOD_PROFILE path bypass is forbidden; use a sealed PALMOD_PROFILE_FD");
  }
  if (!config.plugin_directory.is_absolute() ||
      (config.enable_control && !config.control_socket.is_absolute())) {
    return fail(RuntimeState::Failed, "plugin directory and control socket must be absolute paths");
  }
  if (config.expected_profile_sha256.size() != 64) {
    return fail(RuntimeState::Failed, "PALMOD_PROFILE_SHA256 must be a 64-character digest");
  }

  std::string profile_error;
  auto profile_json = read_sealed_profile(config.profile_fd, profile_error);
  if (!profile_json) return fail(RuntimeState::Failed, std::move(profile_error));
  const std::string actual_profile_sha = sha256_text(*profile_json);
  if (!fixed_equal(actual_profile_sha, lower(config.expected_profile_sha256))) {
    return fail(RuntimeState::Failed, "sealed profile SHA-256 does not match PALMOD_PROFILE_SHA256");
  }
  auto profile = BuildProfile::parse_json(*profile_json, profile_error);
  if (!profile) return fail(RuntimeState::Failed, std::move(profile_error));

  auto fingerprint = fingerprint_self();
  if (!fingerprint.fingerprint) {
    return fail(RuntimeState::Failed, std::move(fingerprint.error));
  }
  std::string mismatch;
  if (!profile->exactly_matches(*fingerprint.fingerprint, mismatch)) {
    return fail(RuntimeState::UnsupportedBuild, std::move(mismatch));
  }
  if (!verify_anchors(*profile, mismatch)) {
    return fail(RuntimeState::UnsupportedBuild, std::move(mismatch));
  }
  {
    std::scoped_lock lock(mu_);
    fingerprint_ = *fingerprint.fingerprint;
    profile_ = *profile;
  }

  // Start the control server only after the profile is validated — otherwise a
  // subprocess that also inherited LD_PRELOAD (e.g. the crash reporter, which has
  // no profile FD) would bind the control socket before failing, hijacking it
  // from the real server.
  if (config.enable_control) {
    std::string control_error;
    if (!control_.start(config.control_socket,
                        [this](std::string_view packet, uid_t uid) {
                          return control_request(packet, uid);
                        },
                        control_error)) {
      return fail(RuntimeState::Failed, std::move(control_error));
    }
  }

  plugin_directory_ = config.plugin_directory;
  std::string plugin_error;
  if (!reload_plugins(plugin_error)) {
    return fail(RuntimeState::Failed, "plugin transaction failed: " + plugin_error);
  }
  HookCallbacks callbacks;
  callbacks.on_chat = [this](std::string_view text, std::string player,
                             std::uint64_t handle, int auth) {
    AuthState state = AuthState::Unknown;
    if (auth == 1) state = AuthState::Player;
    else if (auth == 2) state = AuthState::Admin;
    return on_chat(text, std::move(player), handle, state);
  };
  callbacks.on_game_tick = [this] {
    on_game_tick([this](const SemanticAction& action) {
      execute_action_on_game_thread(action);
    });
  };
  callbacks.on_player_join = [this](std::string stable_id, std::string display_name,
                                    std::uint64_t handle) {
    std::string join_error;
    if (!players_.upsert(std::move(stable_id), std::move(display_name), handle, join_error)) {
      JsonLog::instance().write(JsonLog::Level::Warn, "player.join_rejected", join_error);
    }
  };
  callbacks.on_player_leave = [this](std::string stable_id) {
    players_.remove(stable_id);
  };
  callbacks.on_event = [this](const PluginEvent& event) {
    deliver_event(event);
  };
  std::string hook_error;
  if (!hooks_->install(*profile, std::move(callbacks), hook_error)) {
    std::shared_lock lock(plugins_mu_);
    plugin_set_->plugins.stop();
    return fail(RuntimeState::Failed, "hook backend '" + std::string(hooks_->name()) +
                                      "' failed: " + hook_error);
  }
  install_generic_hooks(*profile);
  state_.store(RuntimeState::Running);
  start_plugin_watch();
  JsonLog::instance().write(JsonLog::Level::Info, "runtime.started",
                            "profile gate passed and runtime started",
                            {{"profile", profile->profile_id}, {"hook_backend", hooks_->name()}});
  return true;
}

void Runtime::stop() {
  const auto old = state_.exchange(RuntimeState::Stopped);
  if (old == RuntimeState::Cold || old == RuntimeState::Stopped) return;
  {
    std::scoped_lock lock(plugin_watch_mu_);
    plugin_watch_stop_ = true;
  }
  plugin_watch_cv_.notify_all();
  if (plugin_watch_thread_.joinable()) plugin_watch_thread_.join();
  if (hooks_) hooks_->uninstall();
  {
    std::shared_lock lock(plugins_mu_);
    plugin_set_->plugins.stop();
  }
  control_.stop();
}

bool Runtime::on_chat(std::string_view text, std::string player,
                      std::uint64_t player_handle, AuthState auth) {
  if (state_.load() != RuntimeState::Running) return false;
  std::shared_lock lock(plugins_mu_);
  auto result = plugin_set_->commands.route(
      text, std::move(player), player_handle, auth,
      [this](CommandInvocation invocation) {
        return plugin_set_->plugins.dispatch(std::move(invocation));
      });
  if (result.matched && !result.dispatched && !result.error.empty()) {
    JsonLog::instance().write(JsonLog::Level::Warn, "command.rejected", result.error);
  }
  return result.matched && result.suppress;
}

void Runtime::on_game_tick(
    const std::function<void(const SemanticAction&)>& executor) {
  actions_.drain(executor);
}

void Runtime::execute_action_on_game_thread(const SemanticAction& action) {
  std::string execute_error;
  if (!hooks_->execute_action(action, execute_error)) {
    JsonLog::instance().write(JsonLog::Level::Error, "action.execute_failed",
                              execute_error, {{"plugin", action.source_plugin}});
  }
}

void Runtime::install_generic_hooks(const BuildProfile& profile) {
  std::set<std::string, std::less<>> kinds;
  {
    std::shared_lock lock(plugins_mu_);
    kinds = plugin_set_->plugins.subscribed_event_kinds();
  }
  for (const auto& kind : kinds) {
    if (kind == "chat") continue;  // delivered by the dedicated chat hook
    // The backend resolves the UFunction live by name (GUObjectArray) and reads
    // its parameter layout live — no baked function catalog. A subscribed kind
    // that is not a game function simply fails to resolve and is logged.
    GenericHookSpec spec;
    spec.name = kind;
    spec.fframe_locals_offset = profile.reflection_fframe_locals_offset;
    std::string generic_error;
    if (!hooks_->install_generic_hook(spec, generic_error)) {
      JsonLog::instance().write(JsonLog::Level::Warn, "hook.generic_unavailable",
                                generic_error, {{"function", kind}});
    }
  }
}

std::size_t Runtime::deliver_event(const PluginEvent& event) {
  if (state_.load() != RuntimeState::Running) return 0;
  std::shared_lock lock(plugins_mu_);
  return plugin_set_->plugins.deliver_event(event);
}

bool Runtime::wait_plugins_idle(std::chrono::milliseconds timeout) {
  std::shared_lock lock(plugins_mu_);
  return plugin_set_->plugins.wait_idle(timeout);
}

bool Runtime::reload_plugins(std::string& error) {
  auto fresh = std::make_unique<PluginSet>(actions_);
  // Give plugins read-side reflection (pal.find_object/find_all_of/get) from the
  // same object-array facts the generic call path uses.
  if (profile_ && profile_->reflection_guobjectarray_objects_va != 0 &&
      profile_->reflection_fname_pool_blocks_va != 0) {
    ObjectArrayLayout layout;
    layout.objects_va = profile_->reflection_guobjectarray_objects_va;
    layout.super_offset = profile_->reflection_super_struct_offset;
    fresh->plugins.set_reflection_reader(
        ReflectionReader{layout, FNamePool{profile_->reflection_fname_pool_blocks_va}});
  }
  const auto report = fresh->plugins.load_directory_report(plugin_directory_, fresh->commands);
  if (!report.ok()) {
    std::ostringstream summary;
    summary << "loaded " << report.loaded << '/' << report.discovered;
    for (const auto& failure : report.errors) summary << "; " << failure;
    error = summary.str();
    return false;
  }
  std::unique_ptr<PluginSet> old;
  {
    std::unique_lock lock(plugins_mu_);
    old = std::move(plugin_set_);
    plugin_set_ = std::move(fresh);
  }
  // Destruction waits for already accepted callbacks after the atomic set swap.
  old.reset();
  JsonLog::instance().write(JsonLog::Level::Info, "plugins.reloaded",
                            "plugin transaction committed",
                            {{"loaded", std::to_string(report.loaded)}});
  return true;
}

void Runtime::start_plugin_watch() {
  namespace fs = std::filesystem;
  plugin_watch_thread_ = std::thread([this] {
    // Newest regular-file mtime under the plugin directory. Start from ::min()
    // rather than a default-constructed value: libstdc++'s file_clock epoch is
    // in the future, so real mtimes have negative counts and would compare below
    // a zero-count default, hiding every change.
    const auto newest_mtime = [this]() {
      fs::file_time_type newest = fs::file_time_type::min();
      std::error_code ec;
      for (fs::recursive_directory_iterator it(plugin_directory_, ec), end;
           !ec && it != end; it.increment(ec)) {
        std::error_code entry_ec;
        if (it->is_regular_file(entry_ec) && !entry_ec) {
          // Fresh stat (not the directory_entry's cached value, which is stale
          // relative to a modification after enumeration).
          const auto when = fs::last_write_time(it->path(), entry_ec);
          if (!entry_ec && when > newest) newest = when;
        }
      }
      return newest;
    };
    auto last = newest_mtime();
    for (;;) {
      std::unique_lock lock(plugin_watch_mu_);
      plugin_watch_cv_.wait_for(lock, std::chrono::seconds(1),
                                [this] { return plugin_watch_stop_; });
      if (plugin_watch_stop_) return;
      lock.unlock();
      const auto now = newest_mtime();
      if (now <= last) continue;
      last = now;
      std::string reload_error;
      if (reload_plugins(reload_error)) {
        JsonLog::instance().write(JsonLog::Level::Info, "plugins.hot_reloaded",
                                  "plugin change detected; reloaded");
      } else {
        // Transactional: on failure the previously loaded plugins keep running.
        JsonLog::instance().write(JsonLog::Level::Warn, "plugins.hot_reload_failed",
                                  reload_error);
      }
    }
  });
}

std::string Runtime::state_name(RuntimeState state) {
  switch (state) {
    case RuntimeState::Cold: return "cold";
    case RuntimeState::Starting: return "starting";
    case RuntimeState::UnsupportedBuild: return "unsupported_build";
    case RuntimeState::Running: return "running";
    case RuntimeState::Failed: return "failed";
    case RuntimeState::Stopped: return "stopped";
  }
  return "unknown";
}

std::string Runtime::status_json() const {
  json::Object result;
  result.emplace("state", state_name(state_.load()));
  result.emplace("lua_available", PluginRuntime::lua_available());
  result.emplace("hook_backend", hooks_ ? std::string(hooks_->name()) : "none");
  result.emplace("action_queue_size", static_cast<std::int64_t>(actions_.size()));
  result.emplace("action_queue_dropped", static_cast<std::int64_t>(actions_.dropped()));
  {
    std::scoped_lock lock(mu_);
    result.emplace("error", last_error_);
    result.emplace("profile_id", profile_ ? profile_->profile_id : "");
    result.emplace("executable_sha256", fingerprint_ ? fingerprint_->sha256 : "");
    result.emplace("elf_build_id", fingerprint_ ? fingerprint_->elf_build_id : "");
  }
  json::Array plugin_values;
  std::shared_lock plugins_lock(plugins_mu_);
  for (const auto& status : plugin_set_->plugins.statuses()) {
    json::Object object;
    object.emplace("id", status.id);
    object.emplace("version", status.version);
    object.emplace("running", status.running);
    object.emplace("error", status.error);
    object.emplace("queued", static_cast<std::int64_t>(status.queued));
    plugin_values.emplace_back(std::move(object));
  }
  result.emplace("plugins", std::move(plugin_values));
  return json::stringify(json::Value{std::move(result)});
}

std::string Runtime::control_request(std::string_view packet, uid_t peer_uid) {
  auto parsed = json::parse(packet);
  if (!parsed.value || !parsed.value->object()) {
    return response_error("null", "invalid_request",
                          parsed.value ? "request must be a JSON object" : parsed.error);
  }
  const auto& root = *parsed.value->object();
  const auto* id = json::get(root, "id");
  const auto* method = json::get(root, "method");
  const auto* params = json::get(root, "params");
  if (!id || !id->integer() || *id->integer() < 0 || !method || !method->string() ||
      !params || !params->object()) {
    return response_error(id ? request_id_json(*id) : "null", "invalid_request",
                          "expected {id:<nonnegative integer>,method,params:{}}");
  }
  if (const auto* version = json::get(root, "version");
      version && (!version->integer() || *version->integer() != 1)) {
    return response_error(request_id_json(*id), "invalid_request", "optional version must be 1");
  }
  const std::string id_json = request_id_json(*id);
  if (*method->string() == "ping") {
    return "{\"id\":" + id_json + ",\"ok\":true,\"result\":{\"pong\":true}}";
  }
  if (*method->string() == "status" || *method->string() == "plugins.list") {
    return "{\"id\":" + id_json + ",\"ok\":true,\"result\":" + status_json() + "}";
  }
  if (*method->string() == "plugins.reload") {
    if (state_.load() != RuntimeState::Running) {
      return response_error(id_json, "not_running", "plugins can only be reloaded while running");
    }
    if (const auto* plugin = json::get(*params->object(), "plugin");
        plugin && (!plugin->string() || !plugin->string()->empty())) {
      return response_error(id_json, "unsupported",
                            "single-plugin reload is not transactional yet; omit params.plugin to reload all");
    }
    std::string reload_error;
    const bool reloaded = reload_plugins(reload_error);
    JsonLog::instance().write(reloaded ? JsonLog::Level::Info : JsonLog::Level::Error,
                              "control.plugins_reload", reloaded ? "committed" : reload_error,
                              {{"peer_uid", std::to_string(peer_uid)}});
    if (!reloaded) return response_error(id_json, "reload_failed", reload_error);
    return "{\"id\":" + id_json + ",\"ok\":true,\"result\":{\"reloaded\":true}}";
  }
  if (*method->string() == "command.invoke") {
    if (state_.load() != RuntimeState::Running) {
      return response_error(id_json, "not_running", "commands can only be invoked while running");
    }
    std::string command_error;
    auto line = control_command_line(*params->object(), command_error);
    if (!line) return response_error(id_json, "invalid_params", command_error);
    RouteResult routed;
    {
      std::shared_lock lock(plugins_mu_);
      routed = plugin_set_->commands.route(
          *line, {}, 0, AuthState::Admin,
          [this, peer_uid](CommandInvocation invocation) {
            invocation.principal = PrincipalKind::LocalOperator;
            invocation.operator_uid = static_cast<std::uint32_t>(peer_uid);
            invocation.player.clear();
            invocation.player_handle = 0;
            return plugin_set_->plugins.dispatch(std::move(invocation));
          });
    }
    JsonLog::instance().write(routed.dispatched ? JsonLog::Level::Info : JsonLog::Level::Warn,
                              "control.command_invoke",
                              routed.dispatched ? "queued" : routed.error,
                              {{"peer_uid", std::to_string(peer_uid)},
                               {"command", *line}});
    if (!routed.matched) return response_error(id_json, "unknown_command", "command is not registered");
    if (!routed.dispatched) return response_error(id_json, "command_rejected", routed.error);
    return "{\"id\":" + id_json + ",\"ok\":true,\"result\":{\"queued\":true," 
           "\"principal\":\"local_operator\"}}";
  }
  return response_error(id_json, "method_not_found", "unknown read-only control method");
}

Runtime& Runtime::process() {
  static Runtime runtime;
  return runtime;
}

RuntimeConfig Runtime::config_from_environment() {
  RuntimeConfig config;
  if (const char* fd = std::getenv(kEnvProfileFd)) {
    int parsed = -1;
    const std::string_view token(fd);
    const auto converted = std::from_chars(token.data(), token.data() + token.size(), parsed);
    if (converted.ec == std::errc{} && converted.ptr == token.data() + token.size()) {
      config.profile_fd = parsed;
    }
  }
  if (const char* digest = std::getenv(kEnvProfileSha256)) config.expected_profile_sha256 = digest;
  if (const char* plugins = std::getenv(kEnvPluginDirectory)) config.plugin_directory = plugins;
  if (const char* socket = std::getenv(kEnvControlSocket)) config.control_socket = socket;
  return config;
}

void start_process_runtime_async() {
  static std::atomic<bool> started{false};
  if (started.exchange(true)) return;
  pthread_t thread{};
  if (pthread_create(&thread, nullptr, bootstrap_thread, nullptr) == 0) {
    pthread_detach(thread);
  }
}

}  // namespace palmod
