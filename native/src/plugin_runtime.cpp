#include "palmod/plugin_runtime.hpp"

#include "palmod/json.hpp"
#include "palmod/json_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <utility>

#if PALMOD_HAS_LUA
#include <lua.hpp>

#include "palmod/generated/plugin_stdlib_lua.hpp"
#endif

namespace palmod {
namespace {

constexpr std::size_t kMaxManifestBytes = 256U * 1024U;
constexpr std::size_t kMaxCommandQueue = 256;

std::optional<std::string> require_string(const json::Object& object,
                                          std::string_view key,
                                          std::string& error) {
  const auto* value = json::get(object, key);
  if (!value || !value->string() || value->string()->empty()) {
    error = "manifest field '" + std::string(key) + "' must be a non-empty string";
    return std::nullopt;
  }
  return *value->string();
}

std::optional<std::size_t> optional_limit(const json::Object& root,
                                          std::string_view key,
                                          std::size_t fallback,
                                          std::size_t minimum,
                                          std::size_t maximum,
                                          std::string& error) {
  const auto* value = json::get(root, key);
  if (!value) return fallback;
  const auto* integer = value->integer();
  if (!integer || *integer < 0 || static_cast<std::uint64_t>(*integer) < minimum ||
      static_cast<std::uint64_t>(*integer) > maximum) {
    error = "manifest field '" + std::string(key) + "' is outside the allowed range";
    return std::nullopt;
  }
  return static_cast<std::size_t>(*integer);
}

bool valid_id(std::string_view id) {
  if (id.size() < 2 || id.size() > 64 || id.front() < 'a' || id.front() > 'z') return false;
  return std::all_of(id.begin(), id.end(), [](unsigned char c) {
    return std::islower(c) != 0 || std::isdigit(c) != 0 || c == '_' || c == '.' || c == '-';
  });
}

bool safe_entrypoint(std::string_view entrypoint) {
  if (entrypoint.empty() || entrypoint.size() > 128 || entrypoint == "." || entrypoint == "..") return false;
  return entrypoint.find('/') == std::string_view::npos &&
         entrypoint.find('\\') == std::string_view::npos &&
         entrypoint.ends_with(".lua");
}

std::string canonical(std::string_view text) {
  std::string result(text);
  std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return result;
}

}  // namespace

std::optional<PluginManifest> PluginManifest::load(
    const std::filesystem::path& path, std::string& error) {
  std::error_code fs_error;
  const auto size = std::filesystem::file_size(path, fs_error);
  if (fs_error || size > kMaxManifestBytes) {
    error = fs_error ? "cannot stat plugin manifest: " + fs_error.message()
                     : "plugin manifest exceeds 256 KiB";
    return std::nullopt;
  }
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream data;
  data << stream.rdbuf();
  if (!stream || data.str().size() != size) {
    error = "cannot read plugin manifest: " + path.string();
    return std::nullopt;
  }
  auto parsed = json::parse(data.str());
  if (!parsed.value || !parsed.value->object()) {
    error = parsed.value ? "plugin manifest root must be an object"
                         : "invalid plugin manifest JSON: " + parsed.error;
    return std::nullopt;
  }
  const auto& root = *parsed.value->object();
  const auto* schema = json::get(root, "schema_version");
  if (!schema || !schema->integer() || *schema->integer() != 1) {
    error = "plugin manifest schema_version must be 1";
    return std::nullopt;
  }
  auto id = require_string(root, "id", error);
  auto version = require_string(root, "version", error);
  auto entrypoint = require_string(root, "entrypoint", error);
  if (!id || !version || !entrypoint) return std::nullopt;
  if (!valid_id(*id) || !safe_entrypoint(*entrypoint)) {
    error = "plugin id or entrypoint is unsafe";
    return std::nullopt;
  }
  auto memory = optional_limit(root, "memory_limit_bytes", 32U * 1024U * 1024U,
                               1024U * 1024U, 32U * 1024U * 1024U, error);
  auto instructions = optional_limit(root, "instruction_limit", 250000,
                                     1000, 250000, error);
  if (!memory || !instructions) return std::nullopt;

  PluginManifest manifest;
  manifest.schema_version = 1;
  manifest.id = *id;
  manifest.version = *version;
  manifest.directory = path.parent_path();
  manifest.entrypoint = manifest.directory / *entrypoint;
  manifest.memory_limit_bytes = *memory;
  manifest.instruction_limit = *instructions;

  const auto* commands_value = json::get(root, "commands");
  const auto* commands = commands_value ? commands_value->array() : nullptr;
  if (!commands || commands->size() > 64) {
    error = "manifest commands must be an array of at most 64 items";
    return std::nullopt;
  }
  for (const auto& value : *commands) {
    const auto* command = value.object();
    if (!command) {
      error = "command declaration must be an object";
      return std::nullopt;
    }
    auto name = require_string(*command, "name", error);
    auto permission = require_string(*command, "permission", error);
    const auto* suppress = json::get(*command, "suppress");
    if (!name || !permission || !suppress || !suppress->boolean()) {
      if (error.empty()) error = "command suppress must be a boolean";
      return std::nullopt;
    }
    CommandSpec spec;
    spec.plugin_id = manifest.id;
    spec.name = *name;
    spec.suppress = *suppress->boolean();
    if (*permission == "everyone") spec.permission = Permission::Everyone;
    else if (*permission == "server.admin") spec.permission = Permission::ServerAdmin;
    else {
      error = "unknown command permission: " + *permission;
      return std::nullopt;
    }
    manifest.commands.push_back(std::move(spec));
  }
  if (!std::filesystem::is_regular_file(manifest.entrypoint, fs_error) || fs_error) {
    error = "plugin entrypoint is not a regular file";
    return std::nullopt;
  }
  return manifest;
}

class PluginRuntime::Instance {
 public:
  Instance(PluginManifest manifest, ActionQueue& actions, const ReflectionReader* reader)
      : manifest_(std::move(manifest)), actions_(actions), reader_(reader) {}
  ~Instance() { stop(); }

  bool start(std::string& error) {
#if PALMOD_HAS_LUA
    thread_ = std::thread([this] { run(); });
    std::unique_lock lock(mu_);
    started_cv_.wait(lock, [this] { return initialized_; });
    error = error_;
    return running_;
#else
    error = "Lua 5.4 support was not compiled in";
    std::scoped_lock lock(mu_);
    initialized_ = true;
    error_ = error;
    return false;
#endif
  }

  bool enqueue(CommandInvocation invocation) {
    std::scoped_lock lock(mu_);
    if (!running_ || stopping_ || queue_.size() >= kMaxCommandQueue) return false;
    queue_.push_back(std::move(invocation));
    work_cv_.notify_one();
    return true;
  }

  bool enqueue_event(PluginEvent event) {
    std::scoped_lock lock(mu_);
    if (!running_ || stopping_ || event_queue_.size() >= kMaxCommandQueue) return false;
    if (!subscribed_kinds_.contains(canonical(event.kind))) return false;
    event_queue_.push_back(std::move(event));
    work_cv_.notify_one();
    return true;
  }

  PluginStatus status() const {
    std::scoped_lock lock(mu_);
    return {manifest_.id, manifest_.version, running_, error_,
            queue_.size() + event_queue_.size()};
  }

  bool wait_idle(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mu_);
    return idle_cv_.wait_for(lock, timeout, [this] {
      return queue_.empty() && event_queue_.empty() && !busy_;
    });
  }

  void stop() {
    {
      std::scoped_lock lock(mu_);
      stopping_ = true;
      work_cv_.notify_all();
    }
    if (thread_.joinable()) thread_.join();
  }

  const PluginManifest& manifest() const { return manifest_; }

  std::set<std::string, std::less<>> subscribed_kinds() const {
    std::scoped_lock lock(mu_);
    return subscribed_kinds_;
  }

 private:
#if PALMOD_HAS_LUA
  struct Allocator {
    std::size_t used{0};
    std::size_t limit{0};
  } allocator_;

  static void* lua_allocate(void* opaque, void* pointer, std::size_t old_size,
                            std::size_t new_size) {
    auto& allocator = *static_cast<Allocator*>(opaque);
    const std::size_t accounted_old = pointer ? old_size : 0;
    if (new_size == 0) {
      std::free(pointer);
      allocator.used = accounted_old > allocator.used ? 0 : allocator.used - accounted_old;
      return nullptr;
    }
    if (new_size > accounted_old && new_size - accounted_old > allocator.limit - allocator.used) {
      return nullptr;
    }
    void* replacement = std::realloc(pointer, new_size);
    if (!replacement) return nullptr;
    allocator.used = allocator.used - accounted_old + new_size;
    return replacement;
  }

  static Instance* self(lua_State* state) {
    return static_cast<Instance*>(lua_touserdata(state, lua_upvalueindex(1)));
  }

  static int lua_on_command(lua_State* state) {
    auto* instance = self(state);
    const char* name = luaL_checkstring(state, 1);
    luaL_checktype(state, 2, LUA_TFUNCTION);
    const std::string key = canonical(name);
    const auto declared = std::find_if(instance->manifest_.commands.begin(),
                                       instance->manifest_.commands.end(),
                                       [&](const CommandSpec& command) {
                                         return canonical(command.name) == key;
                                       });
    if (declared == instance->manifest_.commands.end()) {
      return luaL_error(state, "command is not declared in manifest");
    }
    lua_pushvalue(state, 2);
    const int reference = luaL_ref(state, LUA_REGISTRYINDEX);
    if (const auto old = instance->handlers_.find(key); old != instance->handlers_.end()) {
      luaL_unref(state, LUA_REGISTRYINDEX, old->second);
      old->second = reference;
    } else {
      instance->handlers_.emplace(key, reference);
    }
    return 0;
  }

  static int lua_on_event(lua_State* state) {
    auto* instance = self(state);
    const std::string kind = canonical(luaL_checkstring(state, 1));
    luaL_checktype(state, 2, LUA_TFUNCTION);
    if (kind.empty() || kind.size() > 64) {
      return luaL_error(state, "event kind must be 1..64 bytes");
    }
    lua_pushvalue(state, 2);
    const int reference = luaL_ref(state, LUA_REGISTRYINDEX);
    if (const auto old = instance->event_handlers_.find(kind);
        old != instance->event_handlers_.end()) {
      luaL_unref(state, LUA_REGISTRYINDEX, old->second);
      old->second = reference;
    } else {
      instance->event_handlers_.emplace(kind, reference);
    }
    {
      // Publish the subscription so the delivering thread can filter under mu_.
      std::scoped_lock lock(instance->mu_);
      instance->subscribed_kinds_.insert(kind);
    }
    return 0;
  }


  // Convert a Lua value at `idx` into a ParamInput value tree: number/bool ->
  // number, string -> text, array-like table -> is_array items, string-keyed
  // table -> is_struct named members. Depth-bounded.
  static ParamInput parse_param(lua_State* state, int idx, std::string name, int depth) {
    ParamInput param;
    param.name = std::move(name);
    if (depth > 8) return param;
    idx = lua_absindex(state, idx);
    switch (lua_type(state, idx)) {
      case LUA_TNUMBER:
        param.number = lua_tonumber(state, idx);
        break;
      case LUA_TBOOLEAN:
        param.number = lua_toboolean(state, idx) != 0 ? 1.0 : 0.0;
        break;
      case LUA_TSTRING:
        param.is_text = true;
        param.text = lua_tostring(state, idx);
        break;
      case LUA_TTABLE: {
        lua_rawgeti(state, idx, 1);
        const bool is_array = lua_isnil(state, -1) == 0;
        lua_pop(state, 1);
        if (is_array) {
          param.is_array = true;
          const lua_Integer count = luaL_len(state, idx);
          for (lua_Integer i = 1; i <= count && i <= 4096; ++i) {
            lua_rawgeti(state, idx, i);
            param.items.push_back(parse_param(state, -1, "", depth + 1));
            lua_pop(state, 1);
          }
        } else {
          param.is_struct = true;
          lua_pushnil(state);
          while (lua_next(state, idx) != 0) {
            if (lua_type(state, -2) == LUA_TSTRING) {
              param.items.push_back(
                  parse_param(state, -1, lua_tostring(state, -2), depth + 1));
            }
            lua_pop(state, 1);  // pop value, keep key for the next iteration
          }
        }
        break;
      }
      default:
        break;
    }
    return param;
  }

  // pal.find_object(class[, name]) -> object handle (integer) or nil.
  static int lua_find_object(lua_State* state) {
    auto* instance = self(state);
    const char* cls = luaL_checkstring(state, 1);
    const char* name =
        (lua_gettop(state) >= 2 && lua_type(state, 2) == LUA_TSTRING) ? lua_tostring(state, 2) : "";
    const std::uint64_t obj =
        instance->reader_ != nullptr ? instance->reader_->find_object(cls, name) : 0;
    if (obj == 0) {
      lua_pushnil(state);
    } else {
      lua_pushinteger(state, static_cast<lua_Integer>(obj));
    }
    return 1;
  }

  // pal.find_all_of(class[, max]) -> array of object handles.
  static int lua_find_all_of(lua_State* state) {
    auto* instance = self(state);
    const char* cls = luaL_checkstring(state, 1);
    lua_Integer max = lua_gettop(state) >= 2 ? luaL_checkinteger(state, 2) : 256;
    max = max < 1 ? 1 : (max > 4096 ? 4096 : max);
    lua_newtable(state);
    if (instance->reader_ != nullptr) {
      const auto objects = instance->reader_->find_all_of(cls, static_cast<std::size_t>(max));
      for (std::size_t i = 0; i < objects.size(); ++i) {
        lua_pushinteger(state, static_cast<lua_Integer>(objects[i]));
        lua_rawseti(state, -2, static_cast<lua_Integer>(i + 1));
      }
    }
    return 1;
  }

  // pal.get(handle, property) -> the decoded value (scalar/string/array/table) or nil.
  static int lua_get(lua_State* state) {
    auto* instance = self(state);
    const auto handle = static_cast<std::uint64_t>(luaL_checkinteger(state, 1));
    const char* prop = luaL_checkstring(state, 2);
    std::optional<EventArg> value;
    if (instance->reader_ != nullptr) value = instance->reader_->get_property(handle, prop);
    if (!value) {
      lua_pushnil(state);
    } else {
      instance->push_event_arg(*value);
    }
    return 1;
  }

  // pal.class_of(handle) -> class name string or nil.
  static int lua_class_of(lua_State* state) {
    auto* instance = self(state);
    const auto handle = static_cast<std::uint64_t>(luaL_checkinteger(state, 1));
    const std::string cls =
        instance->reader_ != nullptr ? instance->reader_->class_of(handle) : std::string();
    if (cls.empty()) {
      lua_pushnil(state);
    } else {
      lua_pushstring(state, cls.c_str());
    }
    return 1;
  }

  // pal.datatable_rows(name[, max]) -> array of a DataTable's row-name strings.
  static int lua_datatable_rows(lua_State* state) {
    auto* instance = self(state);
    const char* name = luaL_checkstring(state, 1);
    lua_Integer max = lua_gettop(state) >= 2 ? luaL_checkinteger(state, 2) : 4096;
    max = max < 1 ? 1 : (max > 65536 ? 65536 : max);
    lua_newtable(state);
    if (instance->reader_ != nullptr) {
      const std::uint64_t table = instance->reader_->find_object("DataTable", name);
      if (table != 0) {
        const auto rows = instance->reader_->datatable_rows(table, static_cast<std::size_t>(max));
        for (std::size_t i = 0; i < rows.size(); ++i) {
          lua_pushstring(state, rows[i].c_str());
          lua_rawseti(state, -2, static_cast<lua_Integer>(i + 1));
        }
      }
    }
    return 1;
  }

  static int lua_pal_call(lua_State* state) {
    auto* instance = self(state);
    const char* path = luaL_checkstring(state, 1);
    luaL_checktype(state, 2, LUA_TTABLE);
    if (!instance->current_ && !instance->current_event_) {
      return luaL_error(state, "actions are only valid inside a callback");
    }
    SemanticAction action;
    action.kind = ActionKind::CallFunction;
    action.source_plugin = instance->manifest_.id;
    if (instance->current_) {
      action.actor = instance->current_->principal == PrincipalKind::LocalOperator
                         ? "local-operator:" + std::to_string(instance->current_->operator_uid)
                         : instance->current_->player;
      action.actor_handle = instance->current_->player_handle;
    } else {
      action.actor = instance->current_event_->source;
      action.actor_handle = instance->current_event_->handle;
    }
    action.function_path = path;
    if (lua_gettop(state) >= 3) {
      // The target is either a class name (first live instance) or a specific
      // object handle from pal.find_object/find_all_of.
      if (lua_type(state, 3) == LUA_TSTRING) {
        action.target_class = lua_tostring(state, 3);
      } else if (lua_isinteger(state, 3)) {
        action.target_object = static_cast<std::uint64_t>(lua_tointeger(state, 3));
      }
    }
    // The args table's named keys are the top-level parameters.
    action.call_args = std::move(parse_param(state, 2, "", 0).items);
    if (action.function_path.size() > 256 || action.call_args.size() > 64) {
      return luaL_error(state, "call arguments are too large");
    }
    if (!instance->actions_.push(std::move(action))) {
      return luaL_error(state, "game-thread action queue is full");
    }
    return 0;
  }


  static int lua_log(lua_State* state) {
    auto* instance = self(state);
    const std::string_view level(luaL_checkstring(state, 1));
    std::string message(luaL_checkstring(state, 2));
    if (message.size() > 2048) message.resize(2048);
    auto log_level = JsonLog::Level::Info;
    if (level == "debug") log_level = JsonLog::Level::Debug;
    else if (level == "warn") log_level = JsonLog::Level::Warn;
    else if (level == "error") log_level = JsonLog::Level::Error;
    JsonLog::instance().write(log_level, "plugin.log", message,
                              {{"plugin", instance->manifest_.id}});
    return 0;
  }

  static void instruction_hook(lua_State* state, lua_Debug*) {
    auto* instance = *static_cast<Instance**>(lua_getextraspace(state));
    constexpr std::size_t kQuantum = 1000;
    if (instance->instructions_remaining_ <= kQuantum) {
      instance->instructions_remaining_ = 0;
      luaL_error(state, "plugin instruction budget exceeded");
      return;
    }
    instance->instructions_remaining_ -= kQuantum;
  }

  void expose_api(lua_State* state) {
    lua_newtable(state);
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_on_command, 1);
    lua_setfield(state, -2, "on_command");
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_on_event, 1);
    lua_setfield(state, -2, "on_event");
    // `hook(name, fn)` is intention-revealing sugar for subscribing to a game
    // function by its reflected name: the runtime auto-installs a generic
    // UFunction::Func hook for any subscribed kind found in the profile's hook
    // catalog, and the decoded parameters arrive as `event.args`.
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_on_event, 1);
    lua_setfield(state, -2, "hook");
    // `call(path, args[, target_class])` calls any UFunction by name, generically:
    // the game thread resolves it in GUObjectArray, reads its param layout live,
    // encodes `args`, and dispatches via ProcessEvent. No per-function native code.
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_pal_call, 1);
    lua_setfield(state, -2, "call");
    // Read-side reflection: find objects by class/name and read their properties.
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_find_object, 1);
    lua_setfield(state, -2, "find_object");
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_find_all_of, 1);
    lua_setfield(state, -2, "find_all_of");
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_get, 1);
    lua_setfield(state, -2, "get");
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_class_of, 1);
    lua_setfield(state, -2, "class_of");
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_datatable_rows, 1);
    lua_setfield(state, -2, "datatable_rows");
    lua_pushlightuserdata(state, this);
    lua_pushcclosure(state, lua_log, 1);
    lua_setfield(state, -2, "log");
    lua_setglobal(state, "palmod");
  }

  void open_safe_libraries(lua_State* state) {
    const struct { const char* name; lua_CFunction open; } libraries[] = {
        {LUA_GNAME, luaopen_base}, {LUA_TABLIBNAME, luaopen_table},
        {LUA_STRLIBNAME, luaopen_string}, {LUA_MATHLIBNAME, luaopen_math},
        {LUA_UTF8LIBNAME, luaopen_utf8}};
    for (const auto& library : libraries) {
      luaL_requiref(state, library.name, library.open, 1);
      lua_pop(state, 1);
    }
    lua_pushnil(state); lua_setglobal(state, "dofile");
    lua_pushnil(state); lua_setglobal(state, "loadfile");
    lua_pushnil(state); lua_setglobal(state, "load");
    lua_pushnil(state); lua_setglobal(state, "collectgarbage");
  }

  // Run the embedded pure-Lua standard library as a preamble, so every plugin
  // gets the higher-level helpers (palmod.reply / broadcast / paginate / ...),
  // built on the native primitives, with no `require` and no per-plugin copy.
  // Authored in sdk/lua/stdlib.lua and compiled in (see cmake/embed_lua.cmake).
  bool load_stdlib(std::string& error) {
    if (luaL_loadbufferx(state_, kPluginStdlibLua, sizeof(kPluginStdlibLua) - 1,
                         "@palmod/stdlib", "t") != LUA_OK ||
        lua_pcall(state_, 0, 0, 0) != LUA_OK) {
      error = std::string("palmod stdlib failed to load: ") +
              (lua_tostring(state_, -1) ? lua_tostring(state_, -1) : "unknown error");
      lua_pop(state_, 1);
      return false;
    }
    return true;
  }

  bool initialize_lua(std::string& error) {
    allocator_.limit = manifest_.memory_limit_bytes;
    state_ = lua_newstate(lua_allocate, &allocator_);
    if (!state_) {
      error = "cannot create Lua state within memory limit";
      return false;
    }
    *static_cast<Instance**>(lua_getextraspace(state_)) = this;
    open_safe_libraries(state_);
    expose_api(state_);
    // Before the plugin body and before the instruction budget is armed, so the
    // stdlib load is neither billed to nor interruptible by the plugin's limit.
    if (!load_stdlib(error)) return false;
    instructions_remaining_ = manifest_.instruction_limit;
    lua_sethook(state_, instruction_hook, LUA_MASKCOUNT, 1000);
    if (luaL_loadfilex(state_, manifest_.entrypoint.c_str(), "t") != LUA_OK ||
        lua_pcall(state_, 0, 0, 0) != LUA_OK) {
      error = lua_tostring(state_, -1) ? lua_tostring(state_, -1) : "Lua plugin initialization failed";
      lua_pop(state_, 1);
      return false;
    }
    for (const auto& command : manifest_.commands) {
      if (!handlers_.contains(canonical(command.name))) {
        error = "plugin did not register declared command: " + command.name;
        return false;
      }
    }
    return true;
  }

  void invoke(const CommandInvocation& invocation) {
    const auto found = handlers_.find(canonical(invocation.command));
    if (found == handlers_.end()) return;
    lua_rawgeti(state_, LUA_REGISTRYINDEX, found->second);
    lua_newtable(state_);
    lua_pushlstring(state_, invocation.command.data(), invocation.command.size());
    lua_setfield(state_, -2, "command");
    lua_pushlstring(state_, invocation.raw.data(), invocation.raw.size());
    lua_setfield(state_, -2, "raw");
    lua_pushlstring(state_, invocation.player.data(), invocation.player.size());
    lua_setfield(state_, -2, "player");
    lua_pushinteger(state_, static_cast<lua_Integer>(invocation.player_handle));
    lua_setfield(state_, -2, "player_handle");
    lua_pushboolean(state_, invocation.auth == AuthState::Admin);
    lua_setfield(state_, -2, "is_admin");
    lua_pushstring(state_, invocation.principal == PrincipalKind::LocalOperator
                               ? "local_operator" : "in_game_player");
    lua_setfield(state_, -2, "principal");
    lua_pushinteger(state_, static_cast<lua_Integer>(invocation.operator_uid));
    lua_setfield(state_, -2, "operator_uid");
    lua_newtable(state_);
    for (std::size_t i = 0; i < invocation.args.size(); ++i) {
      lua_pushlstring(state_, invocation.args[i].data(), invocation.args[i].size());
      lua_rawseti(state_, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(state_, -2, "args");
    current_ = &invocation;
    instructions_remaining_ = manifest_.instruction_limit;
    lua_sethook(state_, instruction_hook, LUA_MASKCOUNT, 1000);
    if (lua_pcall(state_, 1, 0, 0) != LUA_OK) {
      const char* failure = lua_tostring(state_, -1);
      JsonLog::instance().write(JsonLog::Level::Error, "plugin.callback_failed",
                                failure ? failure : "unknown Lua error",
                                {{"plugin", manifest_.id}, {"command", invocation.command}});
      lua_pop(state_, 1);
    }
    current_ = nullptr;
  }

  // Push one decoded arg onto the Lua stack: a string, a number, or (for array
  // args) a 1-based table of its elements.
  void push_event_arg(const EventArg& arg) {
    if (arg.is_struct) {
      lua_newtable(state_);
      for (const auto& item : arg.items) {
        push_event_arg(item);
        lua_setfield(state_, -2, item.name.c_str());
      }
    } else if (arg.is_array) {
      lua_newtable(state_);
      lua_Integer index = 1;
      for (const auto& item : arg.items) {
        push_event_arg(item);
        lua_rawseti(state_, -2, index++);
      }
    } else if (arg.is_text) {
      lua_pushlstring(state_, arg.text.data(), arg.text.size());
    } else {
      lua_pushnumber(state_, arg.number);
    }
  }

  void invoke_event(const PluginEvent& event) {
    const auto found = event_handlers_.find(canonical(event.kind));
    if (found == event_handlers_.end()) return;
    lua_rawgeti(state_, LUA_REGISTRYINDEX, found->second);
    lua_newtable(state_);
    lua_pushlstring(state_, event.kind.data(), event.kind.size());
    lua_setfield(state_, -2, "kind");
    lua_pushinteger(state_, static_cast<lua_Integer>(event.sequence));
    lua_setfield(state_, -2, "sequence");
    lua_pushlstring(state_, event.source.data(), event.source.size());
    lua_setfield(state_, -2, "source");
    lua_pushlstring(state_, event.text.data(), event.text.size());
    lua_setfield(state_, -2, "text");
    lua_pushlstring(state_, event.subject.data(), event.subject.size());
    lua_setfield(state_, -2, "subject");
    lua_pushinteger(state_, static_cast<lua_Integer>(event.handle));
    lua_setfield(state_, -2, "handle");
    lua_pushinteger(state_, static_cast<lua_Integer>(event.number));
    lua_setfield(state_, -2, "number");
    // Generic by-name hooks carry their decoded parameters here: args[name] = value.
    lua_newtable(state_);
    for (const auto& arg : event.args) {
      push_event_arg(arg);
      lua_setfield(state_, -2, arg.name.c_str());
    }
    lua_setfield(state_, -2, "args");
    current_event_ = &event;
    instructions_remaining_ = manifest_.instruction_limit;
    lua_sethook(state_, instruction_hook, LUA_MASKCOUNT, 1000);
    if (lua_pcall(state_, 1, 0, 0) != LUA_OK) {
      const char* failure = lua_tostring(state_, -1);
      JsonLog::instance().write(JsonLog::Level::Error, "plugin.event_failed",
                                failure ? failure : "unknown Lua error",
                                {{"plugin", manifest_.id}, {"event", event.kind}});
      lua_pop(state_, 1);
    }
    current_event_ = nullptr;
  }

  void run() {
    std::string initialization_error;
    const bool ok = initialize_lua(initialization_error);
    {
      std::scoped_lock lock(mu_);
      initialized_ = true;
      running_ = ok;
      error_ = initialization_error;
      started_cv_.notify_all();
    }
    if (ok) {
      while (true) {
        CommandInvocation invocation;
        PluginEvent event;
        bool is_event = false;
        {
          std::unique_lock lock(mu_);
          work_cv_.wait(lock, [this] {
            return stopping_ || !queue_.empty() || !event_queue_.empty();
          });
          if (stopping_ && queue_.empty() && event_queue_.empty()) break;
          if (!queue_.empty()) {
            invocation = std::move(queue_.front());
            queue_.pop_front();
          } else {
            event = std::move(event_queue_.front());
            event_queue_.pop_front();
            is_event = true;
          }
          busy_ = true;
        }
        if (is_event) {
          invoke_event(event);
        } else {
          invoke(invocation);
        }
        {
          std::scoped_lock lock(mu_);
          busy_ = false;
          if (queue_.empty() && event_queue_.empty()) idle_cv_.notify_all();
        }
      }
    }
    if (state_) {
      lua_close(state_);
      state_ = nullptr;
    }
    std::scoped_lock lock(mu_);
    running_ = false;
    busy_ = false;
    idle_cv_.notify_all();
  }

  lua_State* state_{nullptr};
  std::map<std::string, int, std::less<>> handlers_;
  std::map<std::string, int, std::less<>> event_handlers_;
  const CommandInvocation* current_{nullptr};
  const PluginEvent* current_event_{nullptr};
  std::size_t instructions_remaining_{0};
#endif

  PluginManifest manifest_;
  ActionQueue& actions_;
  const ReflectionReader* reader_{nullptr};
  mutable std::mutex mu_;
  std::condition_variable started_cv_;
  std::condition_variable work_cv_;
  std::condition_variable idle_cv_;
  std::deque<CommandInvocation> queue_;
  std::deque<PluginEvent> event_queue_;
  std::set<std::string, std::less<>> subscribed_kinds_;
  std::thread thread_;
  bool initialized_{false};
  bool running_{false};
  bool stopping_{false};
  bool busy_{false};
  std::string error_;
};

PluginRuntime::PluginRuntime(ActionQueue& actions) : actions_(actions) {}

void PluginRuntime::set_reflection_reader(ReflectionReader reader) {
  reader_ = std::move(reader);  // set before plugins load; instances hold &reader_
}
PluginRuntime::~PluginRuntime() { stop(); }

std::size_t PluginRuntime::load_directory(const std::filesystem::path& root,
                                          CommandRouter& router) {
  return load_directory_report(root, router).loaded;
}

PluginLoadReport PluginRuntime::load_directory_report(
    const std::filesystem::path& root, CommandRouter& router) {
  PluginLoadReport report;
  std::error_code error;
  if (!std::filesystem::is_directory(root, error)) {
    report.errors.push_back("plugin directory is unavailable: " + root.string());
    JsonLog::instance().write(JsonLog::Level::Warn, "plugins.missing",
                              "plugin directory is unavailable", {{"path", root.string()}});
    return report;
  }
  std::vector<std::filesystem::path> manifests;
  for (const auto& entry : std::filesystem::directory_iterator(root, error)) {
    if (error) break;
    if (entry.is_directory()) {
      const auto manifest = entry.path() / "manifest.json";
      if (std::filesystem::is_regular_file(manifest)) manifests.push_back(manifest);
    }
  }
  std::sort(manifests.begin(), manifests.end());
  report.discovered = manifests.size();
  for (const auto& manifest_path : manifests) {
    std::string failure;
    auto manifest = PluginManifest::load(manifest_path, failure);
    if (!manifest) {
      report.errors.push_back(manifest_path.string() + ": " + failure);
      JsonLog::instance().write(JsonLog::Level::Error, "plugin.manifest_rejected",
                                failure, {{"path", manifest_path.string()}});
      continue;
    }
    auto instance = std::make_unique<Instance>(*manifest, actions_, &reader_);
    if (!instance->start(failure)) {
      report.errors.push_back(manifest->id + ": " + failure);
      JsonLog::instance().write(JsonLog::Level::Error, "plugin.start_failed", failure,
                                {{"plugin", manifest->id}});
      std::scoped_lock lock(mu_);
      plugins_.emplace(manifest->id, std::move(instance));
      continue;
    }
    bool commands_ok = true;
    for (auto command : manifest->commands) {
      if (!router.register_command(std::move(command), failure)) {
        commands_ok = false;
        break;
      }
    }
    if (!commands_ok) {
      report.errors.push_back(manifest->id + ": " + failure);
      JsonLog::instance().write(JsonLog::Level::Error, "plugin.command_rejected", failure,
                                {{"plugin", manifest->id}});
      instance->stop();
      continue;
    }
    {
      std::scoped_lock lock(mu_);
      if (!plugins_.emplace(manifest->id, std::move(instance)).second) {
        report.errors.push_back(manifest->id + ": duplicate plugin id");
        JsonLog::instance().write(JsonLog::Level::Error, "plugin.duplicate",
                                  "duplicate plugin id", {{"plugin", manifest->id}});
        continue;
      }
    }
    ++report.loaded;
    JsonLog::instance().write(JsonLog::Level::Info, "plugin.loaded", "plugin started",
                              {{"plugin", manifest->id}, {"version", manifest->version}});
  }
  return report;
}

bool PluginRuntime::dispatch(CommandInvocation invocation) {
  std::scoped_lock lock(mu_);
  const auto found = plugins_.find(invocation.plugin_id);
  return found != plugins_.end() && found->second->enqueue(std::move(invocation));
}

std::size_t PluginRuntime::deliver_event(const PluginEvent& event) {
  std::scoped_lock lock(mu_);
  std::size_t delivered = 0;
  for (const auto& [id, instance] : plugins_) {
    (void)id;
    if (instance->enqueue_event(event)) ++delivered;
  }
  return delivered;
}

std::set<std::string, std::less<>> PluginRuntime::subscribed_event_kinds() const {
  std::scoped_lock lock(mu_);
  std::set<std::string, std::less<>> kinds;
  for (const auto& [id, instance] : plugins_) {
    (void)id;
    for (auto& kind : instance->subscribed_kinds()) kinds.insert(kind);
  }
  return kinds;
}

std::vector<PluginStatus> PluginRuntime::statuses() const {
  std::scoped_lock lock(mu_);
  std::vector<PluginStatus> result;
  result.reserve(plugins_.size());
  for (const auto& [id, instance] : plugins_) {
    (void)id;
    result.push_back(instance->status());
  }
  return result;
}

bool PluginRuntime::wait_idle(std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  std::scoped_lock lock(mu_);
  for (const auto& [id, instance] : plugins_) {
    (void)id;
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline || !instance->wait_idle(
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now))) return false;
  }
  return true;
}

void PluginRuntime::stop() {
  std::map<std::string, std::unique_ptr<Instance>, std::less<>> plugins;
  {
    std::scoped_lock lock(mu_);
    plugins.swap(plugins_);
  }
  for (auto& [id, instance] : plugins) {
    (void)id;
    instance->stop();
  }
}

}  // namespace palmod
