#include "palmod/reflection_backend.hpp"

#include "palmod/invoke.hpp"
#include "palmod/json_log.hpp"
#include "palmod/parms_encode.hpp"
#include "palmod/reflect_layout.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace palmod {
namespace {

// A single active reflection backend at a time. A production implementation
// keyed by UFunction* would use a table; the tick hook only needs one context.
ReflectionHookBackend* g_active_reflection = nullptr;

bool make_slot_writable(void** slot, std::string& error) {
  const long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    error = "cannot determine page size";
    return false;
  }
  const auto mask = static_cast<std::uintptr_t>(page_size) - 1;
  const auto address = reinterpret_cast<std::uintptr_t>(slot);
  // An 8-byte aligned pointer never straddles a page boundary, so one page
  // covers the whole slot.
  auto* page = reinterpret_cast<void*>(address & ~mask);
  if (mprotect(page, static_cast<std::size_t>(page_size),
               PROT_READ | PROT_WRITE) != 0) {
    error = "cannot make reflection pointer slot writable";
    return false;
  }
  return true;
}

// Uppercase hex of `n` bytes — used to turn a 16-byte sender Guid into a stable
// player id for the directory (mirrors Palworld's own "Player id" hex format).
std::string bytes_to_hex(const std::uint8_t* data, std::size_t n) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0x0F]);
  }
  return out;
}

}  // namespace

std::optional<ReflectionResolver> make_reflection_resolver(const BuildProfile& profile) {
  if (!profile.has_reflection()) return std::nullopt;
  return ReflectionResolver{profile.reflection_func_offset, profile.reflection_vtable_va};
}

bool PointerSlotHook::install(void** slot, void* replacement, std::string& error) {
  if (slot_ != nullptr) {
    error = "pointer slot hook is already installed";
    return false;
  }
  if (slot == nullptr) {
    error = "pointer slot address is null";
    return false;
  }
  if ((reinterpret_cast<std::uintptr_t>(slot) % alignof(void*)) != 0) {
    error = "pointer slot is not 8-byte aligned; refusing a non-atomic write";
    return false;
  }
  if (!make_slot_writable(slot, error)) return false;
  original_ = *slot;
  std::atomic_ref<void*>(*slot).store(replacement, std::memory_order_release);
  slot_ = slot;
  return true;
}

void PointerSlotHook::uninstall() {
  if (slot_ == nullptr) return;
  std::atomic_ref<void*>(*slot_).store(original_, std::memory_order_release);
  slot_ = nullptr;
  original_ = nullptr;
}

bool ReflectionHookBackend::install(const BuildProfile& profile,
                                    HookCallbacks callbacks, std::string& error) {
  callbacks_ = std::move(callbacks);
  g_active_reflection = this;
  resolver_ = make_reflection_resolver(profile);
  fname_pool_ = FNamePool{profile.reflection_fname_pool_blocks_va};
  // The GUObjectArray walker is shared by the inventory adapter + the admin check.
  object_layout_ = ObjectArrayLayout{};
  object_layout_.objects_va = profile.reflection_guobjectarray_objects_va;
  object_layout_.super_offset = profile.reflection_super_struct_offset;
  process_event_slot_ = profile.reflection_process_event_slot;
  if (!profile.reflection_admin_controller_class.empty() &&
      profile.reflection_admin_badmin_offset != 0) {
    admin_layout_.controller_class = profile.reflection_admin_controller_class;
    admin_layout_.player_state_offset = profile.reflection_admin_player_state_offset;
    admin_layout_.player_uid_offset = profile.reflection_admin_player_uid_offset;
    admin_layout_.badmin_offset = profile.reflection_admin_badmin_offset;
  }
  // The loader runs at LD_PRELOAD time, before the game creates GEngine and
  // populates GUObjectArray. Reflection hooks can only install once those exist,
  // so wait for the engine to come up (this runs on the detached bootstrap
  // thread, so blocking is fine). A non-null GEngine appears ~1s into boot but is
  // still mid-construction then; dereferencing its half-built vtable crashes the
  // swap. So require the pointer to resolve to an object whose vtable *and* Tick
  // slot both land inside the game image before treating it as ready — and probe
  // it with fault-safe reads so a transient garbage pointer never faults us.
  std::uint64_t ready_engine = 0;
  if (profile.reflection_gengine_global_va != 0) {
    const std::uint64_t image_lo = profile.image_base;
    const std::uint64_t image_hi = profile.image_base + profile.executable_size;
    const auto in_image = [image_lo, image_hi](std::uint64_t va) {
      return va >= image_lo && va < image_hi;
    };
    const auto probe_engine = [&](std::uint64_t& engine_out) -> bool {
      std::uint64_t engine = 0;
      if (!try_read_u64(profile.reflection_gengine_global_va, engine) || engine < 0x10000) {
        return false;
      }
      std::uint64_t vtable = 0;
      if (!try_read_u64(engine, vtable) || !in_image(vtable)) return false;
      std::uint64_t tick_fn = 0;
      const std::uint64_t tick_entry =
          vtable + profile.reflection_engine_tick_vtable_slot * sizeof(std::uint64_t);
      if (!try_read_u64(tick_entry, tick_fn) || !in_image(tick_fn)) return false;
      engine_out = engine;
      return true;
    };
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(240);
    while (std::chrono::steady_clock::now() < deadline) {
      if (probe_engine(ready_engine)) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    JsonLog::instance().write(
        ready_engine != 0 ? JsonLog::Level::Info : JsonLog::Level::Warn,
        "reflection.engine_wait",
        ready_engine != 0 ? "GEngine fully constructed; installing reflection hooks"
                          : "GEngine did not become valid before timeout; installing anyway");
  }

  bool installed_any = false;

  // Resolve the game-thread drain pump from the profile: swap GEngine's Tick
  // vtable entry (UE4SS's EngineTick method, done as a data-pointer swap). Skip
  // when a tick slot was injected for testing.
  if (!layout_.configured() && ready_engine != 0) {
    const std::uint64_t slot = vtable_slot_address(
        ready_engine, profile.reflection_engine_tick_vtable_slot);
    if (slot != 0) {
      layout_.tick_slot = reinterpret_cast<void**>(static_cast<std::uintptr_t>(slot));
    }
  }

  // Periodic game-thread tick — drains the action queue on the game thread.
  if (layout_.configured()) {
    JsonLog::instance().write(JsonLog::Level::Info, "reflection.tick_installing",
                              "swapping GEngine Tick vtable slot");
    TickFn trampoline = &tick_trampoline;
    void* trampoline_bits = nullptr;
    std::memcpy(&trampoline_bits, &trampoline, sizeof trampoline_bits);
    std::string tick_error;
    if (tick_hook_.install(layout_.tick_slot, trampoline_bits, tick_error)) {
      installed_any = true;
      JsonLog::instance().write(JsonLog::Level::Info, "reflection.tick_installed",
                                "GEngine Tick drain pump installed");
    } else {
      JsonLog::instance().write(JsonLog::Level::Warn, "reflection.tick_unavailable",
                                tick_error);
    }
  }

  // Chat interception from validated profile facts. Per-hook fail-closed: if the
  // UFunction::Func slot can't be resolved we log and keep going, we do not abort
  // the whole backend.
  if (profile.has_chat_hook() && (callbacks_.on_event || callbacks_.on_chat)) {
    const ReflectionResolver resolver{profile.reflection_func_offset,
                                      profile.reflection_vtable_va};
    ChatHook::Config config;
    config.broadcast_thunk_va = profile.image_base + profile.chat_broadcast_thunk_rva;
    config.fframe_locals_offset = profile.chat_fframe_locals_offset;
    config.layout = {profile.chat_sender_offset, profile.chat_text_offset,
                     profile.reflection_admin_sender_uid_offset};
    // The BroadcastChatMessage UFunction may not be registered at the instant
    // GEngine goes valid (class registration lags engine construction), so the
    // resolver can miss its Func slot on the first try. Retry until it resolves,
    // bounded by a deadline — install() is a no-op that fails cleanly when the
    // slot isn't found yet, so re-attempting is safe.
    JsonLog::instance().write(JsonLog::Level::Info, "reflection.chat_resolving",
                              "scanning for BroadcastChatMessage UFunction::Func slot");
    std::string chat_error;
    bool chat_ok = false;
    const auto chat_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(180);
    while (std::chrono::steady_clock::now() < chat_deadline) {
      if (chat_hook_.install(config, resolver, make_chat_deliver(), chat_error)) {
        chat_ok = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (chat_ok) {
      installed_any = true;
      JsonLog::instance().write(JsonLog::Level::Info, "hook.chat_installed",
          "reflection chat hook installed on BroadcastChatMessage");
    } else {
      JsonLog::instance().write(JsonLog::Level::Warn, "hook.chat_unavailable", chat_error);
    }
  }

  if (!installed_any) {
    g_active_reflection = nullptr;
    callbacks_ = {};
    error = "reflection backend: no hooks available (no reflection layout or chat facts)";
    return false;
  }
  return true;
}

ChatDeliver ReflectionHookBackend::make_chat_deliver() {
  return [this](const DecodedChat& chat) -> bool {
    JsonLog::instance().write(JsonLog::Level::Info, "chat.observed", "chat decoded",
                              {{"text", chat.event.text}, {"source", chat.event.source}});
    // Observation: every chat broadcast becomes a "chat" event for subscribers.
    if (callbacks_.on_event) callbacks_.on_event(chat.event);
    // Command recognition: only `!`-prefixed messages are mod commands. A cheap
    // front-char check keeps normal chat off the (expensive) admin-resolve path.
    const std::string& text = chat.event.text;
    if (text.size() < 2 || text.front() != '!' || !callbacks_.on_chat) return false;
    // Resolve the sender's server-side admin status from their Guid.
    AuthState auth = AuthState::Unknown;
    if (chat.has_sender_uid && admin_layout_.configured() &&
        object_layout_.configured()) {
      const ObjectArray objects(object_layout_, fname_pool_);
      auth = resolve_player_auth(objects, admin_layout_, chat.sender_uid.data());
    }
    const int auth_code = auth == AuthState::Admin ? 2 : (auth == AuthState::Player ? 1 : 0);
    // A sender we positively identified via their controller (auth != Unknown) is
    // definitely connected, so register them in the player directory. This is how
    // the reflection backend populates it (no dedicated join hook yet) — and it
    // lets GiveItem's target resolution find a player who has issued a command,
    // e.g. an admin granting an item to themselves.
    if (auth != AuthState::Unknown && chat.has_sender_uid && callbacks_.on_player_join) {
      callbacks_.on_player_join(
          bytes_to_hex(chat.sender_uid.data(), chat.sender_uid.size()),
          chat.event.source, /*handle=*/0);
    }
    // Translate the `!` mod prefix to the router's `/` and route synchronously.
    std::string command = "/" + text.substr(1);
    JsonLog::instance().write(
        JsonLog::Level::Info, "chat.command", "mod command received; routing",
        {{"source", chat.event.source},
         {"auth", auth == AuthState::Admin  ? "admin"
                  : auth == AuthState::Player ? "player"
                                              : "unknown"},
         {"has_sender_uid", chat.has_sender_uid ? "true" : "false"}});
    return callbacks_.on_chat(command, chat.event.source, /*handle=*/0, auth_code);
  };
}

bool ReflectionHookBackend::execute_action(const SemanticAction& action,
                                           std::string& error) {
  if (action.kind == ActionKind::CallFunction) {
    return execute_call(action, error);
  }
  error = "reflection backend: only generic CallFunction actions are supported";
  return false;
}

bool ReflectionHookBackend::execute_call(const SemanticAction& action,
                                         std::string& error) {
  if (process_event_slot_ == 0 || !object_layout_.configured() || !fname_pool_.valid()) {
    error = "generic call: ProcessEvent slot / object array / FName pool missing";
    return false;
  }
  // Parse "/Script/Pkg.Class:Func" into the owning class + function name.
  const std::string& path = action.function_path;
  const auto colon = path.rfind(':');
  const std::string func = colon == std::string::npos ? path : path.substr(colon + 1);
  std::string owner;
  if (colon != std::string::npos) {
    const std::string class_path = path.substr(0, colon);
    const auto dot = class_path.rfind('.');
    owner = dot == std::string::npos ? class_path : class_path.substr(dot + 1);
  }
  const std::string target_class = action.target_class.empty() ? owner : action.target_class;

  const ObjectArray objects(object_layout_, fname_pool_);
  const std::uint64_t ufunction = objects.find_function(func, owner);
  if (ufunction == 0) {
    error = "generic call: UFunction not found: " + path;
    return false;
  }
  // A specific object handle wins; otherwise the first live instance of the class.
  std::uint64_t target = action.target_object;
  if (target == 0) {
    target = objects.find(target_class);
    if (target == 0) {
      error = "generic call: no live instance of " + target_class;
      return false;
    }
  }
  // Read the function's parameter layout live from reflection (no baked offsets).
  const StructLayout layout = read_struct_layout(ufunction, fname_pool_);
  const FNamePool pool = fname_pool_;
  const FNameEncoder encode = [pool](const std::string& name) { return pool.lookup(name); };
  EncodedParms encoded =
      encode_parms(layout.size + 0x40, layout.fields, action.call_args, encode);
  const std::uint64_t process_event = read_vtable_slot(target, process_event_slot_);
  if (process_event == 0) {
    error = "generic call: could not read ProcessEvent from the target vtable";
    return false;
  }
  call_process_event(process_event, target, ufunction, encoded.data());
  JsonLog::instance().write(JsonLog::Level::Info, "action.call",
                            "generic UFunction call dispatched",
                            {{"function", path}, {"target", target_class}});
  return true;
}

bool ReflectionHookBackend::install_generic_hook(const GenericHookSpec& spec_in,
                                                 std::string& error) {
  if (!resolver_) {
    error = "reflection backend has no resolver; profile lacks reflection facts";
    return false;
  }
  if (!callbacks_.on_event) {
    error = "reflection backend has no event sink to deliver generic hooks";
    return false;
  }
  // Resolve the hook target live by name — the same path generic calls use: find
  // the UFunction in GUObjectArray, take its Func slot (UFunction + func_offset)
  // as the swap target, and read its parameter layout live. No baked catalog.
  GenericHookSpec spec = spec_in;
  if (spec.thunk_va == 0 && spec.func_slot_va == 0) {
    if (!object_layout_.configured() || !fname_pool_.valid()) {
      error = "generic hook: object array / FName pool missing for live resolution";
      return false;
    }
    const ObjectArray objects(object_layout_, fname_pool_);
    const std::uint64_t ufunction = objects.find_function(spec.name, "");
    if (ufunction == 0) {
      error = "generic hook: UFunction not found: " + spec.name;
      return false;
    }
    spec.func_slot_va = ufunction + resolver_->func_offset;
    spec.params = read_struct_layout(ufunction, fname_pool_).fields;
  }
  // Resolve NameProperty args to strings when the profile supplies the FName
  // pool; otherwise they fall back to their numeric index.
  FNameResolver resolve_fname;
  if (fname_pool_.valid()) {
    const FNamePool pool = fname_pool_;
    resolve_fname = [pool](std::uint32_t index) { return pool.resolve(index); };
  }
  auto on_event = callbacks_.on_event;
  const int id = generic_hooks_.install(
      spec, *resolver_, std::move(resolve_fname),
      [on_event](const GenericEvent& decoded) {
        PluginEvent event;
        event.kind = decoded.name;
        event.args = decoded.args;
        on_event(event);
      },
      error);
  if (id < 0) return false;
  JsonLog::instance().write(JsonLog::Level::Info, "hook.generic_installed",
                            "reflection generic hook installed", {{"function", spec.name}});
  return true;
}

void ReflectionHookBackend::uninstall() {
  generic_hooks_.uninstall_all();
  chat_hook_.uninstall();
  tick_hook_.uninstall();
  resolver_.reset();
  fname_pool_ = FNamePool{};
  callbacks_ = {};
  if (g_active_reflection == this) g_active_reflection = nullptr;
}

void ReflectionHookBackend::tick_trampoline(void* engine, float delta_seconds,
                                            bool idle_mode) {
  auto* self = g_active_reflection;
  if (self == nullptr) return;
  // Drain the action queue here — we are on the game thread once per frame.
  if (self->callbacks_.on_game_tick) self->callbacks_.on_game_tick();
  void* original_bits = self->tick_hook_.original();
  if (original_bits != nullptr) {
    TickFn original = nullptr;
    std::memcpy(&original, &original_bits, sizeof original);
    if (original != nullptr) original(engine, delta_seconds, idle_mode);
  }
}

}  // namespace palmod
