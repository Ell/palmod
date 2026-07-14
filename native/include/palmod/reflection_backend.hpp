#pragma once

#include "palmod/chat_hook.hpp"
#include "palmod/fname_pool.hpp"
#include "palmod/generic_hook.hpp"
#include "palmod/hook_backend.hpp"
#include "palmod/object_array.hpp"
#include "palmod/player_auth.hpp"
#include "palmod/pointer_slot_hook.hpp"
#include "palmod/reflection_resolver.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace palmod {

// Builds an in-process UFunction::Func resolver from a profile's dynamically
// observed reflection facts. Returns nullopt when the profile carries none, so
// the backend fails closed on builds whose reflection layout is unconfirmed.
std::optional<ReflectionResolver> make_reflection_resolver(const BuildProfile& profile);

// Build-specific reflection facts a validated profile must supply before any
// reflection hook can be installed. An unconfigured layout means the backend
// fails closed. Only the periodic game-thread tick slot is modelled today.
//
// Chat/inventory `UFunction::Func` slots are located at runtime by
// `ReflectionResolver` (scan this process for the fixed exec-thunk pointer,
// validate the UFunction vtable at `slot - func_offset`) — so the backend needs
// only the recovered constants (func offset `0xd8`, vtable, per-target thunk
// VAs) from the profile, not a live `GUObjectArray` walk. That resolution path
// and the FFrame-decoding trampolines are the remaining work.
struct ReflectionLayout {
  void** tick_slot{nullptr};

  bool configured() const { return tick_slot != nullptr; }
};

// Data-pointer (reflection / vtable) hook backend. Preferred over inline code
// hooking: no relocator, no code patching, atomic install. Fail-closed until a
// validated ReflectionLayout is available; today the layout is injected for
// testing and must otherwise come from a validated profile.
class ReflectionHookBackend final : public HookBackend {
 public:
  explicit ReflectionHookBackend(ReflectionLayout layout = {})
      : layout_(layout) {}
  ~ReflectionHookBackend() override { uninstall(); }

  std::string_view name() const override { return "reflection"; }
  bool install(const BuildProfile& profile, HookCallbacks callbacks,
               std::string& error) override;
  bool execute_action(const SemanticAction& action, std::string& error) override;
  bool install_generic_hook(const GenericHookSpec& spec,
                            std::string& error) override;
  void uninstall() override;

 private:
  // The game-thread drain pump hooks `UEngine::Tick(float DeltaSeconds, bool
  // bIdleMode)` — a `this`call, so `this` is the first argument. Matching the ABI
  // lets the trampoline chain the real Tick correctly (UE4SS's EngineTick method,
  // via a vtable-slot swap instead of an inline hook).
  using TickFn = void (*)(void* engine, float delta_seconds, bool idle_mode);
  static void tick_trampoline(void* engine, float delta_seconds, bool idle_mode);

  // Builds the chat handler: observe (on_event) + recognize a `!`-prefixed mod
  // command, resolve the sender's server-side admin status, route it, and suppress
  // the broadcast when it matches. Runs on the game thread.
  ChatDeliver make_chat_deliver();

  // Generic call: resolve the UFunction by path in GUObjectArray, read its param
  // layout live, encode the args, find the target object by class, and dispatch
  // via ProcessEvent. No per-function native code. Game thread only.
  bool execute_call(const SemanticAction& action, std::string& error);

  ReflectionLayout layout_;
  HookCallbacks callbacks_;
  PointerSlotHook tick_hook_;
  ChatHook chat_hook_;
  std::optional<ReflectionResolver> resolver_;
  FNamePool fname_pool_;
  GenericHookTable generic_hooks_;
  // Object-array walker facts (shared by the admin check + generic calls),
  // resolved from the profile at install().
  ObjectArrayLayout object_layout_;
  AdminLayout admin_layout_;
  // Generic call: UObject::ProcessEvent vtable slot (0 = generic calls disabled).
  std::size_t process_event_slot_{0};
};

}  // namespace palmod
