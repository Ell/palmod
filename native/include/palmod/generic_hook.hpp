#pragma once

#include "palmod/parms_decode.hpp"
#include "palmod/pointer_slot_hook.hpp"
#include "palmod/reflection_resolver.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace palmod {

// A decoded call of any hooked UFunction: the function name plus its arguments
// decoded from the reflection param layout. This is the generic analogue of the
// chat-specific PluginEvent — one shape for every by-name hook.
struct GenericEvent {
  std::string name;
  std::vector<EventArg> args;
};

using GenericDeliver = std::function<void(const GenericEvent&)>;

// What to hook and how to decode it. The target is normally resolved live by
// name (find the UFunction in GUObjectArray; its Func slot is the swap target and
// its parameter layout is read live) — set `name` and leave the rest empty. The
// `thunk_va` exec-thunk path is a legacy fallback (used by unit tests that supply
// a pre-known thunk); `func_slot_va` is a pre-resolved Func slot.
struct GenericHookSpec {
  std::uint64_t thunk_va{0};        // legacy: resolve the Func slot from this thunk
  std::uint64_t func_slot_va{0};    // pre-resolved UFunction::Func slot (live path)
  std::size_t fframe_locals_offset{0x18};
  std::string name;                 // function name, becomes GenericEvent::name
  std::vector<ParamSpec> params;    // param layout (read live from reflection)
};

// Installs reflection (UFunction::Func) hooks on arbitrary functions by name.
// Every hook swaps its Func slot to one of a fixed pool of distinct trampoline
// stubs; the stub's compile-time index routes the call back to the right entry
// (so the many identical-signature exec thunks stay distinguishable without
// reversing FFrame.Node). Observation-only: the original is always chained.
class GenericHookTable {
 public:
  static constexpr int kCapacity = 128;

  GenericHookTable();
  ~GenericHookTable();
  GenericHookTable(const GenericHookTable&) = delete;
  GenericHookTable& operator=(const GenericHookTable&) = delete;

  // Returns a hook id (>= 0) or -1 with `error` set. `resolve_fname` may be empty
  // (NameProperty args then fall back to their numeric index).
  int install(const GenericHookSpec& spec, const ReflectionResolver& resolver,
              FNameResolver resolve_fname, GenericDeliver deliver,
              std::string& error);
  void uninstall(int id);
  void uninstall_all();
  int active_count() const;

 private:
  struct Entry {
    bool active{false};
    GenericHookSpec spec;
    FNameResolver resolve_fname;
    GenericDeliver deliver;
    PointerSlotHook hook;
  };

  using ThunkFn = void (*)(void*, void*, void*);
  template <std::size_t I>
  static void stub(void* context, void* fframe, void* result);
  template <std::size_t... I>
  static std::array<ThunkFn, sizeof...(I)> make_stubs(std::index_sequence<I...>);
  static const std::array<ThunkFn, kCapacity>& stubs();
  void dispatch(std::size_t index, void* context, void* fframe, void* result);

  std::array<Entry, kCapacity> entries_{};
};

}  // namespace palmod
