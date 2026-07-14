#include "palmod/generic_hook.hpp"

#include <cstring>
#include <utility>

namespace palmod {
namespace {

// The stub pool is static, so it reaches its table through this global. One
// table at a time (there is one game process); construction claims it.
GenericHookTable* g_active_table = nullptr;

}  // namespace

template <std::size_t I>
void GenericHookTable::stub(void* context, void* fframe, void* result) {
  if (g_active_table != nullptr) {
    g_active_table->dispatch(I, context, fframe, result);
  }
}

template <std::size_t... I>
std::array<GenericHookTable::ThunkFn, sizeof...(I)> GenericHookTable::make_stubs(
    std::index_sequence<I...>) {
  return {&GenericHookTable::stub<I>...};
}

const std::array<GenericHookTable::ThunkFn, GenericHookTable::kCapacity>&
GenericHookTable::stubs() {
  static const auto table = make_stubs(std::make_index_sequence<kCapacity>{});
  return table;
}

GenericHookTable::GenericHookTable() {
  if (g_active_table == nullptr) g_active_table = this;
}

GenericHookTable::~GenericHookTable() {
  uninstall_all();
  if (g_active_table == this) g_active_table = nullptr;
}

int GenericHookTable::install(const GenericHookSpec& spec,
                              const ReflectionResolver& resolver,
                              FNameResolver resolve_fname, GenericDeliver deliver,
                              std::string& error) {
  if (g_active_table != this) {
    error = "another GenericHookTable already owns the stub pool";
    return -1;
  }
  if ((spec.thunk_va == 0 && spec.func_slot_va == 0) || !deliver) {
    error = "generic hook requires a thunk or slot address and a deliver callback";
    return -1;
  }
  int id = -1;
  for (int i = 0; i < kCapacity; ++i) {
    if (!entries_[static_cast<std::size_t>(i)].active) {
      id = i;
      break;
    }
  }
  if (id < 0) {
    error = "generic hook table is full";
    return -1;
  }

  // A live-resolved Func slot wins; otherwise resolve it from the exec-thunk VA.
  void** slot = spec.func_slot_va != 0
                    ? reinterpret_cast<void**>(static_cast<std::uintptr_t>(spec.func_slot_va))
                    : resolver.resolve(spec.thunk_va, error);
  if (slot == nullptr) return -1;  // error set by resolve()

  auto& entry = entries_[static_cast<std::size_t>(id)];
  entry.spec = spec;
  entry.resolve_fname = std::move(resolve_fname);
  entry.deliver = std::move(deliver);

  ThunkFn stub_fn = stubs()[static_cast<std::size_t>(id)];
  void* stub_bits = nullptr;
  std::memcpy(&stub_bits, &stub_fn, sizeof(stub_bits));
  if (!entry.hook.install(slot, stub_bits, error)) {
    entry.deliver = {};
    entry.resolve_fname = {};
    return -1;
  }
  entry.active = true;
  return id;
}

void GenericHookTable::uninstall(int id) {
  if (id < 0 || id >= kCapacity) return;
  auto& entry = entries_[static_cast<std::size_t>(id)];
  if (!entry.active) return;
  entry.hook.uninstall();
  entry.deliver = {};
  entry.resolve_fname = {};
  entry.active = false;
}

void GenericHookTable::uninstall_all() {
  for (int i = 0; i < kCapacity; ++i) uninstall(i);
}

int GenericHookTable::active_count() const {
  int count = 0;
  for (const auto& entry : entries_) {
    if (entry.active) ++count;
  }
  return count;
}

void GenericHookTable::dispatch(std::size_t index, void* context, void* fframe,
                                void* result) {
  auto& entry = entries_[index];
  if (entry.active && fframe != nullptr && entry.deliver) {
    const auto* base = static_cast<const std::uint8_t*>(fframe);
    const void* locals = nullptr;
    std::memcpy(&locals, base + entry.spec.fframe_locals_offset, sizeof(locals));
    if (locals != nullptr) {
      GenericEvent event;
      event.name = entry.spec.name;
      event.args = decode_parms(locals, entry.spec.params, entry.resolve_fname);
      entry.deliver(event);
    }
  }

  // Always chain the original exec thunk (observation-only).
  void* original_bits = entry.hook.original();
  if (original_bits != nullptr) {
    ThunkFn original = nullptr;
    std::memcpy(&original, &original_bits, sizeof(original));
    if (original != nullptr) original(context, fframe, result);
  }
}

}  // namespace palmod
