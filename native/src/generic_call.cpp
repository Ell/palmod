#include "palmod/generic_call.hpp"

#include "palmod/invoke.hpp"

#include <cstdint>

namespace palmod {

bool call_ufunction(const GenericCallSpec& spec, const ReflectionResolver& resolver,
                    std::uint64_t target, std::size_t process_event_slot,
                    const std::vector<ParamInput>& inputs,
                    const FNameEncoder& encode_fname, std::string& error) {
  if (spec.thunk_va == 0) {
    error = "generic call requires a UFunction exec-thunk address";
    return false;
  }
  if (target == 0) {
    error = "generic call requires a non-null target object";
    return false;
  }
  void** slot = resolver.resolve(spec.thunk_va, error);
  if (slot == nullptr) return false;  // error set by resolve()

  // The UFunction object is `func_offset` bytes before its Func slot.
  const auto slot_va = reinterpret_cast<std::uintptr_t>(slot);
  if (slot_va < resolver.func_offset) {
    error = "resolved UFunction slot is below the function offset";
    return false;
  }
  const std::uint64_t function_va = slot_va - resolver.func_offset;

  const std::uint64_t process_event_va = read_vtable_slot(target, process_event_slot);
  if (process_event_va == 0) {
    error = "could not read ProcessEvent from the target object's vtable";
    return false;
  }

  auto parms = encode_parms(spec.parms_size, spec.params, inputs, encode_fname);
  call_process_event(process_event_va, target, function_va, parms.data());
  return true;
}

}  // namespace palmod
