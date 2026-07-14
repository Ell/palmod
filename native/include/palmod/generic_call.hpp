#pragma once

#include "palmod/parms_decode.hpp"   // ParamSpec
#include "palmod/parms_encode.hpp"   // ParamInput, FNameEncoder
#include "palmod/reflection_resolver.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace palmod {

// Everything needed to call a UFunction by name, all from reflection: the exec
// thunk (to resolve the live UFunction object, shared with the hook path), the
// Parms size, and the parameter layout.
struct GenericCallSpec {
  std::uint64_t thunk_va{0};
  std::size_t parms_size{0};
  std::vector<ParamSpec> params;
};

// The write-side counterpart to the generic hook: resolve the UFunction object
// from its exec thunk (`slot - func_offset`), encode the Parms from `inputs`, and
// dispatch via `UObject::ProcessEvent(function, parms)` on `target`. Fail-closed —
// returns false with `error` set if the function can't be resolved or the target
// has no ProcessEvent at `process_event_slot`. Every address/offset is derived
// from reflection + the profile; nothing here is hardcoded.
//
// NOTE: this MUTATES game state, so correctness must be validated against a live
// server before it is trusted — the mechanism is unit-tested, the wiring is not
// a substitute for that validation.
bool call_ufunction(const GenericCallSpec& spec, const ReflectionResolver& resolver,
                    std::uint64_t target, std::size_t process_event_slot,
                    const std::vector<ParamInput>& inputs,
                    const FNameEncoder& encode_fname, std::string& error);

}  // namespace palmod
