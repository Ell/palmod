#pragma once

#include "palmod/parms_decode.hpp"  // ParamSpec

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <vector>

namespace palmod {

// A typed value to write into a Parms buffer for one named parameter. Mirrors
// the decoded `EventArg`: a scalar/text leaf, an ordered list (`is_array`), or a
// struct's named members (`is_struct`, members carry their own `name`).
struct ParamInput {
  std::string name;
  bool is_text{false};
  std::string text;    // for StrProperty / NameProperty
  double number{0.0};  // for numeric/bool/enum properties
  bool is_array{false};
  bool is_struct{false};
  std::vector<ParamInput> items;
};

// string -> FName ComparisonIndex (a reverse lookup against the live name pool).
// Returns 0 when the name is not present.
using FNameEncoder = std::function<std::uint32_t(const std::string&)>;

// An encoded Parms buffer plus the heap buffers its FStrings/TArrays point into.
// `parms` holds pointers into `pools`; a std::deque never invalidates references
// to existing elements on push_back, so those pointers stay valid as more pools
// are added. Keep the whole object alive for the duration of the call.
struct EncodedParms {
  std::vector<std::uint8_t> parms;
  std::deque<std::vector<std::uint8_t>> pools;

  void* data() { return parms.data(); }
  const void* data() const { return parms.data(); }
  std::size_t size() const { return parms.size(); }
};

// The write-side inverse of `decode_parms`: build a zero-initialized `Parms`
// buffer of `parms_size` and place each input's value at its parameter's
// reflected byte offset. Handles scalars, NameProperty (via `encode_fname`),
// StrProperty (allocates a UTF-16 buffer), StructProperty (recursive), and
// ArrayProperty (of scalars or structs). The layout comes entirely from
// reflection — no hardcoded offsets — so this drives calling any UFunction by
// name with arbitrary arguments.
EncodedParms encode_parms(std::size_t parms_size,
                          const std::vector<ParamSpec>& params,
                          const std::vector<ParamInput>& inputs,
                          const FNameEncoder& encode_fname = {});

}  // namespace palmod
