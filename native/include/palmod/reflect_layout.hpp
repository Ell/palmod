#pragma once

#include "palmod/fname_pool.hpp"
#include "palmod/parms_decode.hpp"  // ParamSpec

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace palmod {

// A struct/function's member layout read live from reflection, plus the byte span
// it occupies (a safe Parms buffer size).
struct StructLayout {
  std::vector<ParamSpec> fields;
  std::size_t size{0};
};

// Walk a UStruct's (a UFunction or UScriptStruct at `struct_va`) ChildProperties
// into a ParamSpec list, reading each FProperty's type (FFieldClass name),
// `Offset_Internal`, and `ElementSize` live — recursing into StructProperty and
// resolving ArrayProperty inner type/size (+ element struct fields). Names come
// from the FName pool. Every read is fault-safe and depth-bounded, so a bad
// pointer yields a truncated layout rather than a crash. This is the
// reflection-mappings endgame: offsets are never hardcoded, they are read from
// the engine's own metadata at call time, so any function is callable by name.
StructLayout read_struct_layout(std::uint64_t struct_va, const FNamePool& names,
                                int depth = 0);

// Find a property named `name` in a UStruct/UClass, walking the SuperStruct chain
// (`super_offset`) so inherited properties resolve too. Returns its ParamSpec
// (with the absolute Offset_Internal), or nullopt. Fault-safe + bounded.
std::optional<ParamSpec> find_property(std::uint64_t struct_va, std::string_view name,
                                       const FNamePool& names,
                                       std::uint64_t super_offset);

}  // namespace palmod
