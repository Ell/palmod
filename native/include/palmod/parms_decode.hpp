#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace palmod {

// One reflected parameter's layout (name, FProperty type, byte offset in Parms).
// For `ArrayProperty`, `inner_type`/`inner_size` describe the element property.
// For `StructProperty`, `fields` holds the struct's members (offsets relative to
// the struct start), decoded recursively.
struct ParamSpec {
  std::string name;
  std::string type;
  std::size_t offset{0};
  std::string inner_type;      // ArrayProperty element FProperty type
  std::size_t inner_size{0};   // ArrayProperty element size in bytes
  std::vector<ParamSpec> fields;  // StructProperty member layout
};

// A decoded argument: a number, UTF-8 text, an ordered list of scalar elements
// (`ArrayProperty` → `is_array`), or a struct's named members (`StructProperty`
// → `is_struct`, members carry their own `name`). Mirrors what Lua needs.
struct EventArg {
  std::string name;
  bool is_text{false};
  std::string text;
  double number{0.0};
  bool is_array{false};
  bool is_struct{false};
  std::vector<EventArg> items;
};

// FName index -> string (resolved against the live name pool). Optional: without
// it, NameProperty args fall back to their numeric index.
using FNameResolver = std::function<std::string(std::uint32_t)>;

// Decode a UFunction `Parms` buffer into named args using the reflection param
// layout. Handles the common FProperty types (int/float/bool/enum/str/name);
// unknown/struct/object types are skipped. This is the generic core that turns
// any hooked function's arguments into an event payload.
std::vector<EventArg> decode_parms(const void* parms,
                                   const std::vector<ParamSpec>& params,
                                   const FNameResolver& resolve_fname = {});

}  // namespace palmod
