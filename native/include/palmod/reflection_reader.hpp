#pragma once

#include "palmod/object_array.hpp"
#include "palmod/parms_decode.hpp"  // EventArg

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace palmod {

// Read-side reflection for plugins: find live objects by class/name and read
// their properties — the `pal.find_object`/`find_all_of`/`get` primitives. Every
// access is fault-safe (process_vm_readv), so a plugin can call it off the game
// thread without risking a crash on a freed/racing object. Built from the same
// profile facts the generic call path uses; disabled (ops return empty) when the
// object-array facts are absent.
class ReflectionReader {
 public:
  ReflectionReader() = default;
  ReflectionReader(ObjectArrayLayout layout, FNamePool names)
      : layout_(layout), names_(names) {}

  bool enabled() const { return layout_.configured() && names_.valid(); }

  // First live non-CDO object that is-a `class_name` (and is named `name` when
  // `name` is non-empty). Returns the object VA, or 0.
  std::uint64_t find_object(std::string_view class_name, std::string_view name) const;

  // Up to `max` live non-CDO objects that are-a `class_name`.
  std::vector<std::uint64_t> find_all_of(std::string_view class_name,
                                         std::size_t max) const;

  // Read property `prop` from object `obj`, resolving the class + super chain.
  // Returns the decoded value (scalar/text/array/struct), or nullopt if absent.
  std::optional<EventArg> get_property(std::uint64_t obj, std::string_view prop) const;

  // The object's class name ("" on failure).
  std::string class_of(std::uint64_t obj) const;

  // Row-name keys of a UDataTable's RowMap. RowMap is a TMap<FName, uint8*> and is
  // NOT a reflected UPROPERTY, so it is read at the fixed UDataTable layout. Up to
  // `max` names (skips free/None slots). Works for any DataTable (items, recipes…).
  std::vector<std::string> datatable_rows(std::uint64_t datatable, std::size_t max) const;

 private:
  ObjectArrayLayout layout_;
  FNamePool names_;
};

}  // namespace palmod
