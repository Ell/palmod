#pragma once

#include "palmod/fname_pool.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace palmod {

// Layout of the live `GUObjectArray` (FChunkedFixedUObjectArray) + the UObject
// header fields, all from reflection (build 24088465 defaults shown). `super_off`
// (UStruct::SuperStruct) enables an IsA check up the class chain; 0 falls back to
// an exact class-name match.
struct ObjectArrayLayout {
  std::uint64_t objects_va{0};        // GUObjectArray.ObjObjects.Objects (FUObjectItem**)
  std::size_t num_elements_offset{0x14};
  std::size_t elements_per_chunk{64 * 1024};
  std::size_t item_size{24};          // sizeof(FUObjectItem)
  std::size_t class_offset{0x10};     // UObject::ClassPrivate
  std::size_t name_offset{0x18};      // UObject::NamePrivate (FName cmp index, i32)
  std::size_t outer_offset{0x20};     // UObject::OuterPrivate
  std::size_t super_offset{0};        // UStruct::SuperStruct (0 = IsA disabled)

  bool configured() const { return objects_va != 0; }
};

// Walks the live object array in-process to find UObjects by class — the "find
// the target `this`" primitive for the mutation path (e.g. locate a player's
// inventory), and the basis for a generic `pal.find_object`. Everything is driven
// by reflection offsets; nothing is hardcoded per game object.
class ObjectArray {
 public:
  ObjectArray(ObjectArrayLayout layout, FNamePool names)
      : layout_(layout), names_(names) {}

  // Visit every live UObject VA; stops early if `visit` returns false. Returns
  // the number visited.
  std::size_t for_each(const std::function<bool(std::uint64_t)>& visit) const;

  // The class name of `object` ("" on failure), cached by class pointer.
  std::string class_name(std::uint64_t object) const;

  // The object's own name ("" on failure).
  std::string object_name(std::uint64_t object) const;

  // True if `object`'s class is `base_class` or (when super_offset is set) derives
  // from it via the SuperStruct chain.
  bool is_a(std::uint64_t object, std::string_view base_class) const;

  // First live non-CDO object that is-a `base_class` and passes `predicate`
  // (default: accept any). Returns the object VA, or 0 if none. CDOs
  // (`Default__...`) are skipped.
  std::uint64_t find(std::string_view base_class,
                     const std::function<bool(std::uint64_t)>& predicate = {}) const;

  // First UFunction named `func_name` whose owning class (Outer) is named
  // `outer_class` (or any owner when `outer_class` is empty). Returns the
  // UFunction VA, or 0. This is the by-name resolution for a generic call.
  std::uint64_t find_function(std::string_view func_name,
                              std::string_view outer_class) const;

 private:
  ObjectArrayLayout layout_;
  FNamePool names_;
  mutable std::unordered_map<std::uint64_t, std::string> class_name_cache_;
};

}  // namespace palmod
