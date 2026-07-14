#include "palmod/object_array.hpp"

#include <cctype>
#include <cstring>

namespace palmod {
namespace {

constexpr std::uint64_t kCanonicalLimit = std::uint64_t{1} << 48;
constexpr std::size_t kMaxObjects = 8'000'000;   // sanity bound
constexpr std::size_t kMaxSuperDepth = 64;       // class-chain guard

// Case-insensitive compare — UE FNames are case-insensitive, and pal.hook/on_event
// subscriptions arrive canonicalized to lowercase while the live UFunction keeps
// its original casing (e.g. "AddItem_ServerInternal").
bool iequal(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// Direct reads. The walk touches ~155k objects, so a per-read syscall
// (process_vm_readv) is far too slow — the call path runs on the game thread
// where UObjects are stable, and the canonical-address guard rejects obvious
// garbage before a dereference.
bool read_u64(std::uint64_t va, std::uint64_t& out) {
  if (va == 0 || va >= kCanonicalLimit) return false;
  std::memcpy(&out, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(va)),
              sizeof(out));
  return true;
}

bool read_i32(std::uint64_t va, std::int32_t& out) {
  if (va == 0 || va >= kCanonicalLimit) return false;
  std::memcpy(&out, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(va)),
              sizeof(out));
  return true;
}

}  // namespace

std::size_t ObjectArray::for_each(
    const std::function<bool(std::uint64_t)>& visit) const {
  if (!layout_.configured() || !visit) return 0;
  std::uint64_t chunk_array = 0;
  if (!read_u64(layout_.objects_va, chunk_array) || chunk_array == 0) return 0;
  std::int32_t num = 0;
  if (!read_i32(layout_.objects_va + layout_.num_elements_offset, num)) return 0;
  if (num <= 0 || static_cast<std::size_t>(num) > kMaxObjects) return 0;

  std::size_t visited = 0;
  for (std::size_t i = 0; i < static_cast<std::size_t>(num); ++i) {
    const std::size_t chunk_i = i / layout_.elements_per_chunk;
    const std::size_t within = i % layout_.elements_per_chunk;
    std::uint64_t chunk = 0;
    if (!read_u64(chunk_array + chunk_i * sizeof(std::uint64_t), chunk) || chunk == 0) {
      continue;
    }
    std::uint64_t object = 0;
    if (!read_u64(chunk + within * layout_.item_size, object) || object == 0) continue;
    ++visited;
    if (!visit(object)) break;
  }
  return visited;
}

std::string ObjectArray::class_name(std::uint64_t object) const {
  std::uint64_t cls = 0;
  if (!read_u64(object + layout_.class_offset, cls) || cls == 0) return {};
  if (const auto it = class_name_cache_.find(cls); it != class_name_cache_.end()) {
    return it->second;
  }
  std::int32_t cmp = 0;
  std::string name;
  if (read_i32(cls + layout_.name_offset, cmp) && cmp > 0) {
    name = names_.resolve(static_cast<std::uint32_t>(cmp));
  }
  class_name_cache_.emplace(cls, name);
  return name;
}

std::string ObjectArray::object_name(std::uint64_t object) const {
  std::int32_t cmp = 0;
  if (!read_i32(object + layout_.name_offset, cmp) || cmp <= 0) return {};
  return names_.resolve(static_cast<std::uint32_t>(cmp));
}

bool ObjectArray::is_a(std::uint64_t object, std::string_view base_class) const {
  std::uint64_t cls = 0;
  if (!read_u64(object + layout_.class_offset, cls) || cls == 0) return false;
  if (layout_.super_offset == 0) {
    return class_name(object) == base_class;  // exact match when IsA is disabled
  }
  for (std::size_t depth = 0; cls != 0 && depth < kMaxSuperDepth; ++depth) {
    std::int32_t cmp = 0;
    if (read_i32(cls + layout_.name_offset, cmp) && cmp > 0 &&
        names_.resolve(static_cast<std::uint32_t>(cmp)) == base_class) {
      return true;
    }
    std::uint64_t super = 0;
    if (!read_u64(cls + layout_.super_offset, super)) break;
    cls = super;
  }
  return false;
}

std::uint64_t ObjectArray::find(
    std::string_view base_class,
    const std::function<bool(std::uint64_t)>& predicate) const {
  std::uint64_t found = 0;
  for_each([&](std::uint64_t object) {
    if (!is_a(object, base_class)) return true;
    const std::string name = object_name(object);
    if (name.rfind("Default__", 0) == 0) return true;  // skip CDOs
    if (predicate && !predicate(object)) return true;
    found = object;
    return false;  // stop
  });
  return found;
}

std::uint64_t ObjectArray::find_function(std::string_view func_name,
                                         std::string_view outer_class) const {
  std::uint64_t found = 0;
  for_each([&](std::uint64_t object) {
    if (class_name(object) != "Function") return true;
    if (!iequal(object_name(object), func_name)) return true;
    if (!outer_class.empty()) {
      std::uint64_t outer = 0;
      if (!read_u64(object + layout_.outer_offset, outer) || outer == 0) return true;
      if (!iequal(object_name(outer), outer_class)) return true;
    }
    found = object;
    return false;  // stop
  });
  return found;
}

}  // namespace palmod
