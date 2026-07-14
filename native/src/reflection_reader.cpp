#include "palmod/reflection_reader.hpp"

#include "palmod/invoke.hpp"  // try_read_u64
#include "palmod/reflect_layout.hpp"

namespace palmod {

std::uint64_t ReflectionReader::find_object(std::string_view class_name,
                                            std::string_view name) const {
  if (!enabled() || class_name.empty()) return 0;
  const ObjectArray objects(layout_, names_);
  if (name.empty()) return objects.find(class_name);
  return objects.find(class_name, [&objects, name](std::uint64_t obj) {
    return objects.object_name(obj) == name;
  });
}

std::vector<std::uint64_t> ReflectionReader::find_all_of(std::string_view class_name,
                                                         std::size_t max) const {
  std::vector<std::uint64_t> found;
  if (!enabled() || class_name.empty() || max == 0) return found;
  const ObjectArray objects(layout_, names_);
  objects.for_each([&](std::uint64_t obj) {
    if (!objects.is_a(obj, class_name)) return true;
    if (objects.object_name(obj).rfind("Default__", 0) == 0) return true;  // skip CDOs
    found.push_back(obj);
    return found.size() < max;
  });
  return found;
}

std::optional<EventArg> ReflectionReader::get_property(std::uint64_t obj,
                                                       std::string_view prop) const {
  if (!enabled() || obj == 0) return std::nullopt;
  std::uint64_t class_va = 0;
  if (!try_read_u64(obj + layout_.class_offset, class_va) || class_va == 0) {
    return std::nullopt;
  }
  const auto spec = find_property(class_va, prop, names_, layout_.super_offset);
  if (!spec) return std::nullopt;
  const FNamePool pool = names_;
  const FNameResolver resolve = [pool](std::uint32_t index) { return pool.resolve(index); };
  // The spec's offset is absolute within the object, so decode straight from it.
  auto decoded = decode_parms(
      reinterpret_cast<const void*>(static_cast<std::uintptr_t>(obj)), {*spec}, resolve);
  if (decoded.empty()) return std::nullopt;
  return decoded.front();
}

std::string ReflectionReader::class_of(std::uint64_t obj) const {
  if (!enabled() || obj == 0) return {};
  return ObjectArray(layout_, names_).class_name(obj);
}

std::vector<std::string> ReflectionReader::datatable_rows(std::uint64_t datatable,
                                                          std::size_t max) const {
  std::vector<std::string> rows;
  if (!enabled() || datatable == 0 || max == 0) return rows;
  // UDataTable::RowMap = TMap<FName, uint8*> @ +0x30. Its sparse-array element
  // storage is a TArray {ptr@0, Num@8, Max@0xc}; each set element is
  // {FName Key@0, uint8* Value@8, i32 HashNext, i32 HashIndex} = 0x18 bytes.
  constexpr std::uint64_t kRowMapOffset = 0x30;
  constexpr std::uint64_t kElementStride = 0x18;
  std::uint64_t data = 0;
  std::int32_t capacity = 0;
  if (!try_read_bytes(datatable + kRowMapOffset, &data, sizeof(data)) || data == 0) {
    return rows;
  }
  if (!try_read_bytes(datatable + kRowMapOffset + 0xc, &capacity, sizeof(capacity)) ||
      capacity <= 0) {
    return rows;
  }
  const std::size_t limit =
      capacity < 200000 ? static_cast<std::size_t>(capacity) : 200000;
  for (std::size_t i = 0; i < limit && rows.size() < max; ++i) {
    std::uint32_t comparison_index = 0;
    if (!try_read_bytes(data + i * kElementStride, &comparison_index,
                        sizeof(comparison_index)) ||
        comparison_index == 0) {
      continue;  // free slot / None
    }
    std::string name = names_.resolve(comparison_index);
    if (!name.empty()) rows.push_back(std::move(name));
  }
  return rows;
}

}  // namespace palmod
