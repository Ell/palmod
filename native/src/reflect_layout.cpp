#include "palmod/reflect_layout.hpp"

#include "palmod/invoke.hpp"  // try_read_u64, try_read_bytes

namespace palmod {
namespace {

// UE 5.1 FField / FProperty / UStruct offsets (build 24088465, confirmed by the
// reflection dumper). See docs/design/reflection-mappings.md.
constexpr std::uint64_t kUStructChildProps = 0x50;  // FField* ChildProperties
constexpr std::uint64_t kFFieldClass = 0x08;        // FFieldClass* (FName @ +0)
constexpr std::uint64_t kFFieldNext = 0x20;         // FField* Next
constexpr std::uint64_t kFFieldName = 0x28;         // FName NamePrivate
constexpr std::uint64_t kFPropElemSize = 0x38;      // int32 ElementSize
constexpr std::uint64_t kFPropOffset = 0x4c;        // int32 Offset_Internal
constexpr std::uint64_t kFPropInner = 0x78;         // Struct / Inner FProperty

constexpr int kMaxDepth = 8;
constexpr int kMaxFields = 512;

// Heap pointers on this build live in the 0x7f... canonical band; the check
// rejects small/packed non-pointer words so a bad field can't derail the walk.
bool looks_like_pointer(std::uint64_t value) { return (value >> 40) == 0x7f; }

std::uint32_t read_u32(std::uint64_t va) {
  std::uint64_t value = 0;
  if (!try_read_bytes(va, &value, sizeof(std::uint32_t))) return 0;
  return static_cast<std::uint32_t>(value);
}

std::string type_name(const FNamePool& names, std::uint64_t field_va) {
  std::uint64_t field_class = 0;
  if (!try_read_u64(field_va + kFFieldClass, field_class) || field_class == 0) return {};
  return names.resolve(read_u32(field_class));  // FFieldClass FName @ +0x00
}

}  // namespace

StructLayout read_struct_layout(std::uint64_t struct_va, const FNamePool& names,
                                int depth) {
  StructLayout layout;
  if (struct_va == 0 || depth > kMaxDepth) return layout;

  std::uint64_t field = 0;
  try_read_u64(struct_va + kUStructChildProps, field);
  int seen = 0;
  while (looks_like_pointer(field) && seen < kMaxFields) {
    ParamSpec spec;
    spec.type = type_name(names, field);
    spec.name = names.resolve(read_u32(field + kFFieldName));
    spec.offset = read_u32(field + kFPropOffset);
    const std::uint32_t elem_size = read_u32(field + kFPropElemSize);

    if (spec.type == "StructProperty") {
      std::uint64_t struct_ref = 0;
      try_read_u64(field + kFPropInner, struct_ref);
      if (looks_like_pointer(struct_ref)) {
        spec.fields = read_struct_layout(struct_ref, names, depth + 1).fields;
      }
    } else if (spec.type == "ArrayProperty") {
      std::uint64_t inner = 0;
      try_read_u64(field + kFPropInner, inner);
      if (looks_like_pointer(inner)) {
        spec.inner_type = type_name(names, inner);
        spec.inner_size = read_u32(inner + kFPropElemSize);
        if (spec.inner_type == "StructProperty") {
          std::uint64_t element_struct = 0;
          try_read_u64(inner + kFPropInner, element_struct);
          if (looks_like_pointer(element_struct)) {
            spec.fields = read_struct_layout(element_struct, names, depth + 1).fields;
          }
        }
      }
    }

    const std::size_t end = spec.offset + elem_size;
    if (end > layout.size) layout.size = end;
    layout.fields.push_back(std::move(spec));

    std::uint64_t next = 0;
    try_read_u64(field + kFFieldNext, next);
    field = next;
    ++seen;
  }

  // Round the span up to 16 so any alignment padding a caller relies on is
  // covered.
  layout.size = (layout.size + 15) & ~std::size_t{15};
  return layout;
}

std::optional<ParamSpec> find_property(std::uint64_t struct_va, std::string_view name,
                                       const FNamePool& names,
                                       std::uint64_t super_offset) {
  std::uint64_t level = struct_va;
  for (int depth = 0; looks_like_pointer(level) && depth <= kMaxDepth * 8; ++depth) {
    StructLayout layout = read_struct_layout(level, names, 0);
    for (auto& field : layout.fields) {
      if (field.name == name) return field;  // absolute Offset_Internal
    }
    if (super_offset == 0) break;
    std::uint64_t super = 0;
    if (!try_read_u64(level + super_offset, super)) break;
    level = super;
  }
  return std::nullopt;
}

}  // namespace palmod
