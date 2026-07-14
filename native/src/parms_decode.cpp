#include "palmod/parms_decode.hpp"

#include "palmod/invoke.hpp"  // try_read_bytes
#include "palmod/utf16.hpp"

#include <optional>
#include <string_view>
#include <vector>

namespace palmod {
namespace {

constexpr std::uint64_t kCanonicalLimit = std::uint64_t{1} << 48;
constexpr std::int32_t kMaxArrayElements = 4096;

// All reads are fault-safe (process_vm_readv) so the decoder can run off the game
// thread over live objects (pal.get) without a SIGSEGV on a freed/racing pointer.
template <typename T>
T read(const std::uint8_t* base, std::size_t offset) {
  T value{};
  try_read_bytes(reinterpret_cast<std::uint64_t>(base) + offset, &value, sizeof(T));
  return value;
}

// Decode an FString {u16* data, i32 num, i32 max} at `field` to UTF-8.
std::string read_fstring(const std::uint8_t* field) {
  const auto data = read<std::uint64_t>(field, 0);
  const auto num = read<std::int32_t>(field, sizeof(std::uint64_t));
  if (data == 0 || num <= 1) return {};  // num counts the null terminator
  constexpr std::int32_t kMax = 1 << 16;
  const std::int32_t chars = num - 1 < kMax ? num - 1 : kMax;
  std::vector<char16_t> buffer(static_cast<std::size_t>(chars));
  if (!try_read_bytes(data, buffer.data(),
                      static_cast<std::size_t>(chars) * sizeof(char16_t))) {
    return {};
  }
  return utf16_to_utf8(buffer.data(), static_cast<std::size_t>(chars));
}

EventArg number_value(double value) {
  EventArg arg;
  arg.number = value;
  return arg;
}

EventArg text_value(std::string value) {
  EventArg arg;
  arg.is_text = true;
  arg.text = std::move(value);
  return arg;
}

// Decode a single scalar FProperty at `field` into a nameless EventArg, or
// nullopt if the type is not a supported scalar (struct/array/etc.).
std::optional<EventArg> decode_scalar(const std::uint8_t* field,
                                      std::string_view type,
                                      const FNameResolver& resolve_fname) {
  if (type == "IntProperty" || type == "Int32Property") {
    return number_value(read<std::int32_t>(field, 0));
  }
  if (type == "Int64Property") {
    return number_value(static_cast<double>(read<std::int64_t>(field, 0)));
  }
  if (type == "Int16Property") return number_value(read<std::int16_t>(field, 0));
  if (type == "ByteProperty" || type == "Int8Property") {
    return number_value(read<std::int8_t>(field, 0));
  }
  if (type == "UInt32Property") return number_value(read<std::uint32_t>(field, 0));
  if (type == "UInt16Property") return number_value(read<std::uint16_t>(field, 0));
  if (type == "UInt64Property") {
    return number_value(static_cast<double>(read<std::uint64_t>(field, 0)));
  }
  if (type == "ObjectProperty" || type == "ClassProperty" ||
      type == "WeakObjectProperty" || type == "InterfaceProperty") {
    // The object pointer as an opaque numeric handle (UE VAs fit a double's
    // 52-bit mantissa). Observation only — a hook can correlate, not deref.
    return number_value(static_cast<double>(read<std::uint64_t>(field, 0)));
  }
  if (type == "FloatProperty") return number_value(read<float>(field, 0));
  if (type == "DoubleProperty") return number_value(read<double>(field, 0));
  if (type == "BoolProperty") {
    return number_value(read<std::uint8_t>(field, 0) != 0 ? 1 : 0);
  }
  if (type == "EnumProperty") return number_value(read<std::uint8_t>(field, 0));
  if (type == "StrProperty") return text_value(read_fstring(field));
  if (type == "NameProperty") {
    // FName is { i32 ComparisonIndex, i32 Number }. A nonzero Number is an
    // instance suffix: the displayed name is "<base>_<Number-1>".
    const auto index = read<std::uint32_t>(field, 0);
    const auto number = read<std::int32_t>(field, sizeof(std::uint32_t));
    if (resolve_fname) {
      std::string name = resolve_fname(index);
      if (number > 0) name += "_" + std::to_string(number - 1);
      return text_value(std::move(name));
    }
    return number_value(index);
  }
  return std::nullopt;
}

constexpr int kMaxStructDepth = 8;  // guards against pathological nesting

std::vector<EventArg> decode_fields(const std::uint8_t* base,
                                    const std::vector<ParamSpec>& params,
                                    const FNameResolver& resolve_fname, int depth);

// Decode a TArray {T* data, i32 num, i32 max}. Elements are scalars, or (when
// inner_type is StructProperty and the element layout is known) nested structs.
EventArg decode_array(const std::uint8_t* field, const ParamSpec& param,
                      const FNameResolver& resolve_fname, int depth) {
  EventArg arg;
  arg.name = param.name;
  arg.is_array = true;
  const auto data = read<std::uint64_t>(field, 0);
  const auto num = read<std::int32_t>(field, sizeof(std::uint64_t));
  if (data == 0 || data >= kCanonicalLimit || num <= 0 || param.inner_size == 0) {
    return arg;  // empty / unreadable / unknown element size
  }
  const bool struct_elements =
      param.inner_type == "StructProperty" && !param.fields.empty();
  const std::int32_t count = num < kMaxArrayElements ? num : kMaxArrayElements;
  const auto* elements =
      reinterpret_cast<const std::uint8_t*>(static_cast<std::uintptr_t>(data));
  for (std::int32_t i = 0; i < count; ++i) {
    const auto* element = elements + static_cast<std::size_t>(i) * param.inner_size;
    if (struct_elements) {
      EventArg item;
      item.is_struct = true;
      if (depth < kMaxStructDepth) {
        item.items = decode_fields(element, param.fields, resolve_fname, depth + 1);
      }
      arg.items.push_back(std::move(item));
      continue;
    }
    auto scalar = decode_scalar(element, param.inner_type, resolve_fname);
    if (!scalar) break;  // non-scalar element type we can't decode: give up
    arg.items.push_back(std::move(*scalar));
  }
  return arg;
}

// Decode a flat set of fields at `base` (offsets are relative to `base`).
// Recurses into StructProperty members up to a bounded depth.
std::vector<EventArg> decode_fields(const std::uint8_t* base,
                                    const std::vector<ParamSpec>& params,
                                    const FNameResolver& resolve_fname, int depth) {
  std::vector<EventArg> args;
  for (const auto& param : params) {
    const auto* field = base + param.offset;
    if (param.type == "ArrayProperty") {
      args.push_back(decode_array(field, param, resolve_fname, depth));
      continue;
    }
    if (param.type == "StructProperty") {
      EventArg arg;
      arg.name = param.name;
      arg.is_struct = true;
      if (depth < kMaxStructDepth) {
        arg.items = decode_fields(field, param.fields, resolve_fname, depth + 1);
      }
      args.push_back(std::move(arg));
      continue;
    }
    auto scalar = decode_scalar(field, param.type, resolve_fname);
    if (scalar) {
      scalar->name = param.name;
      args.push_back(std::move(*scalar));
    }
    // Unsupported types (set/map/...) are skipped.
  }
  return args;
}

}  // namespace

std::vector<EventArg> decode_parms(const void* parms,
                                   const std::vector<ParamSpec>& params,
                                   const FNameResolver& resolve_fname) {
  if (parms == nullptr) return {};
  return decode_fields(static_cast<const std::uint8_t*>(parms), params,
                       resolve_fname, 0);
}

}  // namespace palmod
