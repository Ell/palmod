#include "palmod/parms_encode.hpp"

#include "palmod/utf16.hpp"

#include <cstring>
#include <string_view>

namespace palmod {
namespace {

constexpr int kMaxStructDepth = 8;

template <typename T>
void write(std::uint8_t* field, T value) {
  std::memcpy(field, &value, sizeof(T));
}

const ParamInput* find_input(const std::vector<ParamInput>& inputs,
                             const std::string& name) {
  for (const auto& input : inputs) {
    if (input.name == name) return &input;
  }
  return nullptr;
}

// Holds the mutable encode state (the pools that back FStrings/TArrays) so the
// recursion can allocate stable buffers. `parms.data()` and every pool's data()
// stay valid for the object's lifetime (deque reference stability + parms is
// never resized after construction).
class Encoder {
 public:
  Encoder(EncodedParms& out, const FNameEncoder& encode_fname)
      : out_(out), encode_fname_(encode_fname) {}

  void encode_fields(std::uint8_t* base, const std::vector<ParamSpec>& params,
                     const std::vector<ParamInput>& inputs, int depth) {
    for (const auto& param : params) {
      const auto* input = find_input(inputs, param.name);
      if (input == nullptr) continue;  // absent -> left zeroed (the ABI default)
      std::uint8_t* field = base + param.offset;
      if (param.type == "ArrayProperty") {
        encode_array(field, param, *input, depth);
      } else if (param.type == "StructProperty") {
        if (depth < kMaxStructDepth) {
          encode_fields(field, param.fields, input->items, depth + 1);
        }
      } else if (param.type == "StrProperty") {
        encode_str(field, input->text);
      } else {
        encode_scalar(field, param.type, *input);
      }
    }
  }

 private:
  // Write an FString {char16* Data, i32 Num, i32 Max} at `field`, backed by a
  // pool holding the null-terminated UTF-16. An empty string is the null FString.
  void encode_str(std::uint8_t* field, const std::string& text) {
    if (text.empty()) {
      std::memset(field, 0, 16);
      return;
    }
    std::u16string units = utf8_to_utf16(text);
    units.push_back(u'\0');
    std::vector<std::uint8_t>& pool = out_.pools.emplace_back(units.size() * 2);
    std::memcpy(pool.data(), units.data(), pool.size());
    const auto data = reinterpret_cast<std::uint64_t>(pool.data());
    const auto num = static_cast<std::int32_t>(units.size());  // includes the NUL
    write<std::uint64_t>(field, data);
    write<std::int32_t>(field + 8, num);
    write<std::int32_t>(field + 12, num);
  }

  // Write a TArray {T* Data, i32 Num, i32 Max} at `field`, backed by a pool of
  // `count * inner_size` element bytes, each element encoded in place.
  void encode_array(std::uint8_t* field, const ParamSpec& param,
                    const ParamInput& input, int depth) {
    std::memset(field, 0, 16);
    if (!input.is_array || input.items.empty() || param.inner_size == 0) return;
    const std::size_t count = input.items.size();
    std::vector<std::uint8_t>& pool =
        out_.pools.emplace_back(count * param.inner_size, 0);
    const bool struct_elements =
        param.inner_type == "StructProperty" && !param.fields.empty();
    for (std::size_t i = 0; i < count; ++i) {
      std::uint8_t* element = pool.data() + i * param.inner_size;
      if (struct_elements) {
        if (depth < kMaxStructDepth) {
          encode_fields(element, param.fields, input.items[i].items, depth + 1);
        }
      } else if (param.inner_type == "StrProperty") {
        encode_str(element, input.items[i].text);
      } else {
        encode_scalar(element, param.inner_type, input.items[i]);
      }
    }
    const auto data = reinterpret_cast<std::uint64_t>(pool.data());
    write<std::uint64_t>(field, data);
    write<std::int32_t>(field + 8, static_cast<std::int32_t>(count));
    write<std::int32_t>(field + 12, static_cast<std::int32_t>(count));
  }

  // Write one scalar/name value. Unsupported types leave the field zeroed.
  void encode_scalar(std::uint8_t* field, std::string_view type,
                     const ParamInput& input) {
    const double n = input.number;
    if (type == "IntProperty" || type == "Int32Property" || type == "UInt32Property") {
      write<std::int32_t>(field, static_cast<std::int32_t>(n));
    } else if (type == "Int64Property" || type == "UInt64Property") {
      write<std::int64_t>(field, static_cast<std::int64_t>(n));
    } else if (type == "Int16Property" || type == "UInt16Property") {
      write<std::int16_t>(field, static_cast<std::int16_t>(n));
    } else if (type == "ByteProperty" || type == "Int8Property" ||
               type == "EnumProperty") {
      write<std::uint8_t>(field, static_cast<std::uint8_t>(n));
    } else if (type == "BoolProperty") {
      write<std::uint8_t>(field, n != 0.0 ? 1 : 0);
    } else if (type == "FloatProperty") {
      write<float>(field, static_cast<float>(n));
    } else if (type == "DoubleProperty") {
      write<double>(field, n);
    } else if (type == "NameProperty") {
      const std::uint32_t index = encode_fname_ ? encode_fname_(input.text) : 0;
      write<std::uint32_t>(field, index);
      write<std::int32_t>(field + 4, 0);  // Number 0 (no instance suffix)
    }
    // Object/class pointers and unsupported types stay zeroed.
  }

  EncodedParms& out_;
  const FNameEncoder& encode_fname_;
};

}  // namespace

EncodedParms encode_parms(std::size_t parms_size,
                          const std::vector<ParamSpec>& params,
                          const std::vector<ParamInput>& inputs,
                          const FNameEncoder& encode_fname) {
  EncodedParms out;
  out.parms.assign(parms_size, 0);
  Encoder encoder(out, encode_fname);
  encoder.encode_fields(out.parms.data(), params, inputs, 0);
  return out;
}

}  // namespace palmod
