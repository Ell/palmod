#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace palmod::json {

struct Value;
using Object = std::map<std::string, Value, std::less<>>;
using Array = std::vector<Value>;

struct Value {
  using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double,
                               std::string, Array, Object>;
  Storage data{nullptr};

  Value() = default;
  template <typename T>
  Value(T value) : data(std::move(value)) {}

  const Object* object() const { return std::get_if<Object>(&data); }
  const Array* array() const { return std::get_if<Array>(&data); }
  const std::string* string() const { return std::get_if<std::string>(&data); }
  const std::int64_t* integer() const { return std::get_if<std::int64_t>(&data); }
  const bool* boolean() const { return std::get_if<bool>(&data); }
};

struct ParseResult {
  std::optional<Value> value;
  std::string error;
};

ParseResult parse(std::string_view text);
std::string stringify(const Value& value);
std::string escape(std::string_view text);
const Value* get(const Object& object, std::string_view key);

}  // namespace palmod::json
