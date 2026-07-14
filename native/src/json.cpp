#include "palmod/json.hpp"

#include <charconv>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>

namespace palmod::json {
namespace {

class Parser {
 public:
  explicit Parser(std::string_view input) : input_(input) {}

  ParseResult run() {
    skip_space();
    auto value = parse_value();
    if (!value) return {std::nullopt, error_};
    skip_space();
    if (position_ != input_.size()) return fail("trailing characters");
    return {std::move(value), {}};
  }

 private:
  ParseResult fail(std::string message) {
    return {std::nullopt, std::move(message) + " at byte " +
                              std::to_string(position_)};
  }

  void set_error(std::string message) {
    if (error_.empty()) {
      error_ = std::move(message) + " at byte " + std::to_string(position_);
    }
  }

  void skip_space() {
    while (position_ < input_.size()) {
      const char c = input_[position_];
      if (c != ' ' && c != '\n' && c != '\r' && c != '\t') break;
      ++position_;
    }
  }

  std::optional<Value> parse_value() {
    skip_space();
    if (position_ >= input_.size()) {
      set_error("unexpected end of JSON");
      return std::nullopt;
    }
    switch (input_[position_]) {
      case '{': return parse_object();
      case '[': return parse_array();
      case '"': {
        auto string = parse_string();
        if (!string) return std::nullopt;
        return Value{std::move(*string)};
      }
      case 't': return literal("true", Value{true});
      case 'f': return literal("false", Value{false});
      case 'n': return literal("null", Value{nullptr});
      default:
        if (input_[position_] == '-' ||
            (input_[position_] >= '0' && input_[position_] <= '9')) {
          return parse_number();
        }
        set_error("unexpected token");
        return std::nullopt;
    }
  }

  std::optional<Value> literal(std::string_view spelling, Value value) {
    if (input_.substr(position_, spelling.size()) != spelling) {
      set_error("invalid literal");
      return std::nullopt;
    }
    position_ += spelling.size();
    return value;
  }

  std::optional<Value> parse_object() {
    ++position_;
    Object object;
    skip_space();
    if (consume('}')) return Value{std::move(object)};
    while (true) {
      skip_space();
      auto key = parse_string();
      if (!key) return std::nullopt;
      skip_space();
      if (!consume(':')) {
        set_error("expected ':'");
        return std::nullopt;
      }
      auto value = parse_value();
      if (!value) return std::nullopt;
      if (!object.emplace(std::move(*key), std::move(*value)).second) {
        set_error("duplicate object key");
        return std::nullopt;
      }
      skip_space();
      if (consume('}')) break;
      if (!consume(',')) {
        set_error("expected ',' or '}'");
        return std::nullopt;
      }
    }
    return Value{std::move(object)};
  }

  std::optional<Value> parse_array() {
    ++position_;
    Array array;
    skip_space();
    if (consume(']')) return Value{std::move(array)};
    while (true) {
      auto value = parse_value();
      if (!value) return std::nullopt;
      array.push_back(std::move(*value));
      skip_space();
      if (consume(']')) break;
      if (!consume(',')) {
        set_error("expected ',' or ']'");
        return std::nullopt;
      }
    }
    return Value{std::move(array)};
  }

  std::optional<std::string> parse_string() {
    if (!consume('"')) {
      set_error("expected string");
      return std::nullopt;
    }
    std::string output;
    while (position_ < input_.size()) {
      const unsigned char c = static_cast<unsigned char>(input_[position_++]);
      if (c == '"') return output;
      if (c < 0x20U) {
        set_error("control byte in string");
        return std::nullopt;
      }
      if (c != '\\') {
        output.push_back(static_cast<char>(c));
        continue;
      }
      if (position_ >= input_.size()) {
        set_error("unterminated escape");
        return std::nullopt;
      }
      const char escape = input_[position_++];
      switch (escape) {
        case '"': output.push_back('"'); break;
        case '\\': output.push_back('\\'); break;
        case '/': output.push_back('/'); break;
        case 'b': output.push_back('\b'); break;
        case 'f': output.push_back('\f'); break;
        case 'n': output.push_back('\n'); break;
        case 'r': output.push_back('\r'); break;
        case 't': output.push_back('\t'); break;
        case 'u': {
          auto codepoint = parse_hex4();
          if (!codepoint) return std::nullopt;
          if (*codepoint >= 0xd800U && *codepoint <= 0xdfffU) {
            set_error("UTF-16 surrogate escapes are unsupported");
            return std::nullopt;
          }
          append_utf8(output, *codepoint);
          break;
        }
        default:
          set_error("unknown escape");
          return std::nullopt;
      }
    }
    set_error("unterminated string");
    return std::nullopt;
  }

  std::optional<std::uint32_t> parse_hex4() {
    if (input_.size() - position_ < 4) {
      set_error("short unicode escape");
      return std::nullopt;
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = input_[position_++];
      value <<= 4U;
      if (c >= '0' && c <= '9') value |= static_cast<std::uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') value |= static_cast<std::uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') value |= static_cast<std::uint32_t>(c - 'A' + 10);
      else {
        set_error("invalid unicode escape");
        return std::nullopt;
      }
    }
    return value;
  }

  static void append_utf8(std::string& output, std::uint32_t cp) {
    if (cp <= 0x7fU) {
      output.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ffU) {
      output.push_back(static_cast<char>(0xc0U | (cp >> 6U)));
      output.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else {
      output.push_back(static_cast<char>(0xe0U | (cp >> 12U)));
      output.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
      output.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    }
  }

  std::optional<Value> parse_number() {
    const std::size_t start = position_;
    if (input_[position_] == '-') ++position_;
    if (position_ >= input_.size()) {
      set_error("incomplete number");
      return std::nullopt;
    }
    if (input_[position_] == '0') {
      ++position_;
    } else {
      if (input_[position_] < '1' || input_[position_] > '9') {
        set_error("invalid number");
        return std::nullopt;
      }
      while (position_ < input_.size() && input_[position_] >= '0' &&
             input_[position_] <= '9') ++position_;
    }
    bool floating = false;
    if (position_ < input_.size() && input_[position_] == '.') {
      floating = true;
      ++position_;
      const std::size_t digits = position_;
      while (position_ < input_.size() && input_[position_] >= '0' &&
             input_[position_] <= '9') ++position_;
      if (digits == position_) {
        set_error("missing fractional digits");
        return std::nullopt;
      }
    }
    if (position_ < input_.size() &&
        (input_[position_] == 'e' || input_[position_] == 'E')) {
      floating = true;
      ++position_;
      if (position_ < input_.size() &&
          (input_[position_] == '+' || input_[position_] == '-')) ++position_;
      const std::size_t digits = position_;
      while (position_ < input_.size() && input_[position_] >= '0' &&
             input_[position_] <= '9') ++position_;
      if (digits == position_) {
        set_error("missing exponent digits");
        return std::nullopt;
      }
    }
    const auto token = input_.substr(start, position_ - start);
    if (!floating) {
      std::int64_t value = 0;
      const auto result = std::from_chars(token.data(), token.data() + token.size(), value);
      if (result.ec == std::errc{} && result.ptr == token.data() + token.size()) {
        return Value{value};
      }
    }
    std::string owned(token);
    char* end = nullptr;
    const double value = std::strtod(owned.c_str(), &end);
    if (end != owned.c_str() + owned.size() || !std::isfinite(value)) {
      set_error("invalid or non-finite number");
      return std::nullopt;
    }
    return Value{value};
  }

  bool consume(char expected) {
    if (position_ >= input_.size() || input_[position_] != expected) return false;
    ++position_;
    return true;
  }

  std::string_view input_;
  std::size_t position_{0};
  std::string error_;
};

void stringify_to(const Value& value, std::string& out) {
  if (std::holds_alternative<std::nullptr_t>(value.data)) {
    out += "null";
  } else if (const auto* boolean = std::get_if<bool>(&value.data)) {
    out += *boolean ? "true" : "false";
  } else if (const auto* integer = std::get_if<std::int64_t>(&value.data)) {
    out += std::to_string(*integer);
  } else if (const auto* number = std::get_if<double>(&value.data)) {
    std::ostringstream stream;
    stream << std::setprecision(std::numeric_limits<double>::max_digits10) << *number;
    out += stream.str();
  } else if (const auto* string = std::get_if<std::string>(&value.data)) {
    out += '"';
    out += escape(*string);
    out += '"';
  } else if (const auto* array = std::get_if<Array>(&value.data)) {
    out += '[';
    bool first = true;
    for (const auto& item : *array) {
      if (!first) out += ',';
      first = false;
      stringify_to(item, out);
    }
    out += ']';
  } else if (const auto* object = std::get_if<Object>(&value.data)) {
    out += '{';
    bool first = true;
    for (const auto& [key, item] : *object) {
      if (!first) out += ',';
      first = false;
      out += '"';
      out += escape(key);
      out += "\":";
      stringify_to(item, out);
    }
    out += '}';
  }
}

}  // namespace

ParseResult parse(std::string_view text) { return Parser{text}.run(); }

std::string stringify(const Value& value) {
  std::string result;
  stringify_to(value, result);
  return result;
}

std::string escape(std::string_view text) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.reserve(text.size() + 8);
  for (const unsigned char c : text) {
    switch (c) {
      case '"': result += "\\\""; break;
      case '\\': result += "\\\\"; break;
      case '\b': result += "\\b"; break;
      case '\f': result += "\\f"; break;
      case '\n': result += "\\n"; break;
      case '\r': result += "\\r"; break;
      case '\t': result += "\\t"; break;
      default:
        if (c < 0x20U) {
          result += "\\u00";
          result += kHex[c >> 4U];
          result += kHex[c & 0x0fU];
        } else {
          result += static_cast<char>(c);
        }
    }
  }
  return result;
}

const Value* get(const Object& object, std::string_view key) {
  const auto found = object.find(key);
  return found == object.end() ? nullptr : &found->second;
}

}  // namespace palmod::json
