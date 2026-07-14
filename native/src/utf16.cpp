#include "palmod/utf16.hpp"

#include <cstdint>

namespace palmod {
namespace {

void append_utf8(std::string& out, char32_t cp) {
  if (cp <= 0x7f) {
    out.push_back(static_cast<char>(cp));
  } else if (cp <= 0x7ff) {
    out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else if (cp <= 0xffff) {
    out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else {
    out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  }
}

constexpr char32_t kReplacement = 0xfffd;

}  // namespace

std::u16string utf8_to_utf16(std::string_view utf8) {
  std::u16string out;
  out.reserve(utf8.size());
  std::size_t i = 0;
  const std::size_t n = utf8.size();
  auto cont = [&](std::size_t k) {
    return k < n && (static_cast<unsigned char>(utf8[k]) & 0xc0) == 0x80;
  };
  while (i < n) {
    const auto b0 = static_cast<unsigned char>(utf8[i]);
    char32_t cp = kReplacement;
    std::size_t len = 1;
    if (b0 < 0x80) {
      cp = b0;
    } else if ((b0 & 0xe0) == 0xc0 && cont(i + 1)) {
      cp = (static_cast<char32_t>(b0 & 0x1f) << 6) |
           (static_cast<unsigned char>(utf8[i + 1]) & 0x3f);
      len = 2;
      if (cp < 0x80) cp = kReplacement;
    } else if ((b0 & 0xf0) == 0xe0 && cont(i + 1) && cont(i + 2)) {
      cp = (static_cast<char32_t>(b0 & 0x0f) << 12) |
           ((static_cast<unsigned char>(utf8[i + 1]) & 0x3f) << 6) |
           (static_cast<unsigned char>(utf8[i + 2]) & 0x3f);
      len = 3;
      if (cp < 0x800) cp = kReplacement;
    } else if ((b0 & 0xf8) == 0xf0 && cont(i + 1) && cont(i + 2) && cont(i + 3)) {
      cp = (static_cast<char32_t>(b0 & 0x07) << 18) |
           ((static_cast<unsigned char>(utf8[i + 1]) & 0x3f) << 12) |
           ((static_cast<unsigned char>(utf8[i + 2]) & 0x3f) << 6) |
           (static_cast<unsigned char>(utf8[i + 3]) & 0x3f);
      len = 4;
      if (cp < 0x10000 || cp > 0x10ffff) cp = kReplacement;
    }
    if (cp <= 0xffff) {
      out.push_back(static_cast<char16_t>(cp));
    } else {
      const char32_t v = cp - 0x10000;
      out.push_back(static_cast<char16_t>(0xd800 + (v >> 10)));
      out.push_back(static_cast<char16_t>(0xdc00 + (v & 0x3ff)));
    }
    i += len;
  }
  return out;
}

std::string utf16_to_utf8(const char16_t* units, std::size_t count) {
  std::string out;
  if (units == nullptr) return out;
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    const char16_t unit = units[i];
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (i + 1 < count) {
        const char16_t low = units[i + 1];
        if (low >= 0xdc00 && low <= 0xdfff) {
          const char32_t cp = 0x10000 +
              ((static_cast<char32_t>(unit - 0xd800) << 10) | (low - 0xdc00));
          append_utf8(out, cp);
          ++i;
          continue;
        }
      }
      append_utf8(out, kReplacement);
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      append_utf8(out, kReplacement);
    } else {
      append_utf8(out, unit);
    }
  }
  return out;
}

}  // namespace palmod
