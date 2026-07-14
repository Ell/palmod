#include "palmod/fname_pool.hpp"

#include "palmod/utf16.hpp"

#include <cstring>
#include <vector>

namespace palmod {
namespace {

constexpr std::uint64_t kCanonicalLimit = std::uint64_t{1} << 48;
constexpr std::uint32_t kMaxNameLen = 1024;

// Trusted in-process read with a canonical-address guard (rejects obviously bad
// pointers). Not a full mapping check — FName indices from game memory are valid.
template <typename T>
bool read_at(std::uint64_t va, T& out) {
  if (va == 0 || va >= kCanonicalLimit) return false;
  std::memcpy(&out, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(va)),
              sizeof(T));
  return true;
}

bool read_bytes(std::uint64_t va, void* dst, std::size_t n) {
  if (va == 0 || va >= kCanonicalLimit) return false;
  std::memcpy(dst, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(va)), n);
  return true;
}

}  // namespace

std::string FNamePool::resolve(std::uint32_t comparison_index) const {
  if (blocks_va_ == 0 || comparison_index == 0) return {};
  const std::uint32_t block = comparison_index >> 16;
  const std::uint32_t offset = (comparison_index & 0xffff) * 2;

  std::uint64_t block_ptr = 0;
  if (!read_at(blocks_va_ + static_cast<std::uint64_t>(block) * 8, block_ptr) ||
      block_ptr == 0) {
    return {};
  }
  const std::uint64_t entry = block_ptr + offset;
  std::uint16_t header = 0;
  if (!read_at(entry, header)) return {};
  const std::uint32_t len = static_cast<std::uint32_t>(header >> 6);
  const bool wide = (header & 1) != 0;
  if (len == 0 || len > kMaxNameLen) return {};

  const std::uint64_t chars_va = entry + 2;
  if (wide) {
    std::u16string buffer(len, u'\0');
    if (!read_bytes(chars_va, buffer.data(), static_cast<std::size_t>(len) * 2)) {
      return {};
    }
    return utf16_to_utf8(buffer.data(), len);
  }
  std::string latin(len, '\0');
  if (!read_bytes(chars_va, latin.data(), len)) return {};
  // Latin-1 -> UTF-8 (ASCII is identity; bytes >= 0x80 become two bytes).
  std::string utf8;
  utf8.reserve(len);
  for (const unsigned char c : latin) {
    if (c < 0x80) {
      utf8.push_back(static_cast<char>(c));
    } else {
      utf8.push_back(static_cast<char>(0xc0 | (c >> 6)));
      utf8.push_back(static_cast<char>(0x80 | (c & 0x3f)));
    }
  }
  return utf8;
}

std::uint32_t FNamePool::lookup(std::string_view name) const {
  if (blocks_va_ == 0 || name.empty() || name.size() > kMaxNameLen) return 0;
  constexpr std::size_t kBlockBytes = 0x20000;
  std::uint32_t current_block = 0;
  std::uint32_t cursor = 0;
  if (!read_at(blocks_va_ - 8, current_block)) return 0;   // CurrentBlock
  if (!read_at(blocks_va_ - 4, cursor)) return 0;          // CurrentByteCursor
  if (current_block > 0x100000 || cursor > kBlockBytes) return 0;  // sanity

  std::vector<std::uint8_t> data;
  for (std::uint32_t block = 0; block <= current_block; ++block) {
    std::uint64_t block_ptr = 0;
    if (!read_at(blocks_va_ + static_cast<std::uint64_t>(block) * 8, block_ptr) ||
        block_ptr == 0) {
      continue;
    }
    const std::size_t used = (block == current_block) ? cursor : kBlockBytes;
    if (used < 2) continue;
    data.resize(used);
    if (!read_bytes(block_ptr, data.data(), used)) continue;

    std::size_t off = 0;
    while (off + 2 <= used) {
      std::uint16_t header = 0;
      std::memcpy(&header, data.data() + off, sizeof(header));
      if (header == 0) break;
      const std::uint32_t len = static_cast<std::uint32_t>(header >> 6);
      const bool wide = (header & 1) != 0;
      if (len == 0) break;
      const std::size_t size = static_cast<std::size_t>(len) * (wide ? 2 : 1);
      if (off + 2 + size > used) break;
      // Item ids are narrow (ASCII); only narrow entries can match a byte string.
      if (!wide && len == name.size() &&
          std::memcmp(data.data() + off + 2, name.data(), len) == 0) {
        return (block << 16) | static_cast<std::uint32_t>(off >> 1);
      }
      off += 2 + size;
      off = (off + 1) & ~static_cast<std::size_t>(1);  // 2-byte align
    }
  }
  return 0;
}

}  // namespace palmod
