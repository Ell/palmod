#include "palmod/object_walk.hpp"

#include <cstring>

namespace palmod {
namespace {

constexpr std::uint64_t kCanonicalLimit = std::uint64_t{1} << 48;

bool read_pointer(std::uint64_t address, std::uint64_t& out) {
  if (address == 0 || address >= kCanonicalLimit) return false;
  std::memcpy(&out, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
              sizeof(out));
  return true;
}

}  // namespace

std::uint64_t follow_pointer_chain(std::uint64_t start,
                                   const std::vector<std::size_t>& offsets) {
  std::uint64_t current = start;
  for (const std::size_t offset : offsets) {
    if (current == 0 || current >= kCanonicalLimit) return 0;
    std::uint64_t next = 0;
    if (!read_pointer(current + offset, next)) return 0;
    if (next == 0 || next >= kCanonicalLimit) return 0;
    current = next;
  }
  return current;
}

}  // namespace palmod
