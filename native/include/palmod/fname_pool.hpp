#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace palmod {

// Reads UE 5.1 `FName` strings out of the live `FNamePool` (in-process). Given
// the pool's `Blocks` array VA (a build constant + image base), resolves an
// `FName` comparison index to its string: block = index >> 16, byte offset =
// (index & 0xffff) * 2, entry = Blocks[block] + offset; a u16 header encodes
// `Len = hdr >> 6` and `wide = hdr & 1`, with the characters following.
//
// This upgrades generic-hook `NameProperty` arguments from a raw index to the
// actual name (item ids, tags, ...). Indices come from real game memory, so the
// reads are trusted; lengths are clamped defensively.
class FNamePool {
 public:
  FNamePool() = default;
  explicit FNamePool(std::uint64_t blocks_va) : blocks_va_(blocks_va) {}

  bool valid() const { return blocks_va_ != 0; }

  // The resolved name, or "" on any failure (invalid index, null block, ...).
  std::string resolve(std::uint32_t comparison_index) const;

  // The reverse of resolve: scan the live pool for a narrow (ASCII/latin-1) name
  // and return its `FName` ComparisonIndex, or 0 if absent. Reads the allocator
  // extent — `CurrentBlock` @ `Blocks-8`, `CurrentByteCursor` @ `Blocks-4`, block
  // size `0x20000` (confirmed live on build 24088465). O(pool), so callers should
  // cache; used to turn an item-id string into an `FName` for a direct call.
  std::uint32_t lookup(std::string_view name) const;

 private:
  std::uint64_t blocks_va_{0};
};

}  // namespace palmod
