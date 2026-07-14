#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace palmod {

// Follow a chain of reflected pointer-property offsets from `start` to a target
// object (e.g. player -> inventory component -> inventory data). Each offset is
// an ObjectProperty's `Offset_Internal` (from reflection); at each step we read
// the 8-byte pointer at `current + offset` and move to it. Returns 0 if any
// pointer is null or non-canonical. In-process; the offsets come from reflection,
// nothing is hardcoded. This is the "find the target `this`" primitive for the
// mutation path.
std::uint64_t follow_pointer_chain(std::uint64_t start,
                                   const std::vector<std::size_t>& offsets);

}  // namespace palmod
