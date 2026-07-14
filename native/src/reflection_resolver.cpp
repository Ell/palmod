#include "palmod/reflection_resolver.hpp"

#include "palmod/invoke.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/uio.h>
#include <unistd.h>
#include <vector>

namespace palmod {
namespace {

struct Region {
  std::uint64_t start{0};
  std::uint64_t end{0};
};

// Private, writable, anonymous or heap regions — where live UFunction objects
// live. Skipping file-backed and special maps bounds the scan and avoids the
// read-only registration table.
std::vector<Region> scannable_regions() {
  std::vector<Region> regions;
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while (std::getline(maps, line)) {
    std::istringstream stream(line);
    std::string range;
    std::string perms;
    std::string skip;
    std::string path;
    stream >> range >> perms >> skip >> skip >> skip;
    std::getline(stream, path);
    if (const auto first = path.find_first_not_of(' '); first != std::string::npos) {
      path = path.substr(first);
    } else {
      path.clear();
    }
    // Live UFunction objects are in writable, readable, non-file-backed memory
    // (heap/anon). Rejecting file-backed maps ('/'-paths) skips shared-object
    // data and the read-only registration table while reliably covering wherever
    // the allocator placed the object.
    if (perms.size() < 2 || perms[0] != 'r' || perms[1] != 'w') continue;
    if (!path.empty() && path[0] == '/') continue;
    const auto dash = range.find('-');
    if (dash == std::string::npos) continue;
    Region region;
    region.start = std::stoull(range.substr(0, dash), nullptr, 16);
    region.end = std::stoull(range.substr(dash + 1), nullptr, 16);
    if (region.end > region.start) regions.push_back(region);
  }
  return regions;
}

// Scan the game's live memory in 4 MiB chunks. The server is multithreaded and
// mutating this memory as we read; a raw in-process memcpy can fault when another
// thread unmaps a region between the /proc/self/maps snapshot and the read. So
// copy each chunk with process_vm_readv (fault-tolerant: it stops at the first
// unreadable page and reports how much it transferred) and scan the copy.
constexpr std::uint64_t kChunkBytes = 4ULL * 1024 * 1024;

}  // namespace

void** ReflectionResolver::resolve(std::uint64_t thunk_va, std::string& error) const {
  const auto regions = scannable_regions();
  const pid_t self = getpid();
  // The UFunction object is a single heap allocation, so both its vtable pointer
  // (at the header) and its Func slot live in a scanned rw region. Requiring the
  // header to be in one keeps matches to real live objects — dropping this gate
  // lets a coincidental thunk-valued word in read-only memory become a bogus slot.
  const auto mapped = [&regions](std::uint64_t va) {
    for (const auto& region : regions) {
      if (va >= region.start && va + sizeof(std::uint64_t) <= region.end) return true;
    }
    return false;
  };

  // The scan buffer itself lives in scannable memory. Once we copy a chunk that
  // holds the target object, that `[vtable, thunk]` pattern also sits in the
  // buffer — so scanning the buffer's own region would produce a phantom second
  // match. Reserve it once (fixed address) and skip any slot inside its range.
  std::vector<std::uint8_t> buffer;
  buffer.reserve(static_cast<std::size_t>(kChunkBytes));
  const auto buffer_lo = reinterpret_cast<std::uint64_t>(buffer.data());
  const std::uint64_t buffer_hi = buffer_lo + buffer.capacity();

  std::uint64_t found_slot = 0;
  std::size_t match_count = 0;
  for (const auto& region : regions) {
    std::uint64_t base = region.start;
    while (base < region.end) {
      const std::uint64_t want = std::min(kChunkBytes, region.end - base);
      buffer.resize(static_cast<std::size_t>(want));
      iovec local{buffer.data(), static_cast<std::size_t>(want)};
      iovec remote{reinterpret_cast<void*>(static_cast<std::uintptr_t>(base)),
                   static_cast<std::size_t>(want)};
      const ssize_t got = process_vm_readv(self, &local, 1, &remote, 1, 0);
      if (got <= 0) break;  // region raced out from under us; skip the remainder
      const auto valid = static_cast<std::uint64_t>(got);
      for (std::uint64_t i = 0; i + sizeof(std::uint64_t) <= valid;
           i += sizeof(std::uint64_t)) {
        std::uint64_t value = 0;
        std::memcpy(&value, buffer.data() + i, sizeof(value));
        if (value != thunk_va) continue;
        const std::uint64_t slot_va = base + i;
        if (slot_va >= buffer_lo && slot_va < buffer_hi) continue;  // our own copy
        if (slot_va < func_offset) continue;
        const std::uint64_t header_va = slot_va - func_offset;
        if (!mapped(header_va)) continue;
        std::uint64_t header = 0;
        if (!try_read_u64(header_va, header)) continue;
        if (header != vtable_va) continue;
        ++match_count;
        found_slot = slot_va;
      }
      base += valid;  // a short read means the next page faulted; loop re-probes
    }
  }

  if (match_count == 0) {
    error = "no UFunction::Func slot found for the exec thunk";
    return nullptr;
  }
  if (match_count > 1) {
    error = "UFunction::Func slot is not unique; refusing to guess";
    return nullptr;
  }
  return reinterpret_cast<void**>(static_cast<std::uintptr_t>(found_slot));
}

}  // namespace palmod
