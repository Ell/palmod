#pragma once

#include <cstdint>
#include <string>

namespace palmod {

// Resolves a live `UFunction::Func` slot in THIS process by scanning writable
// memory for a known exec-thunk pointer and confirming the `UFunction` vtable at
// (slot - func_offset). It uses only build-fixed constants (thunk VA, vtable VA,
// Func offset), so it is robust to heap ASLR, and it runs in-process under
// LD_PRELOAD, reading its own /proc/self/mem — no ptrace. The recovered slot is
// exactly what the reflection hook backend swaps.
struct ReflectionResolver {
  std::uint64_t func_offset{0};
  std::uint64_t vtable_va{0};

  // Returns the Func slot address, or nullptr (with `error` set) when the slot
  // is not found or is not unique.
  void** resolve(std::uint64_t thunk_va, std::string& error) const;
};

}  // namespace palmod
