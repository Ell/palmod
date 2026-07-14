#include "palmod/invoke.hpp"

#include <cstring>
#include <sys/uio.h>
#include <unistd.h>

namespace palmod {
namespace {

constexpr std::uint64_t kCanonicalLimit = std::uint64_t{1} << 48;

bool read_pointer(std::uint64_t address, std::uint64_t& out) {
  return try_read_u64(address, out);
}

}  // namespace

bool try_read_bytes(std::uint64_t address, void* out, std::size_t len) {
  if (address == 0 || address >= kCanonicalLimit || len == 0) return false;
  iovec local{out, len};
  iovec remote{reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)), len};
  const ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
  return got == static_cast<ssize_t>(len);
}

bool try_read_u64(std::uint64_t address, std::uint64_t& out) {
  out = 0;
  return try_read_bytes(address, &out, sizeof(out));
}

std::uint64_t read_vtable_slot(std::uint64_t object_va, std::size_t slot_index) {
  std::uint64_t vtable = 0;
  if (!read_pointer(object_va, vtable)) return 0;  // *(void**)object
  std::uint64_t method = 0;
  if (!read_pointer(vtable + slot_index * sizeof(std::uint64_t), method)) return 0;
  return method;
}

std::uint64_t read_global_pointer(std::uint64_t global_va) {
  std::uint64_t value = 0;
  if (!read_pointer(global_va, value)) return 0;
  return value;
}

std::uint64_t vtable_slot_address(std::uint64_t object_va, std::size_t slot_index) {
  std::uint64_t vtable = 0;
  if (!read_pointer(object_va, vtable) || vtable == 0) return 0;
  const std::uint64_t address = vtable + slot_index * sizeof(std::uint64_t);
  if (address == 0 || address >= kCanonicalLimit) return 0;
  return address;
}

void call_process_event(std::uint64_t process_event_va, std::uint64_t target,
                        std::uint64_t function, void* parms) {
  if (process_event_va == 0 || target == 0) return;
  using ProcessEventFn = void (*)(void*, void*, void*);
  ProcessEventFn process_event = nullptr;
  std::memcpy(&process_event, &process_event_va, sizeof(process_event));
  process_event(reinterpret_cast<void*>(static_cast<std::uintptr_t>(target)),
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(function)),
                parms);
}

}  // namespace palmod
