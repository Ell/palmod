#pragma once

#include <cstddef>
#include <cstdint>

namespace palmod {

// Fault-safe self read of 8 bytes at `address` into `out`. Uses
// `process_vm_readv` on our own PID, which returns EFAULT for an unmapped or
// mid-construction address instead of raising SIGSEGV — so it is safe to probe
// a global (e.g. `GEngine`) that may not be populated yet at LD_PRELOAD time.
// Returns false (leaving `out` zeroed) when the range is not readable.
bool try_read_u64(std::uint64_t address, std::uint64_t& out);

// Fault-safe self read of `len` bytes at `address` into `out` (same mechanism as
// `try_read_u64`). Returns false without touching `out` when the whole range is
// not readable — lets us decode game structs (FStrings, Guids) at profile-derived
// offsets without ever risking a SIGSEGV from a wrong offset or a freed pointer.
bool try_read_bytes(std::uint64_t address, void* out, std::size_t len);

// Read a virtual-method address from an object's vtable: `*(void**)object` is the
// vtable, and `vtable[slot_index]` is the method. Returns 0 on a null/non-
// canonical read. The slot index is a per-build constant (confirmed live); the
// mechanism is the standard Itanium vtable layout, not a guess.
std::uint64_t read_vtable_slot(std::uint64_t object_va, std::size_t slot_index);

// Dereference a global pointer variable: `*(void**)global_va`. For singletons
// stored at a fixed data address (e.g. `GEngine`). Returns 0 on failure.
std::uint64_t read_global_pointer(std::uint64_t global_va);

// The *address* of a vtable entry — `&(*(void***)object)[slot_index]` — as
// opposed to `read_vtable_slot` which returns the entry's value. This is the
// `void**` slot to install a data-pointer hook on (e.g. swap `GEngine`'s `Tick`
// entry for a game-thread drain pump, UE4SS's EngineTick method without an inline
// hook). Returns 0 on failure.
std::uint64_t vtable_slot_address(std::uint64_t object_va, std::size_t slot_index);

// Invoke `UObject::ProcessEvent(UFunction* Function, void* Parms)` — the uniform
// UE dispatch entry point — on `target`, given ProcessEvent's address (from a
// UObject vtable slot), the UFunction, and an encoded Parms buffer. This is the
// write-side counterpart to the hook trampoline: with the Parms built by
// `encode_parms` and `target` found by `follow_pointer_chain`, it calls any
// UFunction by name. The ProcessEvent ABI is stable across UE builds; only its
// address is build-specific.
void call_process_event(std::uint64_t process_event_va, std::uint64_t target,
                        std::uint64_t function, void* parms);

}  // namespace palmod
