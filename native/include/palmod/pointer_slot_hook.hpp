#pragma once

#include <string>

namespace palmod {

// Atomically swaps one 8-byte, 8-byte-aligned pointer slot to a replacement and
// restores it on uninstall. It operates on raw 8-byte slots, so it works for a
// `UFunction::Func` field or a C++ vtable entry alike. An aligned pointer store
// is atomic on x86-64, so this installs without the thread suspension and
// instruction relocation an inline code hook needs — the reason Palmod prefers
// data-pointer hooking over inline patching.
class PointerSlotHook {
 public:
  bool install(void** slot, void* replacement, std::string& error);
  void uninstall();
  void* original() const { return original_; }
  bool active() const { return slot_ != nullptr; }

 private:
  void** slot_{nullptr};
  void* original_{nullptr};
};

}  // namespace palmod
