#pragma once

#include "palmod/chat_message.hpp"
#include "palmod/pointer_slot_hook.hpp"
#include "palmod/reflection_resolver.hpp"
#include "palmod/types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace palmod {

// A decoded chat broadcast: the event (sender/text) plus the authoritative
// SenderPlayerUId Guid for the server-side admin check, and the message's own
// Category enum (reused when the backend sends a reply so it displays normally).
struct DecodedChat {
  PluginEvent event;
  std::array<std::uint8_t, 16> sender_uid{};
  bool has_sender_uid{false};
  std::uint8_t category{0};
};

// Delivered on the game thread for each chat broadcast. Returns true to SUPPRESS
// the original broadcast — i.e. this was a recognized mod command that should not
// be echoed to chat. Observation-only handlers return false.
using ChatDeliver = std::function<bool(const DecodedChat&)>;

// Core of the chat trampoline: a UFunction exec-thunk hook is called with the
// FFrame; its Locals field holds the Parms buffer whose first member is the
// FPalChatMessage. Extract it, decode it (+ sender Guid), and deliver. Returns
// true if the handler asked to suppress the original broadcast. Pure enough to
// unit-test with a synthetic FFrame + message.
bool handle_broadcast_chat(const void* fframe, std::size_t locals_offset,
                           const ChatFieldLayout& layout, const ChatDeliver& deliver);

// Installs a reflection (UFunction::Func) hook on BroadcastChatMessage: it
// resolves the live Func slot for the exec thunk, swaps it to a trampoline that
// delivers a chat event and then chains the original. Observation-only (it
// always calls the original); suppression is a later, separate concern.
class ChatHook {
 public:
  struct Config {
    std::uint64_t broadcast_thunk_va{0};   // exec thunk VA (image_base + rva)
    std::size_t fframe_locals_offset{0x18};
    ChatFieldLayout layout{};
  };

  ~ChatHook() { uninstall(); }
  bool install(const Config& config, const ReflectionResolver& resolver,
               ChatDeliver deliver, std::string& error);
  void uninstall();
  bool active() const { return hook_.active(); }

 private:
  using ThunkFn = void (*)(void*, void*, void*);
  static void trampoline(void* context, void* fframe, void* result);

  PointerSlotHook hook_;
  ChatDeliver deliver_;
  Config config_;
};

}  // namespace palmod
