#pragma once

#include "palmod/types.hpp"

#include <cstddef>
#include <optional>

namespace palmod {

// Byte offsets of the sender and message FStrings within FPalChatMessage for a
// given build (recovered live: sender +0x08, message +0x28 on build 24088465).
// An FString is {u16* data, i32 num, i32 max}; `num` counts the null terminator.
// These belong in the profile eventually; the defaults match build 24088465.
struct ChatFieldLayout {
  std::size_t sender_fstring_offset{0x08};
  std::size_t text_fstring_offset{0x28};
  // SenderPlayerUId (16-byte Guid) — the authoritative sender identity for the
  // server-side admin check. 0 = absent.
  std::size_t sender_uid_offset{0x18};
};

// Decode an FPalChatMessage into a "chat" PluginEvent (source = sender, text =
// message, both transcoded UTF-16 -> UTF-8). Returns nullopt only for a null
// pointer; malformed/empty FStrings yield empty fields. Reads are bounded so a
// corrupt length cannot run away.
std::optional<PluginEvent> decode_chat_event(const void* message,
                                             const ChatFieldLayout& layout = {});

}  // namespace palmod
