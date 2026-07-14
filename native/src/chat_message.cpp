#include "palmod/chat_message.hpp"

#include "palmod/invoke.hpp"
#include "palmod/utf16.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace palmod {
namespace {

// Read an FString {u16* data, i32 num, i32 max} whose struct starts at VA
// `field_va` and transcode it. Every access is a fault-safe self-read: a wrong
// offset or a stale/garbage pointer yields an empty string, never a crash — the
// decode runs on the game thread inside a live server that must not fault.
std::string read_fstring(std::uint64_t field_va) {
  std::uint64_t data = 0;
  std::uint64_t num_word = 0;
  if (!try_read_u64(field_va, data)) return {};
  if (!try_read_u64(field_va + sizeof(data), num_word)) return {};
  const auto num = static_cast<std::int32_t>(num_word & 0xffffffffU);
  if (data == 0 || num <= 1) return {};  // num counts the null terminator
  constexpr std::int32_t kMaxChars = 1 << 16;
  const std::int32_t chars = num - 1 < kMaxChars ? num - 1 : kMaxChars;
  std::vector<char16_t> buffer(static_cast<std::size_t>(chars));
  if (!try_read_bytes(data, buffer.data(),
                      static_cast<std::size_t>(chars) * sizeof(char16_t))) {
    return {};
  }
  return utf16_to_utf8(buffer.data(), static_cast<std::size_t>(chars));
}

}  // namespace

std::optional<PluginEvent> decode_chat_event(const void* message,
                                             const ChatFieldLayout& layout) {
  if (message == nullptr) return std::nullopt;
  const auto base = reinterpret_cast<std::uint64_t>(message);
  PluginEvent event;
  event.kind = "chat";
  event.source = read_fstring(base + layout.sender_fstring_offset);
  event.text = read_fstring(base + layout.text_fstring_offset);
  return event;
}

}  // namespace palmod
