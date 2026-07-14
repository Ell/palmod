#include "palmod/chat_hook.hpp"

#include "palmod/invoke.hpp"
#include "palmod/json_log.hpp"

#include <cstdint>
#include <cstring>

namespace palmod {
namespace {

// One active chat hook at a time; the exec-thunk trampoline takes no user data,
// so it reaches its context through this static (mirrors the tick trampoline).
ChatHook* g_active_chat_hook = nullptr;

}  // namespace

bool handle_broadcast_chat(const void* fframe, std::size_t locals_offset,
                           const ChatFieldLayout& layout, const ChatDeliver& deliver) {
  if (fframe == nullptr || !deliver) return false;
  // FFrame::Locals (the Parms buffer) is a pointer *inside* the FFrame; read it
  // fault-safe so a wrong locals_offset can't fault, then decode from it.
  std::uint64_t locals = 0;
  if (!try_read_u64(reinterpret_cast<std::uint64_t>(fframe) + locals_offset, locals) ||
      locals == 0) {
    return false;
  }
  auto event = decode_chat_event(
      reinterpret_cast<const void*>(static_cast<std::uintptr_t>(locals)), layout);
  if (!event) return false;
  DecodedChat chat;
  chat.event = std::move(*event);
  // FPalChatMessage.Category is the first field (offset 0 of the Parms buffer).
  try_read_bytes(locals, &chat.category, 1);
  if (layout.sender_uid_offset != 0 &&
      try_read_bytes(locals + layout.sender_uid_offset, chat.sender_uid.data(),
                     chat.sender_uid.size())) {
    chat.has_sender_uid = true;
  }
  return deliver(chat);  // true = suppress the original broadcast
}

bool ChatHook::install(const Config& config, const ReflectionResolver& resolver,
                       ChatDeliver deliver, std::string& error) {
  if (config.broadcast_thunk_va == 0 || !deliver) {
    error = "chat hook requires a broadcast thunk address and a deliver callback";
    return false;
  }
  void** slot = resolver.resolve(config.broadcast_thunk_va, error);
  if (slot == nullptr) return false;  // error set by resolve()

  config_ = config;
  deliver_ = std::move(deliver);
  g_active_chat_hook = this;

  ThunkFn trampoline_fn = &trampoline;
  void* trampoline_bits = nullptr;
  std::memcpy(&trampoline_bits, &trampoline_fn, sizeof(trampoline_bits));
  if (!hook_.install(slot, trampoline_bits, error)) {
    g_active_chat_hook = nullptr;
    deliver_ = {};
    return false;
  }
  return true;
}

void ChatHook::uninstall() {
  hook_.uninstall();
  deliver_ = {};
  if (g_active_chat_hook == this) g_active_chat_hook = nullptr;
}

void ChatHook::trampoline(void* context, void* fframe, void* result) {
  auto* self = g_active_chat_hook;
  if (self == nullptr) return;
  JsonLog::instance().write(JsonLog::Level::Info, "chat.trampoline",
                            "BroadcastChatMessage Func invoked");
  const bool suppress = handle_broadcast_chat(
      fframe, self->config_.fframe_locals_offset, self->config_.layout,
      self->deliver_);
  if (suppress) return;  // a recognized command: swallow the broadcast
  void* original_bits = self->hook_.original();
  if (original_bits != nullptr) {
    ThunkFn original = nullptr;
    std::memcpy(&original, &original_bits, sizeof(original));
    if (original != nullptr) original(context, fframe, result);
  }
}

}  // namespace palmod
