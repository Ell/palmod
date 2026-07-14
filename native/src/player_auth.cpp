#include "palmod/player_auth.hpp"

#include <cstring>

namespace palmod {
namespace {

constexpr std::uint64_t kCanonicalLimit = std::uint64_t{1} << 48;

bool read_at(std::uint64_t va, void* dst, std::size_t n) {
  if (va == 0 || va >= kCanonicalLimit) return false;
  std::memcpy(dst, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(va)), n);
  return true;
}

}  // namespace

AuthState resolve_player_auth(const ObjectArray& objects, const AdminLayout& layout,
                              const std::uint8_t player_uid[16]) {
  if (!layout.configured()) return AuthState::Unknown;
  AuthState result = AuthState::Unknown;
  objects.for_each([&](std::uint64_t controller) {
    if (!objects.is_a(controller, layout.controller_class)) return true;
    if (objects.object_name(controller).rfind("Default__", 0) == 0) return true;  // CDO
    std::uint64_t player_state = 0;
    if (!read_at(controller + layout.player_state_offset, &player_state,
                 sizeof(player_state)) || player_state == 0) {
      return true;
    }
    std::uint8_t uid[16];
    if (!read_at(player_state + layout.player_uid_offset, uid, sizeof(uid))) return true;
    if (std::memcmp(uid, player_uid, sizeof(uid)) != 0) return true;
    std::uint8_t badmin = 0;
    read_at(controller + layout.badmin_offset, &badmin, 1);
    result = badmin != 0 ? AuthState::Admin : AuthState::Player;
    return false;  // found the sender's controller
  });
  return result;
}

}  // namespace palmod
