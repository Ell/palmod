#pragma once

#include "palmod/object_array.hpp"
#include "palmod/types.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace palmod {

// Where a player's server-side admin state lives, from reflection (live-validated
// on build 24088465). Honors Palworld's OWN admin login: bAdmin flips to 1 when a
// client authenticates with the server AdminPassword. The sender is identified by
// their PlayerUId Guid (authoritative, from the chat message), not the spoofable
// display name.
struct AdminLayout {
  std::string controller_class;        // "PalPlayerController" (IsA)
  std::size_t player_state_offset{0};  // AController::PlayerState (0x298)
  std::size_t player_uid_offset{0};    // PalPlayerState::PlayerUId Guid (0x590)
  std::size_t badmin_offset{0};        // PalPlayerController::bAdmin (0x850)

  bool configured() const {
    return !controller_class.empty() && badmin_offset != 0;
  }
};

// Resolve a player's server-side auth from their 16-byte PlayerUId Guid: find the
// PalPlayerController whose PlayerState carries that Guid and read bAdmin.
//   Admin   — matched, bAdmin set
//   Player  — matched, not admin
//   Unknown — no matching controller (not connected / unresolved) → fail closed
AuthState resolve_player_auth(const ObjectArray& objects, const AdminLayout& layout,
                              const std::uint8_t player_uid[16]);

}  // namespace palmod
