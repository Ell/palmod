#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace palmod {

struct PlayerRecord {
  std::string stable_id;
  std::string display_name;
  std::uint64_t handle{0};
};

enum class ResolveStatus : std::uint8_t { Resolved, NotFound, Ambiguous };

struct PlayerResolution {
  ResolveStatus status{ResolveStatus::NotFound};
  PlayerRecord player;
  std::size_t candidate_count{0};
};

// Authoritative registry of currently connected players. Resolution is
// deterministic and never guesses: an exact stable-id match wins, otherwise a
// unique exact display-name match resolves, and anything else is reported as
// NotFound or Ambiguous so mutating actions fail closed instead of targeting an
// arbitrary player.
class PlayerDirectory {
 public:
  bool upsert(std::string stable_id, std::string display_name,
              std::uint64_t handle, std::string& error);
  bool remove(std::string_view stable_id);
  void clear();
  std::size_t size() const;
  PlayerResolution resolve(std::string_view query) const;

 private:
  mutable std::mutex mu_;
  std::map<std::string, PlayerRecord, std::less<>> by_id_;
};

}  // namespace palmod
