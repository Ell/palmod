#include "palmod/player_directory.hpp"

#include <utility>

namespace palmod {
namespace {

constexpr std::size_t kMaxField = 128;

}  // namespace

bool PlayerDirectory::upsert(std::string stable_id, std::string display_name,
                             std::uint64_t handle, std::string& error) {
  if (stable_id.empty() || stable_id.size() > kMaxField) {
    error = "player stable_id must be between 1 and 128 bytes";
    return false;
  }
  if (display_name.empty() || display_name.size() > kMaxField) {
    error = "player display_name must be between 1 and 128 bytes";
    return false;
  }
  std::scoped_lock lock(mu_);
  auto& record = by_id_[stable_id];
  record.stable_id = std::move(stable_id);
  record.display_name = std::move(display_name);
  record.handle = handle;
  return true;
}

bool PlayerDirectory::remove(std::string_view stable_id) {
  std::scoped_lock lock(mu_);
  const auto found = by_id_.find(stable_id);
  if (found == by_id_.end()) return false;
  by_id_.erase(found);
  return true;
}

void PlayerDirectory::clear() {
  std::scoped_lock lock(mu_);
  by_id_.clear();
}

std::size_t PlayerDirectory::size() const {
  std::scoped_lock lock(mu_);
  return by_id_.size();
}

PlayerResolution PlayerDirectory::resolve(std::string_view query) const {
  std::scoped_lock lock(mu_);
  if (query.empty()) return {ResolveStatus::NotFound, {}, 0};
  // A stable id is unique by construction and always wins, even if the same
  // text also happens to be someone's display name.
  if (const auto found = by_id_.find(query); found != by_id_.end()) {
    return {ResolveStatus::Resolved, found->second, 1};
  }
  // Otherwise an exact display name resolves only when it is unambiguous.
  const PlayerRecord* match = nullptr;
  std::size_t count = 0;
  for (const auto& [id, record] : by_id_) {
    if (record.display_name == query) {
      match = &record;
      ++count;
    }
  }
  if (count == 1) return {ResolveStatus::Resolved, *match, 1};
  if (count == 0) return {ResolveStatus::NotFound, {}, 0};
  return {ResolveStatus::Ambiguous, {}, count};
}

}  // namespace palmod
