#include "palmod/action_queue.hpp"

#include "palmod/json_log.hpp"

namespace palmod {

void ActionQueue::bind_game_thread() {
  std::scoped_lock lock(mu_);
  game_thread_ = std::this_thread::get_id();
}

bool ActionQueue::push(SemanticAction action) {
  std::scoped_lock lock(mu_);
  if (queue_.size() >= capacity_) {
    ++dropped_;
    return false;
  }
  queue_.push_back(std::move(action));
  return true;
}

std::size_t ActionQueue::drain(
    const std::function<void(const SemanticAction&)>& executor,
    std::size_t max_actions) {
  {
    std::scoped_lock lock(mu_);
    if (game_thread_ == std::thread::id{}) game_thread_ = std::this_thread::get_id();
    if (game_thread_ != std::this_thread::get_id()) {
      JsonLog::instance().write(JsonLog::Level::Error, "action.wrong_thread",
                                "refused to execute actions outside the game thread");
      return 0;
    }
  }
  std::size_t processed = 0;
  while (processed < max_actions) {
    SemanticAction action;
    {
      std::scoped_lock lock(mu_);
      if (queue_.empty()) break;
      action = std::move(queue_.front());
      queue_.pop_front();
    }
    executor(action);
    ++processed;
  }
  return processed;
}

std::size_t ActionQueue::size() const {
  std::scoped_lock lock(mu_);
  return queue_.size();
}

std::size_t ActionQueue::dropped() const {
  std::scoped_lock lock(mu_);
  return dropped_;
}

}  // namespace palmod
