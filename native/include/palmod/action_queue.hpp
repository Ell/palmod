#pragma once

#include "palmod/types.hpp"

#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

namespace palmod {

class ActionQueue {
 public:
  explicit ActionQueue(std::size_t capacity = 1024) : capacity_(capacity) {}

  void bind_game_thread();
  bool push(SemanticAction action);
  std::size_t drain(const std::function<void(const SemanticAction&)>& executor,
                    std::size_t max_actions = 128);
  std::size_t size() const;
  std::size_t dropped() const;

 private:
  const std::size_t capacity_;
  mutable std::mutex mu_;
  std::deque<SemanticAction> queue_;
  std::thread::id game_thread_{};
  std::size_t dropped_{0};
};

}  // namespace palmod
