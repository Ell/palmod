#pragma once

#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace palmod {

template <typename T>
class HandleTable {
 public:
  using Handle = std::uint64_t;
  static constexpr Handle kInvalid = 0;

  Handle insert(T value) {
    std::scoped_lock lock(mu_);
    std::uint32_t index = 0;
    for (; index < slots_.size(); ++index) {
      if (!slots_[index].value.has_value()) break;
    }
    if (index == slots_.size()) slots_.push_back(Slot{});
    auto& slot = slots_[index];
    if (slot.generation == 0) slot.generation = 1;
    slot.value = std::move(value);
    return encode(index, slot.generation);
  }

  std::optional<T> get(Handle handle) const {
    const auto [index, generation] = decode(handle);
    std::scoped_lock lock(mu_);
    if (index >= slots_.size()) return std::nullopt;
    const auto& slot = slots_[index];
    if (slot.generation != generation || !slot.value) return std::nullopt;
    return slot.value;
  }

  bool erase(Handle handle) {
    const auto [index, generation] = decode(handle);
    std::scoped_lock lock(mu_);
    if (index >= slots_.size()) return false;
    auto& slot = slots_[index];
    if (slot.generation != generation || !slot.value) return false;
    slot.value.reset();
    ++slot.generation;
    if (slot.generation == 0) slot.generation = 1;
    return true;
  }

 private:
  struct Slot {
    std::uint32_t generation{1};
    std::optional<T> value;
  };

  static Handle encode(std::uint32_t index, std::uint32_t generation) {
    return (static_cast<Handle>(generation) << 32U) |
           (static_cast<Handle>(index) + 1U);
  }

  static std::pair<std::uint32_t, std::uint32_t> decode(Handle handle) {
    if (handle == 0) return {std::numeric_limits<std::uint32_t>::max(), 0};
    return {static_cast<std::uint32_t>((handle & 0xffffffffULL) - 1U),
            static_cast<std::uint32_t>(handle >> 32U)};
  }

  mutable std::mutex mu_;
  std::vector<Slot> slots_;
};

}  // namespace palmod
