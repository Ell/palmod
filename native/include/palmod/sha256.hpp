#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>

namespace palmod {

class Sha256 {
 public:
  Sha256();
  void update(std::span<const std::byte> bytes);
  std::array<std::byte, 32> finish();

 private:
  void transform(const std::byte* block);
  std::array<std::uint32_t, 8> state_;
  std::array<std::byte, 64> buffer_{};
  std::uint64_t total_bytes_{0};
  std::size_t buffered_{0};
  bool finished_{false};
};

std::optional<std::string> sha256_file(const std::filesystem::path& path,
                                       std::string& error);
std::string hex(std::span<const std::byte> bytes);

}  // namespace palmod
