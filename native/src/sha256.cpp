#include "palmod/sha256.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace palmod {
namespace {

constexpr std::array<std::uint32_t, 64> kRound = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

constexpr std::uint32_t rotate(std::uint32_t value, unsigned count) {
  return (value >> count) | (value << (32U - count));
}

std::uint32_t read_be32(const std::byte* bytes) {
  return (std::to_integer<std::uint32_t>(bytes[0]) << 24U) |
         (std::to_integer<std::uint32_t>(bytes[1]) << 16U) |
         (std::to_integer<std::uint32_t>(bytes[2]) << 8U) |
         std::to_integer<std::uint32_t>(bytes[3]);
}

void write_be32(std::byte* bytes, std::uint32_t value) {
  bytes[0] = static_cast<std::byte>(value >> 24U);
  bytes[1] = static_cast<std::byte>(value >> 16U);
  bytes[2] = static_cast<std::byte>(value >> 8U);
  bytes[3] = static_cast<std::byte>(value);
}

}  // namespace

Sha256::Sha256()
    : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
             0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U} {}

void Sha256::update(std::span<const std::byte> bytes) {
  if (finished_) return;
  total_bytes_ += bytes.size();
  while (!bytes.empty()) {
    const std::size_t amount = std::min(buffer_.size() - buffered_, bytes.size());
    std::memcpy(buffer_.data() + buffered_, bytes.data(), amount);
    buffered_ += amount;
    bytes = bytes.subspan(amount);
    if (buffered_ == buffer_.size()) {
      transform(buffer_.data());
      buffered_ = 0;
    }
  }
}

std::array<std::byte, 32> Sha256::finish() {
  if (!finished_) {
    const std::uint64_t bit_length = total_bytes_ * 8U;
    buffer_[buffered_++] = std::byte{0x80};
    if (buffered_ > 56) {
      std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_),
                buffer_.end(), std::byte{0});
      transform(buffer_.data());
      buffered_ = 0;
    }
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_),
              buffer_.begin() + 56, std::byte{0});
    for (std::size_t i = 0; i < 8; ++i) {
      buffer_[63 - i] = static_cast<std::byte>(bit_length >> (i * 8U));
    }
    transform(buffer_.data());
    buffered_ = 0;
    finished_ = true;
  }
  std::array<std::byte, 32> digest{};
  for (std::size_t i = 0; i < state_.size(); ++i) {
    write_be32(digest.data() + i * 4, state_[i]);
  }
  return digest;
}

void Sha256::transform(const std::byte* block) {
  std::array<std::uint32_t, 64> words{};
  for (std::size_t i = 0; i < 16; ++i) words[i] = read_be32(block + i * 4);
  for (std::size_t i = 16; i < words.size(); ++i) {
    const std::uint32_t s0 = rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^
                             (words[i - 15] >> 3U);
    const std::uint32_t s1 = rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^
                             (words[i - 2] >> 10U);
    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
  }

  auto [a, b, c, d, e, f, g, h] = state_;
  for (std::size_t i = 0; i < words.size(); ++i) {
    const std::uint32_t sum1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + sum1 + choose + kRound[i] + words[i];
    const std::uint32_t sum0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = sum0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

std::optional<std::string> sha256_file(const std::filesystem::path& path,
                                       std::string& error) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    error = "cannot open executable for hashing: " + path.string();
    return std::nullopt;
  }
  Sha256 hash;
  std::array<std::byte, 1024U * 1024U> buffer{};
  while (stream) {
    stream.read(reinterpret_cast<char*>(buffer.data()),
                static_cast<std::streamsize>(buffer.size()));
    const auto count = stream.gcount();
    if (count > 0) hash.update(std::span(buffer.data(), static_cast<std::size_t>(count)));
  }
  if (!stream.eof()) {
    error = "I/O error while hashing executable: " + path.string();
    return std::nullopt;
  }
  return hex(hash.finish());
}

std::string hex(std::span<const std::byte> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string output;
  output.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const auto value = std::to_integer<unsigned>(bytes[i]);
    output[i * 2] = kDigits[value >> 4U];
    output[i * 2 + 1] = kDigits[value & 0xfU];
  }
  return output;
}

}  // namespace palmod
