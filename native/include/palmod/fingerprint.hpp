#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace palmod {

struct BuildFingerprint {
  std::filesystem::path executable;
  std::string sha256;
  std::string elf_build_id;
  std::uintmax_t size{0};
};

struct FingerprintResult {
  std::optional<BuildFingerprint> fingerprint;
  std::string error;
};

FingerprintResult fingerprint_elf(const std::filesystem::path& executable);
FingerprintResult fingerprint_self();

}  // namespace palmod
