#include "palmod/fingerprint.hpp"

#include "palmod/sha256.hpp"

#include <array>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <limits.h>
#include <span>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace palmod {
namespace {

constexpr std::uint64_t align4(std::uint64_t value) { return (value + 3U) & ~3ULL; }

std::optional<std::string> parse_note_region(std::ifstream& file,
                                             std::uint64_t offset,
                                             std::uint64_t size) {
  if (size == 0 || size > 16U * 1024U * 1024U) return std::nullopt;
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  file.clear();
  file.seekg(static_cast<std::streamoff>(offset));
  file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (file.gcount() != static_cast<std::streamsize>(bytes.size())) return std::nullopt;
  std::uint64_t cursor = 0;
  while (cursor + sizeof(Elf64_Nhdr) <= bytes.size()) {
    Elf64_Nhdr header{};
    std::memcpy(&header, bytes.data() + cursor, sizeof(header));
    cursor += sizeof(header);
    const std::uint64_t name_start = cursor;
    const std::uint64_t desc_start = cursor + align4(header.n_namesz);
    const std::uint64_t next = desc_start + align4(header.n_descsz);
    if (next > bytes.size()) return std::nullopt;
    if (header.n_type == NT_GNU_BUILD_ID && header.n_namesz >= 3 &&
        std::memcmp(bytes.data() + name_start, "GNU", 3) == 0) {
      return hex(std::span(bytes.data() + desc_start, header.n_descsz));
    }
    cursor = next;
  }
  return std::nullopt;
}

std::optional<std::string> read_build_id(const std::filesystem::path& path,
                                         std::string& error) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    error = "cannot open ELF for build-id: " + path.string();
    return std::nullopt;
  }
  Elf64_Ehdr header{};
  file.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (!file || std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64) {
    error = "expected a little-endian x86-64 ELF executable";
    return std::nullopt;
  }
  if (header.e_phentsize == sizeof(Elf64_Phdr) && header.e_phnum > 0) {
    file.seekg(static_cast<std::streamoff>(header.e_phoff));
    std::vector<Elf64_Phdr> programs(header.e_phnum);
    file.read(reinterpret_cast<char*>(programs.data()),
              static_cast<std::streamsize>(programs.size() * sizeof(Elf64_Phdr)));
    if (!file) {
      error = "cannot read ELF program headers";
      return std::nullopt;
    }
    for (const auto& program : programs) {
      if (program.p_type != PT_NOTE) continue;
      if (auto id = parse_note_region(file, program.p_offset, program.p_filesz)) return id;
    }
  }
  if (header.e_shentsize == sizeof(Elf64_Shdr) && header.e_shnum > 0) {
    file.clear();
    file.seekg(static_cast<std::streamoff>(header.e_shoff));
    std::vector<Elf64_Shdr> sections(header.e_shnum);
    file.read(reinterpret_cast<char*>(sections.data()),
              static_cast<std::streamsize>(sections.size() * sizeof(Elf64_Shdr)));
    if (!file) {
      error = "cannot read ELF section headers";
      return std::nullopt;
    }
    for (const auto& section : sections) {
      if (section.sh_type != SHT_NOTE) continue;
      if (auto id = parse_note_region(file, section.sh_offset, section.sh_size)) return id;
    }
  }
  error = "ELF has no GNU build-id note";
  return std::nullopt;
}

}  // namespace

FingerprintResult fingerprint_elf(const std::filesystem::path& executable) {
  std::error_code filesystem_error;
  const auto size = std::filesystem::file_size(executable, filesystem_error);
  if (filesystem_error) {
    return {std::nullopt, "cannot stat executable: " + filesystem_error.message()};
  }
  std::string error;
  auto digest = sha256_file(executable, error);
  if (!digest) return {std::nullopt, error};
  auto build_id = read_build_id(executable, error);
  if (!build_id) return {std::nullopt, error};
  return {BuildFingerprint{executable, *digest, *build_id, size}, {}};
}

FingerprintResult fingerprint_self() {
  std::array<char, PATH_MAX + 1> path{};
  const ssize_t length = readlink("/proc/self/exe", path.data(), PATH_MAX);
  if (length < 0) return {std::nullopt, "readlink(/proc/self/exe) failed"};
  path[static_cast<std::size_t>(length)] = '\0';
  return fingerprint_elf(path.data());
}

}  // namespace palmod
