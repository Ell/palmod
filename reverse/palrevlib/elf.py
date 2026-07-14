"""Dependency-free ELF fingerprint helpers for probe fail-closed checks."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path


class ElfError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LoadSegment:
    file_offset: int
    file_size: int
    virtual_address: int
    memory_size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)

    def contains_file_offset(self, value: int) -> bool:
        return self.file_offset <= value < self.file_offset + self.file_size

    def contains_virtual_address(self, value: int) -> bool:
        return self.virtual_address <= value < self.virtual_address + self.memory_size


def load_segments(path: str | Path) -> list[LoadSegment]:
    with Path(path).open("rb") as handle:
        header = handle.read(64)
        if len(header) != 64 or header[:4] != b"\x7fELF":
            raise ElfError("not an ELF file")
        if header[4] != 2 or header[5] != 1:
            raise ElfError("only ELF64 little-endian files are supported")
        e_phoff = struct.unpack_from("<Q", header, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", header, 54)
        if e_phentsize < 56:
            raise ElfError("invalid ELF program-header size")
        segments: list[LoadSegment] = []
        for index in range(e_phnum):
            handle.seek(e_phoff + index * e_phentsize)
            program_header = handle.read(e_phentsize)
            if len(program_header) != e_phentsize:
                raise ElfError("truncated ELF program-header table")
            p_type, p_flags = struct.unpack_from("<II", program_header, 0)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset, p_vaddr = struct.unpack_from("<QQ", program_header, 8)
            p_filesz, p_memsz = struct.unpack_from("<QQ", program_header, 32)
            segments.append(
                LoadSegment(
                    file_offset=p_offset,
                    file_size=p_filesz,
                    virtual_address=p_vaddr,
                    memory_size=p_memsz,
                    flags=p_flags,
                )
            )
        if not segments:
            raise ElfError("ELF contains no loadable segments")
        return sorted(segments, key=lambda item: item.virtual_address)


def file_offset_to_va(segments: list[LoadSegment], value: int) -> int | None:
    for segment in segments:
        if segment.contains_file_offset(value):
            return segment.virtual_address + value - segment.file_offset
    return None


def va_to_file_offset(segments: list[LoadSegment], value: int) -> int | None:
    for segment in segments:
        if segment.contains_virtual_address(value):
            offset = segment.file_offset + value - segment.virtual_address
            if offset < segment.file_offset + segment.file_size:
                return offset
    return None


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def build_id(path: str | Path) -> str:
    """Extract a GNU/LLVM build ID from ELF PT_NOTE segments."""

    with Path(path).open("rb") as handle:
        header = handle.read(64)
        if len(header) != 64 or header[:4] != b"\x7fELF":
            raise ElfError("not an ELF file")
        if header[4] != 2 or header[5] != 1:
            raise ElfError("only ELF64 little-endian files are supported")
        e_phoff = struct.unpack_from("<Q", header, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", header, 54)
        if e_phentsize < 56:
            raise ElfError("invalid ELF program-header size")
        for index in range(e_phnum):
            handle.seek(e_phoff + index * e_phentsize)
            program_header = handle.read(e_phentsize)
            if len(program_header) != e_phentsize:
                raise ElfError("truncated ELF program-header table")
            p_type = struct.unpack_from("<I", program_header, 0)[0]
            if p_type != 4:  # PT_NOTE
                continue
            p_offset, p_filesz = struct.unpack_from("<QQ", program_header, 8)[0], struct.unpack_from("<Q", program_header, 32)[0]
            handle.seek(p_offset)
            notes = handle.read(p_filesz)
            cursor = 0
            while cursor + 12 <= len(notes):
                namesz, descsz, note_type = struct.unpack_from("<III", notes, cursor)
                cursor += 12
                name = notes[cursor : cursor + namesz].rstrip(b"\0")
                cursor += (namesz + 3) & ~3
                description = notes[cursor : cursor + descsz]
                cursor += (descsz + 3) & ~3
                if name in {b"GNU", b"LLVM"} and note_type == 3 and description:
                    return description.hex()
        raise ElfError("ELF build ID not found")
