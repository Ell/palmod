"""Small deterministic scanners usable by both tests and analysis adapters."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class MemoryRange:
    start: int
    end: int

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass(frozen=True, slots=True)
class PairHit:
    string_va: int
    table_entry_va: int
    function_va: int
    score: int
    reasons: tuple[str, ...]


def _in_ranges(address: int, ranges: Iterable[MemoryRange]) -> bool:
    return any(memory_range.contains(address) for memory_range in ranges)


def scan_uht_name_function_pairs(
    data: bytes,
    *,
    data_va: int,
    string_va: int,
    executable_ranges: Iterable[MemoryRange],
    pointer_size: int = 8,
) -> list[PairHit]:
    """Find `{const char *name, native function}` pairs in a byte window.

    UnrealHeaderTool emits these pairs for native registration.  This scanner
    intentionally only recognizes the structural fact; it does not infer a C++
    prototype or claim that the function is safe to call.
    """

    if pointer_size != 8:
        raise ValueError("only 64-bit little-endian pointers are supported")
    needle = struct.pack("<Q", string_va)
    results: list[PairHit] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            break
        cursor = offset + 1
        if offset % pointer_size != 0 or offset + 16 > len(data):
            continue
        function_va = struct.unpack_from("<Q", data, offset + 8)[0]
        reasons = ["name_pointer_matches"]
        score = 25
        if _in_ranges(function_va, executable_ranges):
            score += 50
            reasons.append("paired_pointer_is_executable")
        else:
            continue
        if offset >= 16:
            previous_name, previous_function = struct.unpack_from("<QQ", data, offset - 16)
            if previous_name and _in_ranges(previous_function, executable_ranges):
                score += 10
                reasons.append("previous_pair_has_executable_target")
        if offset + 32 <= len(data):
            next_name, next_function = struct.unpack_from("<QQ", data, offset + 16)
            if next_name and _in_ranges(next_function, executable_ranges):
                score += 10
                reasons.append("next_pair_has_executable_target")
        results.append(
            PairHit(
                string_va=string_va,
                table_entry_va=data_va + offset,
                function_va=function_va,
                score=score,
                reasons=tuple(reasons),
            )
        )
    return sorted(results, key=lambda hit: (-hit.score, hit.table_entry_va))
