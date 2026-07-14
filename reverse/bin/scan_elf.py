#!/usr/bin/env python3
"""Memory-bounded static fallback for PalMod UHT candidate discovery."""

from __future__ import annotations

import argparse
import mmap
import struct
import sys
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))

from palrevlib.evidence import (  # noqa: E402
    Candidate,
    CodePreimage,
    make_evidence,
    write_json_atomic,
)
from palrevlib.elf import (  # noqa: E402
    build_id,
    file_offset_to_va,
    load_segments,
    sha256_file,
    va_to_file_offset,
)


def all_offsets(mapping: mmap.mmap, needle: bytes):
    cursor = 0
    while True:
        cursor = mapping.find(needle, cursor)
        if cursor < 0:
            return
        yield cursor
        cursor += 1


def parse_known(values: list[str]) -> dict[str, int]:
    result = {}
    for value in values:
        name, separator, address = value.partition("=")
        if not separator:
            raise ValueError("--known-implementation must be NAME=0xADDRESS")
        result[name] = int(address, 0)
    return result


def executable(segments, value: int) -> bool:
    return any(segment.executable and segment.contains_virtual_address(value) for segment in segments)


def direct_relative_call_in_window(
    mapping: mmap.mmap,
    segments,
    function_va: int,
    target_va: int,
    *,
    window_size: int = 512,
) -> bool:
    offset = va_to_file_offset(segments, function_va)
    if offset is None:
        return False
    body = mapping[offset : offset + window_size]
    for index in range(0, max(0, len(body) - 4)):
        if body[index] != 0xE8:
            continue
        displacement = struct.unpack_from("<i", body, index + 1)[0]
        if function_va + index + 5 + displacement == target_va:
            return True
    return False


def code_preimage(mapping: mmap.mmap, segments, role: str, va: int) -> CodePreimage:
    offset = va_to_file_offset(segments, va)
    if offset is None:
        raise ValueError(f"candidate address is not file-backed: {va:#x}")
    body = bytes(mapping[offset : offset + 32])
    note = (
        "single-ret-stub-candidate"
        if body.startswith(b"\xc3\xcc")
        else "candidate-entry-bytes"
    )
    return CodePreimage(
        role=role,
        va=va,
        expected_bytes=body.hex(" ").upper(),
        note=note,
    )


def scan(args: argparse.Namespace) -> dict:
    binary = args.binary.resolve()
    actual_sha256 = sha256_file(binary)
    actual_build_id = build_id(binary)
    if args.expected_sha256 and args.expected_sha256.lower() != actual_sha256:
        raise RuntimeError(
            f"SHA-256 mismatch: expected {args.expected_sha256}, got {actual_sha256}"
        )
    if args.expected_build_id and args.expected_build_id.lower() != actual_build_id:
        raise RuntimeError(
            f"build ID mismatch: expected {args.expected_build_id}, got {actual_build_id}"
        )
    segments = load_segments(binary)
    image_base = min(segment.virtual_address for segment in segments)
    known = parse_known(args.known_implementation)
    candidates: list[Candidate] = []
    string_hits: dict[str, list[int]] = {name: [] for name in args.string}

    with binary.open("rb") as handle, mmap.mmap(
        handle.fileno(), 0, access=mmap.ACCESS_READ
    ) as mapping:
        for name in args.string:
            for string_offset in all_offsets(mapping, name.encode("ascii") + b"\0"):
                string_va = file_offset_to_va(segments, string_offset)
                if string_va is None:
                    continue
                string_hits[name].append(string_va)
                pointer = struct.pack("<Q", string_va)
                for table_offset in all_offsets(mapping, pointer):
                    if table_offset % 8 or table_offset + 16 > len(mapping):
                        continue
                    table_va = file_offset_to_va(segments, table_offset)
                    if table_va is None:
                        continue
                    thunk_va = struct.unpack_from("<Q", mapping, table_offset + 8)[0]
                    if not executable(segments, thunk_va):
                        continue
                    score = 75
                    reasons = [
                        "exact_nul_terminated_ascii",
                        "uht_name_pointer_pair",
                        "paired_pointer_is_executable",
                    ]
                    for delta, label in ((-16, "previous"), (16, "next")):
                        neighbor = table_offset + delta
                        if neighbor < 0 or neighbor + 16 > len(mapping):
                            continue
                        neighbor_name, neighbor_function = struct.unpack_from(
                            "<QQ", mapping, neighbor
                        )
                        if neighbor_name and executable(segments, neighbor_function):
                            score += 10
                            reasons.append(
                                f"{label}_pair_has_executable_target"
                            )
                    implementations: tuple[int, ...] = ()
                    preimages = [
                        code_preimage(mapping, segments, "exec_thunk", thunk_va)
                    ]
                    seed = known.get(name)
                    if seed is not None and direct_relative_call_in_window(
                        mapping, segments, thunk_va, seed
                    ):
                        score += 20
                        reasons.append("known_implementation_has_direct_call_encoding")
                        implementations = (seed,)
                        preimages.append(
                            code_preimage(mapping, segments, "implementation", seed)
                        )
                    candidates.append(
                        Candidate(
                            reflected_name=name,
                            string_va=string_va,
                            table_entry_va=table_va,
                            exec_thunk_va=thunk_va,
                            implementation_candidates=implementations,
                            score=score,
                            reasons=tuple(reasons),
                            code_preimages=tuple(preimages),
                        )
                    )

    return make_evidence(
        binary_path=str(binary),
        binary_sha256=actual_sha256,
        elf_build_id=actual_build_id,
        image_base=image_base,
        candidates=candidates,
        input_refs={
            "patternsleuth": args.patternsleuth_ref,
            "ue4ss": args.ue4ss_ref,
        },
        analyzer={
            "memory_strategy": "read-only-mmap",
            "name": "palmod-mmap-reflection-scan",
            "version": "0.1.0",
        },
        string_hits=string_hits,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--string", action="append", required=True)
    parser.add_argument("--known-implementation", action="append", default=[])
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-build-id")
    parser.add_argument("--ue4ss-ref", required=True)
    parser.add_argument("--patternsleuth-ref", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    write_json_atomic(args.out, scan(args))
    print(f"PALMOD_EVIDENCE={args.out}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"palmod static scanner: {error}", file=sys.stderr)
        raise SystemExit(2) from error
