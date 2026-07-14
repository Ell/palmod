# PalMod native Linux reflected-function candidate scanner.
#@category PalMod
#@author PalMod contributors
#@runtime PyGhidra

"""Locate UHT name/function pairs and export reproducible evidence.

This is a PyGhidra GhidraScript.  It labels static candidates in the Ghidra
database, but it never writes to or executes the imported ELF.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path


def _source_path() -> Path:
    try:
        return Path(str(getSourceFile().getAbsolutePath()))  # noqa: F821
    except Exception:
        return Path(__file__).resolve()


REVERSE_ROOT = _source_path().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))

from palrevlib.evidence import Candidate, make_evidence, write_json_atomic  # noqa: E402
from palrevlib.elf import build_id, sha256_file  # noqa: E402

from ghidra.program.model.symbol import SourceType  # type: ignore  # noqa: E402
from ghidra.framework import Application  # type: ignore  # noqa: E402
from jpype.types import JArray, JByte  # type: ignore  # noqa: E402


CHUNK_SIZE = 4 * 1024 * 1024
OVERLAP = 32
U64_MASK = (1 << 64) - 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--string", action="append", dest="strings", required=True)
    parser.add_argument("--known-implementation", action="append", default=[])
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-build-id")
    parser.add_argument("--ue4ss-ref", required=True)
    parser.add_argument("--patternsleuth-ref", required=True)
    parser.add_argument("--create-labels", action="store_true")
    return parser.parse_args(argv)


def sanitize_symbol(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def to_address(value: int):
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()  # noqa: F821
    return space.getAddress(value)


def executable(value: int) -> bool:
    block = currentProgram.getMemory().getBlock(to_address(value))  # noqa: F821
    return bool(block is not None and block.isExecute())


def read_u64(value: int) -> int | None:
    try:
        return int(currentProgram.getMemory().getLong(to_address(value))) & U64_MASK  # noqa: F821
    except Exception:
        return None


def initialized_chunks():
    """Yield (virtual address, bytes) while bounding Python/Java bridge memory."""

    memory = currentProgram.getMemory()  # noqa: F821
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = int(block.getStart().getOffset())
        end = int(block.getEnd().getOffset()) + 1
        cursor = start
        carry = b""
        while cursor < end:
            requested = min(CHUNK_SIZE, end - cursor)
            java_buffer = JArray(JByte)(requested)
            count = int(memory.getBytes(to_address(cursor), java_buffer))
            if count <= 0:
                break
            try:
                body = memoryview(java_buffer)[:count].tobytes()
            except TypeError:
                body = bytes((int(item) & 0xFF for item in java_buffer[:count]))
            combined = carry + body
            yield cursor - len(carry), combined
            carry = combined[-OVERLAP:]
            cursor += count


def find_many(needles: dict[str, bytes]) -> dict[str, list[int]]:
    results: dict[str, set[int]] = {key: set() for key in needles}
    for chunk_va, data in initialized_chunks():
        for key, needle in needles.items():
            cursor = 0
            while True:
                offset = data.find(needle, cursor)
                if offset < 0:
                    break
                results[key].add(chunk_va + offset)
                cursor = offset + 1
    return {key: sorted(values) for key, values in results.items()}


def direct_call_targets(function_va: int) -> list[int]:
    listing = currentProgram.getListing()  # noqa: F821
    manager = currentProgram.getFunctionManager()  # noqa: F821
    address = to_address(function_va)
    function = manager.getFunctionAt(address) or manager.getFunctionContaining(address)
    if function is None:
        return []
    targets: list[int] = []
    instructions = listing.getInstructions(function.getBody(), True)
    while instructions.hasNext():
        instruction = instructions.next()
        if not instruction.getFlowType().isCall():
            continue
        for target in instruction.getFlows():
            value = int(target.getOffset())
            if executable(value):
                targets.append(value)
    # Stable de-duplication while preserving instruction order.
    return list(dict.fromkeys(targets))


def neighboring_pair_score(table_va: int) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    for delta, label in ((-16, "previous"), (16, "next")):
        name_pointer = read_u64(table_va + delta)
        function_pointer = read_u64(table_va + delta + 8)
        if name_pointer and function_pointer and executable(function_pointer):
            score += 10
            reasons.append(f"{label}_pair_has_executable_target")
    return score, reasons


def create_candidate_label(value: int, label: str) -> str | None:
    symbol_table = currentProgram.getSymbolTable()  # noqa: F821
    address = to_address(value)
    existing = symbol_table.getGlobalSymbol(label, address)
    if existing is None:
        symbol_table.createLabel(address, label, SourceType.USER_DEFINED)
    return label


def scan_name(
    name: str,
    string_hits: list[int],
    table_hits: dict[int, list[int]],
    known_implementations: dict[str, int],
    label: bool,
) -> list[Candidate]:
    candidates: list[Candidate] = []
    implementation_seed = known_implementations.get(name)
    for string_va in string_hits:
        for table_va in table_hits.get(string_va, []):
            if table_va % 8:
                continue
            thunk_va = read_u64(table_va + 8)
            if thunk_va is None or not executable(thunk_va):
                continue
            score = 75
            reasons = ["exact_nul_terminated_ascii", "uht_name_pointer_pair", "paired_pointer_is_executable"]
            neighboring_score, neighboring_reasons = neighboring_pair_score(table_va)
            score += neighboring_score
            reasons.extend(neighboring_reasons)
            calls = direct_call_targets(thunk_va)
            implementations: list[int] = []
            if implementation_seed is not None and implementation_seed in calls:
                score += 20
                reasons.append("known_implementation_is_direct_call")
                implementations.append(implementation_seed)
            implementations.extend(value for value in calls if value not in implementations)
            labels: list[str] = []
            if label:
                base = sanitize_symbol(name)
                labels.append(create_candidate_label(thunk_va, f"palmod_candidate_exec_{base}"))
                if implementation_seed is not None:
                    labels.append(
                        create_candidate_label(
                            implementation_seed, f"palmod_candidate_impl_{base}"
                        )
                    )
            candidates.append(
                Candidate(
                    reflected_name=name,
                    string_va=string_va,
                    table_entry_va=table_va,
                    exec_thunk_va=thunk_va,
                    implementation_candidates=tuple(implementations),
                    score=score,
                    reasons=tuple(reasons),
                    labels_created=tuple(item for item in labels if item),
                )
            )
    return candidates


def main() -> None:
    args = parse_args([str(value) for value in getScriptArgs()])  # noqa: F821
    binary_path = str(currentProgram.getExecutablePath())  # noqa: F821
    actual_sha256 = sha256_file(binary_path)
    actual_build_id = build_id(binary_path)
    if args.expected_sha256 and actual_sha256.lower() != args.expected_sha256.lower():
        raise RuntimeError(
            f"SHA-256 mismatch: expected {args.expected_sha256}, got {actual_sha256}"
        )
    if args.expected_build_id and actual_build_id.lower() != args.expected_build_id.lower():
        raise RuntimeError(
            f"build ID mismatch: expected {args.expected_build_id}, got {actual_build_id}"
        )

    known_implementations: dict[str, int] = {}
    for value in args.known_implementation:
        name, separator, address = value.partition("=")
        if not separator:
            raise ValueError("--known-implementation must be NAME=0xADDRESS")
        known_implementations[name] = int(address, 0)

    image_base = min(
        int(block.getStart().getOffset())
        for block in currentProgram.getMemory().getBlocks()  # noqa: F821
        if block.isInitialized()
    )
    candidates: list[Candidate] = []
    transaction = None
    if args.create_labels:
        transaction = currentProgram.startTransaction("PalMod candidate labels")  # noqa: F821
    try:
        string_hits = find_many(
            {name: name.encode("ascii") + b"\0" for name in args.strings}
        )
        pointer_needles: dict[str, bytes] = {}
        pointer_keys: dict[str, int] = {}
        for name in args.strings:
            for index, string_va in enumerate(string_hits[name]):
                key = f"{name}:{index}"
                pointer_needles[key] = struct.pack("<Q", string_va)
                pointer_keys[key] = string_va
        raw_table_hits = find_many(pointer_needles) if pointer_needles else {}
        table_hits: dict[int, list[int]] = {}
        for key, hits in raw_table_hits.items():
            table_hits[pointer_keys[key]] = hits
        for name in args.strings:
            candidates.extend(
                scan_name(
                    name,
                    string_hits[name],
                    table_hits,
                    known_implementations,
                    args.create_labels,
                )
            )
    finally:
        if transaction is not None:
            currentProgram.endTransaction(transaction, True)  # noqa: F821

    evidence = make_evidence(
        binary_path=binary_path,
        binary_sha256=actual_sha256,
        elf_build_id=actual_build_id,
        image_base=image_base,
        candidates=candidates,
        input_refs={
            "patternsleuth": args.patternsleuth_ref,
            "ue4ss": args.ue4ss_ref,
        },
        analyzer={
            "ghidra_version": str(Application.getApplicationVersion()),
            "name": "palmod-ghidra-reflection-scan",
            "version": "0.1.0",
        },
        string_hits=string_hits,
    )
    write_json_atomic(args.out, evidence)
    print(f"PALMOD_EVIDENCE={args.out}")
    print(f"PALMOD_CANDIDATES={len(candidates)}")


main()
