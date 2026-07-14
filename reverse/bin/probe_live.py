#!/usr/bin/env python3
"""Locate live `UFunction::Func` slots in the running server (reflection-hook prep).

Each reflected function's exec-thunk pointer appears in memory in two kinds of
place: the read-only UHT registration table (static data we already mapped) and
the writable `UFunction::Func` field of the live reflection object built at
startup. This probe owns the server, scans its memory for each thunk pointer,
and classifies the hits — the writable ones are the exact slots the reflection
hook backend will swap. Read-only: no hooks, no mutation.
"""
from __future__ import annotations

import os
import struct
import sys
import tomllib
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib import labproc  # noqa: E402

TARGETS = {
    "EnterChat": "enter_chat_exec_thunk",
    "AddItem_ServerInternal": "add_item_server_internal_exec_thunk",
    "BroadcastChatMessage": "broadcast_chat_message_exec_thunk",
}


def region_label(region: labproc.Region) -> str:
    if region.path:
        base = region.path.rsplit("/", 1)[-1]
        return f"{region.perms} {base}"
    return f"{region.perms} [anon]"


def main() -> int:
    profile_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        REVERSE_ROOT.parent / "profiles/candidates/palworld-linux-24088465.toml")
    profile = tomllib.loads(profile_path.read_text())
    base = profile["elf"]["image_base"]
    anchors = profile["anchors"]
    timeout = int(os.environ.get("PALMOD_LAB_READY_TIMEOUT", "180"))

    targets = {name: base + anchors[key]["rva"] for name, key in TARGETS.items()}

    print("probe: launching owned server")
    proc, port = labproc.launch_owned_server()
    try:
        if not labproc.wait_ready(proc, port, timeout):
            print("probe: server not ready; aborting", file=sys.stderr)
            return 1
        pid = proc.pid
        print(f"probe: ready (pid {pid}, rss {labproc.rss_mib(pid)} MiB, "
              f"{labproc.thread_count(pid)} threads)\n")

        needles = {value: name for name, value in targets.items()}
        # Scan readable, non-executable regions once each (registration data +
        # heap); skip code and the giant file-backed mmaps we don't need.
        hits: dict[str, list[tuple[int, labproc.Region]]] = {n: [] for n in targets}
        scanned = 0
        for region in labproc.iter_regions(pid):
            if "r" not in region.perms or "x" in region.perms:
                continue
            if region.path and not region.anonymous and "PalServer" not in region.path:
                continue  # only the main binary's data + anon/heap
            data = _read_region(pid, region)
            if not data:
                continue
            scanned += len(data)
            for value, name in needles.items():
                needle = struct.pack("<Q", value)
                index = data.find(needle)
                while index != -1:
                    va = region.start + index
                    if va % 8 == 0:
                        hits[name].append((va, region))
                    index = data.find(needle, index + 1)

        print(f"probe: scanned {scanned // (1 << 20)} MiB of data/heap\n")

        # Address ranges backed by the main binary (for spotting vtable/code ptrs).
        binary_ranges = [(r.start, r.end) for r in labproc.iter_regions(pid)
                         if "PalServer" in r.path]
        all_writable = [va for name in targets for va, r in hits[name] if r.writable]

        # Recover UFunction::Func offset: every real UFunction shares one vtable,
        # so the true offset is where the preceding qword is the SAME binary
        # pointer across the most Func slots.
        func_offset, vtable = _recover_func_offset(pid, all_writable, binary_ranges)
        if func_offset is not None:
            print(f"probe: UFunction vtable {vtable:#x}, Func offset {func_offset:#x} "
                  f"(agrees across {_matches(pid, all_writable, func_offset, vtable)}/"
                  f"{len(all_writable)} slots)\n")
        else:
            print("probe: could not resolve a consistent UFunction::Func offset\n")

        exit_code = 0
        for name, value in targets.items():
            found = hits[name]
            writable = [(va, r) for va, r in found if r.writable]
            readonly = [(va, r) for va, r in found if not r.writable]
            print(f"== {name} (exec thunk {value:#x}) ==")
            print(f"  read-only refs (registration table): {len(readonly)}")
            for va, region in readonly:
                print(f"    {va:#x}  {region_label(region)}")
            print(f"  writable refs (live candidates): {len(writable)}")
            for va, region in writable:
                is_ufunc = func_offset is not None and \
                    labproc.read_live(pid, va - func_offset, 8) == struct.pack("<Q", vtable)
                tag = (f"UFunction::Func (obj base {va - func_offset:#x})"
                       if is_ufunc else "native-lookup / delegate copy")
                print(f"    {va:#x}  {region_label(region)}   {tag}")
            if not writable:
                print("    none found")
                exit_code = exit_code or 2
            print()
        return exit_code
    finally:
        print("probe: stopping server")
        labproc.stop(proc)


def _in_binary(value: int, binary_ranges: list[tuple[int, int]]) -> bool:
    return any(start <= value < end for start, end in binary_ranges)


def _recover_func_offset(pid: int, slots: list[int],
                         binary_ranges: list[tuple[int, int]],
                         window: tuple[int, int] = (0x80, 0x148)):
    """Find the offset where the preceding qword is one shared binary pointer.

    Real UFunction objects all share the class vtable, so the correct Func offset
    is the candidate where the same binary pointer precedes the most Func slots.
    Returns (offset, vtable) or (None, None).
    """
    lo, hi = window
    votes: dict[tuple[int, int], int] = {}
    for slot in slots:
        buf = labproc.read_live(pid, slot - hi, hi)
        if not buf or len(buf) < hi:
            continue
        for offset in range(lo, hi, 8):
            value = struct.unpack_from("<Q", buf, hi - offset)[0]
            if _in_binary(value, binary_ranges):
                votes[(offset, value)] = votes.get((offset, value), 0) + 1
    if not votes:
        return None, None
    (offset, vtable), _ = max(votes.items(), key=lambda item: item[1])
    return offset, vtable


def _matches(pid: int, slots: list[int], offset: int, vtable: int) -> int:
    needle = struct.pack("<Q", vtable)
    return sum(1 for slot in slots
               if labproc.read_live(pid, slot - offset, 8) == needle)


def _read_region(pid: int, region: labproc.Region) -> bytes:
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as handle:
            handle.seek(region.start)
            return handle.read(region.end - region.start)
    except (OSError, PermissionError):
        return b""


if __name__ == "__main__":
    raise SystemExit(main())
