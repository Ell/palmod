#!/usr/bin/env python3
"""Confirm FNamePool allocator metadata + verify FName reverse-lookup (live).

For the mutation path we need string -> FName ComparisonIndex. That needs the
allocator's extent: FNameEntryAllocator lays out `uint32 CurrentBlock;
uint32 CurrentByteCursor;` immediately before the `Blocks[]` array (VA 0xc07b0c0),
and blocks are FNameBlockSizeBytes = 0x20000 each. This owns the server, reads
those, walks the pool building name->index, and confirms a round trip against the
existing forward decoder. Read-only, no client needed.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib import labproc  # noqa: E402

BLOCKS_VA = 0x0C07B0C0          # FNameEntryAllocator.Blocks
CURRENT_BLOCK_VA = BLOCKS_VA - 8    # candidate: uint32 CurrentBlock
CURSOR_VA = BLOCKS_VA - 4           # candidate: uint32 CurrentByteCursor
BLOCK_BYTES = 0x20000          # FNameBlockSizeBytes (2^16 offsets * 2-byte align)
MAX_BLOCKS_WALK = 400


def u32(b):
    return struct.unpack("<I", b)[0] if b and len(b) == 4 else None


def u64(b):
    return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None


def walk_block(data, block):
    """Yield (comparison_index, name) for entries in one block's bytes."""
    off = 0
    n = len(data)
    while off + 2 <= n:
        hdr = struct.unpack_from("<H", data, off)[0]
        if hdr == 0:
            break
        length = hdr >> 6
        wide = hdr & 1
        if length == 0:
            break
        size = length * (2 if wide else 1)
        if off + 2 + size > n:
            break
        raw = data[off + 2: off + 2 + size]
        try:
            name = raw.decode("utf-16-le" if wide else "latin-1", "replace")
        except Exception:
            name = None
        index = (block << 16) | (off >> 1)
        if name:
            yield index, name
        off += 2 + size
        off = (off + 1) & ~1


def main() -> int:
    proc, pid = labproc.launch_owned_server()
    try:
        if not labproc.wait_ready(proc, 8211, timeout=200):
            print("server not ready", file=sys.stderr)
            return 2
        # Let world/data tables load so item names are registered.
        import time
        deadline = time.time() + 180
        while time.time() < deadline:
            if labproc.rss_mib(pid) > 750:
                break
            if proc.poll() is not None:
                print("server exited early", file=sys.stderr)
                return 2
            time.sleep(3)
        print(f"pid={pid} rss={labproc.rss_mib(pid)}MiB")

        current_block = u32(labproc.read_live(pid, CURRENT_BLOCK_VA, 4))
        cursor = u32(labproc.read_live(pid, CURSOR_VA, 4))
        print(f"CurrentBlock@Blocks-8 = {current_block}")
        print(f"CurrentByteCursor@Blocks-4 = {cursor} (0x{cursor:x})" if cursor is not None else "cursor=None")

        sane = (current_block is not None and 0 <= current_block < MAX_BLOCKS_WALK
                and cursor is not None and 0 <= cursor <= BLOCK_BYTES)
        print(f"metadata_sane = {sane}")
        if not sane:
            return 1

        # Build name->index across all used blocks; confirm a round trip.
        name_to_index: dict[str, int] = {}
        total = 0
        for block in range(current_block + 1):
            block_ptr = u64(labproc.read_live(pid, BLOCKS_VA + block * 8, 8))
            if not block_ptr:
                continue
            used = cursor if block == current_block else BLOCK_BYTES
            data = labproc.read_live(pid, block_ptr, used)
            if not data:
                continue
            for index, name in walk_block(data, block):
                total += 1
                name_to_index.setdefault(name, index)
        print(f"walked {total} entries, {len(name_to_index)} unique names")

        # Verify: pick recognizable names and round-trip via the forward decoder.
        from palrevlib.reflection import Mem, FNames
        mem = Mem(pid)
        fnames = FNames(mem)
        checked = 0
        for probe in ["BroadcastChatMessage", "None", "PalPlayerState", "ByteProperty"]:
            idx = name_to_index.get(probe)
            if idx is None:
                print(f"  '{probe}': not found")
                continue
            back = fnames.get(idx)
            ok = back == probe
            checked += ok
            print(f"  '{probe}': index=0x{idx:x} -> decode='{back}' {'OK' if ok else 'MISMATCH'}")

        # Show a few item-like names as evidence the item table is loaded.
        items = sorted(n for n in name_to_index if n.startswith("PalSphere") or n.startswith("Wood"))[:8]
        print(f"sample item-ish names: {items}")
        return 0 if checked >= 2 else 1
    finally:
        labproc.stop(proc)


if __name__ == "__main__":
    raise SystemExit(main())
