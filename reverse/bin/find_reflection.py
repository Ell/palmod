#!/usr/bin/env python3
"""Locate the live reflection globals needed to dump a .usmap on the Linux server.

Step 1 of the in-process reflection dumper (see docs/design/reflection-mappings.md).
Owns the server, resolves a known UObject (EnterChat's UFunction via its Func
slot), reads the UObject header at candidate UE-5.1 offsets, and scans memory for
the object pointer to locate FUObjectItem entries -> GUObjectArray. Read-only.
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib import labproc  # noqa: E402

IMAGE_BASE = 0x200000
ENTER_CHAT_THUNK = 0x6c6e980
UFUNCTION_VTABLE = 0x1a48018
UFUNCTION_FUNC_OFFSET = 0xd8

# Candidate UE 5.1 UObjectBase field offsets (to validate).
OBJ = {
    "flags@0x08": (0x08, "i32"),
    "internalindex@0x0c": (0x0c, "i32"),
    "classprivate@0x10": (0x10, "ptr"),
    "fname_cmp@0x18": (0x18, "i32"),
    "fname_num@0x1c": (0x1c, "i32"),
    "outer@0x20": (0x20, "ptr"),
}


def rd(pid, va, n):
    return labproc.read_live(pid, va, n)


def u64(b):
    return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None


def i32(b):
    return struct.unpack("<i", b)[0] if b and len(b) == 4 else None


def find_ufunction_object(pid, regions):
    """Find a live UFunction: writable qword == thunk VA with vtable at -0xd8."""
    needle = struct.pack("<Q", ENTER_CHAT_THUNK)
    vtable = struct.pack("<Q", UFUNCTION_VTABLE)
    for region in regions:
        if "w" not in region.perms or region.path.startswith("/"):
            continue
        data = rd(pid, region.start, region.end - region.start)
        if not data:
            continue
        idx = data.find(needle)
        while idx != -1:
            va = region.start + idx
            if va % 8 == 0:
                header = rd(pid, va - UFUNCTION_FUNC_OFFSET, 8)
                if header == vtable:
                    return va - UFUNCTION_FUNC_OFFSET  # object base
            idx = data.find(needle, idx + 1)
    return None


def main():
    timeout = int(os.environ.get("PALMOD_LAB_READY_TIMEOUT", "180"))
    print("find_reflection: launching owned server")
    proc, port = labproc.launch_owned_server()
    try:
        if not labproc.wait_ready(proc, port, timeout):
            print("server not ready", file=sys.stderr)
            return 1
        pid = proc.pid
        print(f"ready (pid {pid}, {labproc.rss_mib(pid)} MiB)\n")
        regions = labproc.iter_regions(pid)

        obj = find_ufunction_object(pid, regions)
        if obj is None:
            print("could not find a live UFunction object", file=sys.stderr)
            return 1
        print(f"== live UFunction (EnterChat) object base = {obj:#x} ==")
        print(f"  vtable@0x00 = {u64(rd(pid, obj, 8)):#x}")
        internal_index = None
        class_private = None
        fname_cmp = None
        for label, (off, kind) in OBJ.items():
            if kind == "ptr":
                val = u64(rd(pid, obj + off, 8))
                print(f"  {label} = {val:#x}" if val is not None else f"  {label} = ?")
                if off == 0x10:
                    class_private = val
            else:
                val = i32(rd(pid, obj + off, 4))
                print(f"  {label} = {val}")
                if off == 0x0c:
                    internal_index = val
                if off == 0x18:
                    fname_cmp = val

        # ClassPrivate should point to the UClass "Function" (a UObject w/ vtable).
        if class_private:
            cp_vtable = u64(rd(pid, class_private, 8))
            print(f"  -> ClassPrivate {class_private:#x} vtable = "
                  f"{cp_vtable:#x}" if cp_vtable else "  -> ClassPrivate unreadable")

        # A UObject pointer is valid if its vtable lands in the binary image.
        image_lo, image_hi = IMAGE_BASE, 0x0d000000

        def looks_like_uobject(ptr):
            if not ptr or ptr % 8 or ptr >> 40 != 0x7f:
                return False
            vt = u64(rd(pid, ptr, 8))
            return vt is not None and image_lo <= vt < image_hi

        # Scan for pointers to `obj`; the FUObjectItem in GUObjectArray's chunk is
        # the one where chunk_base = hit - InternalIndex*sizeof(FUObjectItem) and
        # neighbouring 24-byte slots also hold valid UObject pointers.
        print(f"\n== locating GUObjectArray chunk (InternalIndex={internal_index}) ==")
        needle = struct.pack("<Q", obj)
        item_size = 24  # {UObject* Object, i32 Flags, i32 ClusterRoot, i32 Serial}
        chunk_base = None
        for region in regions:
            if "w" not in region.perms or region.path.startswith("/"):
                continue
            data = rd(pid, region.start, region.end - region.start)
            if not data:
                continue
            idx = data.find(needle)
            while idx != -1:
                va = region.start + idx
                if va % 8 == 0:
                    base = va - internal_index * item_size
                    # Validate: sample several slots as UObject pointers.
                    good = sum(looks_like_uobject(u64(rd(pid, base + k * item_size, 8)))
                               for k in (0, 1, 2, internal_index, internal_index + 1))
                    if good >= 4:
                        chunk_base = base
                        print(f"  FUObjectItem @ {va:#x} -> chunk base {base:#x} "
                              f"(item_size={item_size}, {good}/5 slots valid)")
                        break
                idx = data.find(needle, idx + 1)
            if chunk_base:
                break
        if not chunk_base:
            print("  no chunk base validated (item_size or layout may differ)")
            return 1

        # GUObjectArray.Objects[0] holds chunk_base. Find that pointer, then find
        # the pointer to *that* array — a fixed .bss VA = the GUObjectArray global.
        def find_pointer_to(value):
            n = struct.pack("<Q", value)
            out = []
            for region in regions:
                if "w" not in region.perms or region.path.startswith("/"):
                    continue
                data = rd(pid, region.start, region.end - region.start)
                if not data:
                    continue
                j = data.find(n)
                while j != -1 and len(out) < 8:
                    va = region.start + j
                    if va % 8 == 0:
                        # A .bss global is a low, non-heap address (not 0x7f...).
                        out.append((va, (va >> 40) != 0x7f))
                    j = data.find(n, j + 1)
            return out

        print("\n== chasing to the GUObjectArray global ==")
        chunk_ptrs = find_pointer_to(chunk_base)
        for va, fixed in chunk_ptrs:
            print(f"  &chunk in chunk-ptr-array @ {va:#x}{'  [fixed/bss]' if fixed else ''}")
        # The chunk-ptr array base is the first such hit; find who points to it.
        if chunk_ptrs:
            array_base = min(va for va, _ in chunk_ptrs)
            print(f"  chunk-ptr array base ~ {array_base:#x}")
            owners = find_pointer_to(array_base)
            for va, fixed in owners:
                tag = "  <- GUObjectArray global (fixed .bss)" if fixed else ""
                rva = f" rva={va - IMAGE_BASE:#x}" if fixed else ""
                print(f"  GUObjectArray.Objects @ {va:#x}{rva}{tag}")

        # --- FNamePool: find the block holding EnterChat's FNameEntry, chase to
        # the fixed Blocks[] global. FNameEntryId 314463 -> block/offset. ---
        print(f"\n== locating FNamePool (EnterChat cmp index {fname_cmp}) ==")
        block_offset_bits = 16
        block = fname_cmp >> block_offset_bits
        offset_units = fname_cmp & ((1 << block_offset_bits) - 1)
        byte_offset = offset_units * 2  # FNameEntryAllocationGranularity = 2
        print(f"  block={block} offset_units={offset_units:#x} byte_offset={byte_offset:#x}")
        name = b"EnterChat"
        entry_start = None
        for region in regions:
            if "w" not in region.perms or region.path.startswith("/"):
                continue
            data = rd(pid, region.start, region.end - region.start)
            if not data:
                continue
            j = data.find(name)
            while j != -1:
                # FNameEntry header (u16) precedes the chars: Len = header >> 6.
                hdr = struct.unpack_from("<H", data, j - 2)[0] if j >= 2 else 0
                if (hdr >> 6) == len(name):
                    entry_start = region.start + j - 2
                    print(f"  FNameEntry('EnterChat') @ {entry_start:#x} (hdr={hdr:#06x}, len={hdr>>6})")
                    break
                j = data.find(name, j + 1)
            if entry_start:
                break
        blocks_base = None
        if entry_start:
            block_base = entry_start - byte_offset
            print(f"  block[{block}] base = {block_base:#x}")
            for va, fixed in find_pointer_to(block_base):
                pool = va - block * 8  # Blocks[block] is at Blocks + block*8
                tag = "  <- FNamePool.Blocks (fixed)" if fixed else ""
                rva = f" rva={pool - IMAGE_BASE:#x}" if fixed else ""
                print(f"  &block[{block}] @ {va:#x} -> FNamePool.Blocks ~ {pool:#x}{rva}{tag}")
                if fixed and blocks_base is None:
                    blocks_base = pool

        # --- Resolve FNames, then walk EnterChat's FProperty chain to nail the
        #     UStruct/FField/FProperty layout. ---
        def resolve_fname(cmp):
            if blocks_base is None or cmp is None:
                return None
            blk = u64(rd(pid, blocks_base + (cmp >> 16) * 8, 8))
            if not blk:
                return None
            entry = blk + (cmp & 0xffff) * 2
            hb = rd(pid, entry, 2)
            if not hb:
                return None
            hdr = struct.unpack("<H", hb)[0]
            ln, wide = hdr >> 6, hdr & 1
            raw = rd(pid, entry + 2, ln * (2 if wide else 1))
            if not raw:
                return None
            return raw.decode("utf-16-le" if wide else "latin-1", "replace")

        print(f"\n== FName resolution check ==")
        print(f"  cmp {fname_cmp} -> {resolve_fname(fname_cmp)!r} (expect 'EnterChat')")

        def heapish(p):
            return p is not None and p >> 40 == 0x7f and p % 8 == 0

        # Find ChildProperties: a UStruct field that points to an FField whose own
        # NamePrivate (at candidate +0x28) resolves to a name.
        print("\n== probing UStruct.ChildProperties / FField layout ==")
        for cp_off in (0x40, 0x48, 0x50, 0x38):
            head = u64(rd(pid, obj + cp_off, 8))
            if not heapish(head):
                continue
            for name_off in (0x28, 0x20, 0x18):
                nm = i32(rd(pid, head + name_off, 4))
                resolved = resolve_fname(nm) if nm and nm > 0 else None
                if resolved and resolved.isascii() and resolved.isprintable():
                    print(f"  ChildProperties@{cp_off:#x}, FField.Name@{name_off:#x}"
                          f" -> first prop {resolved!r}")
                    # Walk the chain trying Next @ candidate offsets.
                    for next_off in (0x20, 0x28, 0x30):
                        names, off_col, fld, seen = [], [], head, 0
                        while heapish(fld) and seen < 12:
                            pn = resolve_fname(i32(rd(pid, fld + name_off, 4)))
                            names.append(pn)
                            off_col.append(i32(rd(pid, fld + 0x4c, 4)))
                            fld = u64(rd(pid, fld + next_off, 8))
                            seen += 1
                        if len(names) >= 2 and all(n and n.isascii() for n in names):
                            print(f"    Next@{next_off:#x}: props={names} offset@0x4c={off_col}")
                            break
                    break
        return 0
    finally:
        print("\nfind_reflection: stopping server")
        labproc.stop(proc)


if __name__ == "__main__":
    raise SystemExit(main())
