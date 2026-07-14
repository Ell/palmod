#!/usr/bin/env python3
"""Recover FProperty inner-type offsets (StructProperty.Struct, ArrayProperty.Inner,
EnumProperty/ByteProperty.Enum) — needed to emit a complete .usmap. Owns the
server, finds known properties by name, and probes candidate offsets. Read-only.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib import labproc, reflection  # noqa: E402


def find_struct_object(mem, names, want):
    for _i, obj in reflection.enumerate_objects(mem):
        cls = mem.u64(obj + reflection.UOBJ_CLASS)
        if cls and reflection.object_name(mem, names, cls) in reflection.STRUCT_CLASS_NAMES:
            if reflection.object_name(mem, names, obj) == want:
                return obj
    return None


def property_fields(mem, want_struct, want_prop):
    """Return the FField VA of a named property in a named struct."""
    def walk(struct_va):
        fld = mem.u64(struct_va + reflection.USTRUCT_CHILDPROPS)
        seen = 0
        while fld and fld >> 40 == 0x7f and seen < 512:
            yield fld
            fld = mem.u64(fld + reflection.FFIELD_NEXT)
            seen += 1
    return walk


def main() -> int:
    timeout = int(os.environ.get("PALMOD_LAB_READY_TIMEOUT", "180"))
    proc, port = labproc.launch_owned_server()
    try:
        if not labproc.wait_ready(proc, port, timeout):
            print("not ready", file=sys.stderr)
            return 1
        pid = proc.pid
        print(f"ready (pid {pid})")
        mem = reflection.Mem(pid)
        names = reflection.FNames(mem)

        chat = find_struct_object(mem, names, "PalChatMessage")
        if not chat:
            print("PalChatMessage not found", file=sys.stderr)
            return 1
        print(f"PalChatMessage @ {chat:#x}")

        # Collect its property FFields by name.
        props = {}
        for fld in property_fields(mem, None, None)(chat):
            nm = names.get(mem.i32(fld + reflection.FFIELD_NAME))
            fclass = mem.u64(fld + reflection.FFIELD_CLASS)
            ptype = names.get(mem.i32(fclass)) if fclass else None
            props[nm] = (fld, ptype)
        for nm, (fld, ptype) in props.items():
            print(f"  {nm} ({ptype}) fld={fld:#x}")

        def probe_inner(nm, resolver_label):
            fld, ptype = props[nm]
            print(f"\n== {nm} ({ptype}) inner-type probe ==")
            for off in range(0x60, 0x98, 8):
                p = mem.u64(fld + off)
                if not p or p >> 40 != 0x7f:
                    continue
                # If p is a UObject (UScriptStruct/UClass/UEnum): name via UOBJ_NAME.
                nm2 = reflection.object_name(mem, names, p)
                if nm2 and nm2.isascii() and nm2.isprintable():
                    print(f"  +{off:#x} -> {p:#x} name={nm2!r} ({resolver_label})")

        # StructProperty: SenderPlayerUId -> its UScriptStruct.
        if "SenderPlayerUId" in props:
            probe_inner("SenderPlayerUId", "StructProperty.Struct")
        # ArrayProperty inner is an FProperty (not a UObject); probe for a field
        # whose own +0x08 FFieldClass resolves to a *Property type name.
        if "ReceiverPlayerUIds" in props:
            fld, _ = props["ReceiverPlayerUIds"]
            print("\n== ReceiverPlayerUIds (ArrayProperty).Inner probe ==")
            for off in range(0x60, 0x98, 8):
                p = mem.u64(fld + off)
                if not p or p >> 40 != 0x7f:
                    continue
                fc = mem.u64(p + reflection.FFIELD_CLASS)
                inner_type = names.get(mem.i32(fc)) if fc else None
                if inner_type and inner_type.endswith("Property"):
                    print(f"  +{off:#x} -> inner FProperty type {inner_type!r}")
        return 0
    finally:
        labproc.stop(proc)


if __name__ == "__main__":
    raise SystemExit(main())
