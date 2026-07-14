#!/usr/bin/env python3
"""Recover ABI hints for a profile's reflected functions (capstone-backed).

For each function the profile records, this disassembles the generated exec
thunk to estimate parameter arity from its marshalling calls, and disassembles a
real implementation's prologue to recover its incoming argument registers. It is
an optional deep step (needs capstone); the dependency-free `verify_profile.py`
remains the required static gate.
"""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))

from palrevlib.disasm import abi_footprint, analyze_thunk  # noqa: E402
from palrevlib.elf import load_segments, va_to_file_offset  # noqa: E402


def classify_impl(data, segments, va: int) -> str:
    offset = va_to_file_offset(segments, va)
    if offset is None:
        return "unmapped"
    return "ret-stub" if data[offset : offset + 1] == b"\xc3" else "real"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--only", action="append", default=[],
                        help="restrict to these function keys")
    args = parser.parse_args(argv)

    profile = tomllib.loads(args.profile.read_text())
    base = profile["elf"]["image_base"]
    data = args.binary.read_bytes()
    segments = load_segments(args.binary)
    functions = profile.get("functions", {})

    for name in sorted(functions):
        if args.only and name not in args.only:
            continue
        fn = functions[name]
        thunk_rva = fn.get("exec_thunk_rva")
        impl_rva = fn.get("implementation_rva")
        if thunk_rva is None or impl_rva is None:
            continue
        thunk_va = base + thunk_rva
        impl_va = base + impl_rva
        declared = fn.get("parameters", [])
        kind = classify_impl(data, segments, impl_va)

        print(f"== {name} ==")
        print(f"  path         : {fn.get('path', '?')}")
        decl = ", ".join(f"{p['name']}:{p['type_name']}" for p in declared) or "none"
        print(f"  declared args: {decl}")

        thunk = analyze_thunk(data, segments, thunk_va, impl_va)
        if thunk.impl_call_index is not None:
            linked = (f"call {thunk.impl_call_index + 1} of "
                      f"{len(thunk.call_targets)}")
        else:
            linked = "NOT FOUND"
        print(f"  thunk {thunk_va:#x}: {len(thunk.call_targets)} calls, "
              f"tail call into impl = {linked}")

        if kind == "real":
            fp = abi_footprint(data, segments, impl_va)
            print(f"  impl  {impl_va:#x} (real): {fp.describe()}")
        else:
            print(f"  impl  {impl_va:#x}: {kind} (no callable body)")
        print()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, KeyError, ValueError, RuntimeError) as error:
        print(f"decode_abi: {error}", file=sys.stderr)
        raise SystemExit(2) from error
