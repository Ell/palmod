#!/usr/bin/env python3
"""Dependency-free static gate for a PalMod build profile against a real ELF.

This is the automatable backbone of the reversing workflow: it reproduces, in
under a second and with no Ghidra/Frida/privileges, the checks that promote a
profile along the static half of the evidence ladder:

  1. fingerprint     - sha256 / build-id / size / image base match the profile
  2. anchors         - every anchor's expected_bytes are byte-exact in the ELF,
                       with executability matching its validators
  3. thunk linkage   - each function's exec thunk contains a direct `E8` call to
                       its recorded implementation (independent of the anchors)
  4. impl triage     - classify each implementation as a real function or a
                       generated `ret` stub (UE emits stubs for unshipped bodies)

Exit code 0 only when the fingerprint and every anchor verify. Thunk/impl facts
are reported for review; ret stubs are expected for some reflected functions.
"""
from __future__ import annotations

import argparse
import struct
import sys
import tomllib
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))

from palrevlib.elf import (  # noqa: E402
    build_id,
    load_segments,
    sha256_file,
    va_to_file_offset,
)


def parse_bytes(spec: str) -> bytes:
    return bytes(int(token, 16) for token in spec.split())


def is_executable(segments, va: int) -> bool:
    return any(s.executable and s.contains_virtual_address(va) for s in segments)


def read_at_va(data: bytes, segments, va: int, length: int) -> bytes | None:
    offset = va_to_file_offset(segments, va)
    if offset is None:
        return None
    return data[offset : offset + length]


def read_live(pid: int, va: int, length: int) -> bytes | None:
    """Read `length` bytes at virtual address `va` from a running process.

    PalServer is ET_EXEC (fixed load), so anchor VAs are absolute at runtime.
    Requires ptrace access to the target (its parent, or same-user without a
    restrictive yama scope).
    """
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as handle:
            handle.seek(va)
            return handle.read(length)
    except (PermissionError, OSError):
        return None


def thunk_calls_target(data: bytes, segments, thunk_va: int, target_va: int,
                       window: int = 512) -> bool:
    """True if a `E8 rel32` inside the thunk window resolves to target_va."""
    body = read_at_va(data, segments, thunk_va, window)
    if not body:
        return False
    for i in range(0, max(0, len(body) - 5)):
        if body[i] != 0xE8:
            continue
        disp = struct.unpack_from("<i", body, i + 1)[0]
        if thunk_va + i + 5 + disp == target_va:
            return True
    return False


def classify_impl(data: bytes, segments, va: int) -> str:
    head = read_at_va(data, segments, va, 4) or b""
    if head[:1] == b"\xc3":
        return "ret-stub"
    if not head:
        return "unmapped"
    return "real"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path, help="candidate/validated .toml profile")
    parser.add_argument("binary", type=Path, help="PalServer-Linux-Shipping ELF")
    parser.add_argument("--pid", type=int, default=None,
                        help="also verify anchors against this running PID's live memory")
    args = parser.parse_args(argv)

    profile = tomllib.loads(args.profile.read_text())
    elf = profile["elf"]
    base = elf["image_base"]
    data = args.binary.read_bytes()
    segments = load_segments(args.binary)

    print(f"profile : {args.profile}")
    print(f"binary  : {args.binary}\n")

    print("== fingerprint ==")
    computed_base = min(s.virtual_address for s in segments)
    fp = [
        ("sha256", str(elf["sha256"]), sha256_file(args.binary)),
        ("build_id", str(elf["build_id"]), build_id(args.binary)),
        ("file_size", str(elf["file_size"]), str(args.binary.stat().st_size)),
        ("image_base", str(base), str(computed_base)),
    ]
    fp_ok = True
    for name, claimed, actual in fp:
        ok = claimed == actual
        fp_ok &= ok
        print(f"  [{'OK ' if ok else 'BAD'}] {name}: {actual}"
              + ("" if ok else f"  (profile claims {claimed})"))

    source = f"live pid {args.pid}" if args.pid is not None else "on-disk ELF"
    print(f"\n== anchors ({source}) ==")
    anchors = profile.get("anchors", {})
    passed = 0
    for name in sorted(anchors):
        anchor = anchors[name]
        va = base + anchor["rva"]
        expected = parse_bytes(anchor["expected_bytes"])
        if args.pid is not None:
            actual = read_live(args.pid, va, len(expected))
        else:
            actual = read_at_va(data, segments, va, len(expected))
        want_exec = "executable" in anchor.get("validators", [])
        exec_here = is_executable(segments, va)
        ok = actual == expected and (not want_exec or exec_here)
        passed += ok
        detail = "" if ok else (
            "  <- not readable (ptrace/permission?)" if actual is None
            else f"  <- bytes/exec mismatch (exec={exec_here})"
        )
        print(f"  [{'OK ' if ok else 'BAD'}] {name} @ {va:#x}{detail}")

    functions = profile.get("functions", {})
    if functions:
        print("\n== thunk -> implementation linkage ==")
        for name in sorted(functions):
            fn = functions[name]
            thunk_rva = fn.get("exec_thunk_rva")
            impl_rva = fn.get("implementation_rva")
            if thunk_rva is None or impl_rva is None:
                continue
            thunk_va = base + thunk_rva
            impl_va = base + impl_rva
            linked = thunk_calls_target(data, segments, thunk_va, impl_va)
            kind = classify_impl(data, segments, impl_va)
            mark = "OK " if linked else "?? "
            print(f"  [{mark}] {name}: thunk {thunk_va:#x} -> impl {impl_va:#x} "
                  f"({kind}){'' if linked else '  <- no direct E8 call found'}")

    total = len(anchors)
    print(f"\nfingerprint: {'PASS' if fp_ok else 'FAIL'} | "
          f"anchors: {passed}/{total} verified")
    return 0 if (fp_ok and passed == total) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, KeyError, ValueError) as error:
        print(f"verify_profile: {error}", file=sys.stderr)
        raise SystemExit(2) from error
