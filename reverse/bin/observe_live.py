#!/usr/bin/env python3
"""Passive live-image observation: own the server, verify anchors in its memory.

Under yama `ptrace_scope=1` only an ancestor may read `/proc/<pid>/mem`, so this
process launches PalServer as its own child and then reads it. Read-only: it
installs no hooks and mutates nothing, so it is safe against the unsigned
candidate profile. Environment (isolated HOME, lab paths) is set by
scripts/lab-observe.sh before exec.
"""
from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib import labproc  # noqa: E402


def parse_bytes(spec: str) -> bytes:
    return bytes(int(token, 16) for token in spec.split())


def main() -> int:
    server = Path(os.environ["PALMOD_SERVER"])
    timeout = int(os.environ.get("PALMOD_LAB_READY_TIMEOUT", "180"))
    profile_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        REVERSE_ROOT.parent / "profiles/candidates/palworld-linux-24088465.toml")

    profile = tomllib.loads(profile_path.read_text())
    base = profile["elf"]["image_base"]
    anchors = profile.get("anchors", {})

    print("observe: launching owned server")
    proc, port = labproc.launch_owned_server()
    try:
        if not labproc.wait_ready(proc, port, timeout):
            print("observe: server did not become ready; see lab log", file=sys.stderr)
            return 1
        pid = proc.pid
        print(f"observe: ready (pid {pid}, rss {labproc.rss_mib(pid)} MiB, "
              f"{labproc.thread_count(pid)} threads)")

        main_map = next((r for r in labproc.iter_regions(pid)
                         if server.name in r.path), None)
        if main_map is not None:
            print(f"observe: main load base = {main_map.start:#x}")

        print("\n== live anchor verification ==")
        passed = 0
        for name in sorted(anchors):
            anchor = anchors[name]
            va = base + anchor["rva"]
            expected = parse_bytes(anchor["expected_bytes"])
            actual = labproc.read_live(pid, va, len(expected))
            ok = actual == expected
            passed += ok
            detail = "" if ok else (
                "  <- not readable (ptrace/permission?)" if actual is None
                else f"  <- live={actual.hex(' ') if actual else '??'}")
            print(f"  [{'OK ' if ok else 'BAD'}] {name} @ {va:#x}{detail}")

        total = len(anchors)
        print(f"\nlive anchors: {passed}/{total} present and byte-exact in the "
              f"running server")
        return 0 if passed == total else 1
    finally:
        print("\nobserve: stopping child server")
        labproc.stop(proc)


if __name__ == "__main__":
    raise SystemExit(main())
