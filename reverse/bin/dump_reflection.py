#!/usr/bin/env python3
"""Generate our own reflection mappings from the live Linux server.

Owns the server, walks GUObjectArray, and emits a JSON schema-with-offsets for
every UStruct/UClass/UFunction — the authoritative, version-exact map we can't
get from a community .usmap (which carries no offsets). Read-only.

    scripts/lab-env.sh sourced, then: python reverse/bin/dump_reflection.py [out.json]
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib import labproc, reflection  # noqa: E402


def main() -> int:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        REVERSE_ROOT.parent / "build" / "palworld-24088465-reflection.json")
    timeout = int(os.environ.get("PALMOD_LAB_READY_TIMEOUT", "180"))

    print("dump_reflection: launching owned server")
    proc, port = labproc.launch_owned_server()
    try:
        if not labproc.wait_ready(proc, port, timeout):
            print("server not ready", file=sys.stderr)
            return 1
        pid = proc.pid
        print(f"ready (pid {pid}, {labproc.rss_mib(pid)} MiB); walking reflection...")

        mem = reflection.Mem(pid)
        names = reflection.FNames(mem)
        num = mem.i32(reflection.GUOBJECTARRAY_OBJECTS + reflection.NUM_ELEMENTS_OFFSET)
        print(f"  GUObjectArray NumElements = {num}")

        started = time.monotonic() if hasattr(time, "monotonic") else 0
        by_kind: dict[str, int] = {}
        structs = []
        for s in reflection.dump_structs(mem, names):
            by_kind[s.kind] = by_kind.get(s.kind, 0) + 1
            structs.append({
                "name": s.name,
                "kind": s.kind,
                "func_rva": s.func_rva,
                "path": s.path,
                "properties": [
                    {"name": p.name, "type": p.type, "offset": p.offset,
                     "elem_size": p.elem_size, "inner": p.inner,
                     "inner_size": p.inner_size}
                    for p in s.properties
                ],
            })
        mem.close()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({
            "build": "palworld-linux-24088465",
            "engine": "UE5.1",
            "source": "live in-process reflection walk",
            "struct_count": len(structs),
            "structs": structs,
        }, indent=1))

        prop_total = sum(len(s["properties"]) for s in structs)
        print(f"\n  dumped {len(structs)} structs ({prop_total} properties) -> {out_path}")
        print(f"  by kind: {by_kind}")

        # Spot-check: chat + inventory schema we hand-reversed earlier.
        for want in ("PalPlayerState", "BroadcastChatMessage", "AddItem_ServerInternal"):
            hit = next((s for s in structs if s["name"] == want), None)
            if hit:
                props = ", ".join(f"{p['name']}@{p['offset']}({p['type']})"
                                  for p in hit["properties"][:6])
                print(f"  {want} [{hit['kind']}]: {props}")
        return 0
    finally:
        print("\ndump_reflection: stopping server")
        labproc.stop(proc)


if __name__ == "__main__":
    raise SystemExit(main())
