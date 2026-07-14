#!/usr/bin/env python3
"""Recover the engine/inheritance facts the loader needs, once per build.

These are STATIC per-build values (baked into the profile, keyed to the ELF
fingerprint) — the loader never needs a server at runtime. This tool recovers
them from a running server so a game update is a re-run, not a re-reverse:

  * UStruct::SuperStruct offset  — for the inventory IsA class check
  * GEngine global VA            — the game-thread drain pump anchor
  * UEngine::Tick vtable slot    — where the drain pump hooks (EngineTick)

SuperStruct + GEngine are pure live-memory reads; the Tick slot is a static byte
scan of .text for the `GEngine->Tick(...)` virtual call in the engine main loop.

    scripts/lab-run.sh reverse/bin/recover_engine_facts.py   (owns its own server)
    # or against a running server:
    python reverse/bin/recover_engine_facts.py --pid <pid> --binary <PalServer...>
"""
from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from pathlib import Path

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))
from palrevlib import labproc  # noqa: E402
from palrevlib.reflection import (Mem, FNames, enumerate_objects, object_name,  # noqa: E402
                                  UOBJ_CLASS, IMAGE_BASE)

IMAGE_HI = 0x10000000  # upper bound of fixed image VAs (non-heap)


def recover_super_struct_offset(mem, names, samples=300):
    """Find the offset whose SuperStruct chain reaches 'Object' for most classes."""
    classes = []
    for _i, obj in enumerate_objects(mem):
        cls = mem.u64(obj + UOBJ_CLASS)
        if cls and object_name(mem, names, cls) == "Class":
            classes.append(obj)
            if len(classes) >= samples:
                break
    best = None
    for off in range(0x30, 0x60, 8):
        good = 0
        for cobj in classes:
            cur, depth = cobj, 0
            while cur and cur >> 40 == 0x7f and depth < 24:
                if object_name(mem, names, cur) == "Object":
                    good += 1
                    break
                cur = mem.u64(cur + off)
                depth += 1
        if classes and good >= 0.8 * len(classes):
            best = (off, good, len(classes))
            break
    return best


def recover_gengine(pid, mem, names):
    """Find the GameEngine singleton, then the single image slot holding its addr."""
    engine = None
    clsname: dict[int, str | None] = {}
    for _i, obj in enumerate_objects(mem):
        cls = mem.u64(obj + UOBJ_CLASS)
        if not cls:
            continue
        if cls not in clsname:
            clsname[cls] = object_name(mem, names, cls)
        cn = clsname[cls]
        if cn and cn.endswith("GameEngine"):
            nm = object_name(mem, names, obj)
            if nm and not nm.startswith("Default__"):
                engine = obj
                break
    if not engine:
        return None, None
    needle = struct.pack("<Q", engine)
    hits = []
    for region in labproc.iter_regions(pid):
        if "w" not in region.perms:
            continue
        data = labproc.read_live(pid, region.start, region.end - region.start)
        if not data:
            continue
        idx = data.find(needle)
        while idx != -1:
            va = region.start + idx
            if idx % 8 == 0 and IMAGE_BASE <= va < IMAGE_HI:
                hits.append(va)
            idx = data.find(needle, idx + 1)
    return hits, engine


def _match_vtable_call(b, j, gengine_reg):
    """At b[j], match `mov (%gengine_reg),%rax ; call *disp(%rax)`; return slot."""
    if j + 3 > len(b):
        return None
    need_b = gengine_reg >= 8
    if b[j] != (0x48 | (0x01 if need_b else 0)) or b[j + 1] != 0x8b:
        return None
    rm = gengine_reg & 7
    if rm in (4, 5):  # rsp/rbp need SIB/disp forms; not seen for GEngine
        return None
    if b[j + 2] != rm:  # mod=00, reg=000 (rax), rm=gengine_reg
        return None
    k = j + 3
    if k + 2 > len(b) or b[k] != 0xff:
        return None
    m2 = b[k + 1]
    if (m2 & 0x38) != 0x10 or (m2 & 7) != 0:  # /2 (call), base rax
        return None
    mod = m2 >> 6
    if mod == 0b01:
        return b[k + 2] // 8
    if mod == 0b10:
        return int.from_bytes(b[k + 2:k + 6], "little") // 8
    if mod == 0b00:
        return 0
    return None


def recover_tick_slot_sites(binary: Path, gengine_va: int):
    """Scan .text for `mov reg,[rip->GEngine]; mov (reg),%rax; call *disp(%rax)`.

    Returns {slot: [call_site_va, ...]} — every GEngine virtual-dispatch site.
    GEngine has many virtual methods, so this yields a set; `Tick` is picked by
    location (it is the one in the engine main loop, see main_loop_pcs)."""
    out = subprocess.run(["objdump", "-h", str(binary)], capture_output=True, text=True).stdout
    text_vma = text_off = text_size = None
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 6 and f[1] == ".text":
            text_size = int(f[2], 16); text_vma = int(f[3], 16); text_off = int(f[5], 16)
            break
    if text_vma is None:
        return {}
    text = binary.read_bytes()[text_off:text_off + text_size]
    sites: dict[int, list[int]] = {}
    n = len(text)
    i = 0
    while i + 7 <= n:
        rex = text[i]
        if rex in (0x48, 0x4c) and text[i + 1] == 0x8b and (text[i + 2] & 0xc7) == 0x05:
            disp = int.from_bytes(text[i + 3:i + 7], "little", signed=True)
            target = (text_vma + i + 7 + disp) & 0xffffffffffffffff
            if target == gengine_va:
                reg = ((text[i + 2] >> 3) & 7) | (0x8 if (rex & 0x4) else 0)
                slot = _match_vtable_call(text, i + 7, reg)
                if slot is not None:
                    sites.setdefault(slot, []).append(text_vma + i)
                i += 7
                continue
        i += 1
    return sites


def main_loop_pcs(pid):
    """Frame PCs of the main (game) thread — these land in the engine main loop,
    which is exactly where GEngine->Tick is called."""
    script = ("set pagination off\nset confirm off\nset debuginfod enabled off\n"
              f"attach {pid}\nthread 1\nbt -30\ndetach\nquit\n")
    sp = Path(f"/tmp/palmod-recover-{pid}.gdb")
    sp.write_text(script)
    try:
        out = subprocess.run(["gdb", "-q", "-batch", "-x", str(sp)],
                             capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return []
    finally:
        sp.unlink(missing_ok=True)
    pcs = []
    for line in out.splitlines():
        m = line.strip()
        if m.startswith("#"):
            for tok in m.split():
                if tok.startswith("0x"):
                    try:
                        pcs.append(int(tok, 16))
                    except ValueError:
                        pass
                    break
    return pcs


def pick_tick_slot(sites, pcs):
    """The Tick slot = the GEngine v-call site nearest a main-loop frame PC."""
    best_slot, best_dist, best_va = None, 1 << 62, None
    for slot, addrs in sites.items():
        for a in addrs:
            d = min((abs(a - pc) for pc in pcs), default=1 << 62)
            if d < best_dist:
                best_slot, best_dist, best_va = slot, d, a
    return best_slot, best_dist, best_va


def find_pid():
    out = subprocess.run(["pgrep", "-f", "PalServer-Linux-Shipping"],
                         capture_output=True, text=True).stdout.split()
    return int(out[0]) if out else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--binary", type=Path, default=None)
    args = ap.parse_args()

    pid = args.pid or find_pid()
    if not pid:
        print("no PalServer pid (pass --pid or start the lab server)", file=sys.stderr)
        return 2
    binary = args.binary or Path(f"/proc/{pid}/exe").resolve()

    mem = Mem(pid)
    names = FNames(mem)

    print(f"pid={pid} binary={binary}")
    ss = recover_super_struct_offset(mem, names)
    if ss:
        print(f"super_struct_offset = 0x{ss[0]:x}   ({ss[1]}/{ss[2]} classes reach Object)")
    else:
        print("super_struct_offset = FAILED")

    hits, engine = recover_gengine(pid, mem, names)
    gengine_va = None
    if engine and isinstance(hits, list) and len(hits) == 1:
        gengine_va = hits[0]
        print(f"gengine_global_va  = 0x{gengine_va:x}   (engine obj 0x{engine:x})")
    else:
        print(f"gengine_global_va  = AMBIGUOUS/FAILED hits={hits}")

    if gengine_va:
        sites = recover_tick_slot_sites(binary, gengine_va)
        pcs = main_loop_pcs(pid)
        slot, dist, va = pick_tick_slot(sites, pcs)
        if slot is not None and dist < 0x4000:
            print(f"engine_tick_vtable_slot = {slot}   "
                  f"(v-call @0x{va:x}, {dist:#x} from a main-loop frame; "
                  f"candidates {sorted(sites)})")
        else:
            print(f"engine_tick_vtable_slot = UNSURE (candidates {sorted(sites)}, "
                  f"nearest dist {dist:#x}); confirm against the main loop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
