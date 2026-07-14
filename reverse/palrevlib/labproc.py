"""Reusable primitives for owning and reading a live lab server process.

Under yama `ptrace_scope=1` only an ancestor may read `/proc/<pid>/mem`, so the
process that reads memory must be the one that launched the server. These
helpers are shared by the observe/probe entry points.
"""
from __future__ import annotations

import os
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Region:
    start: int
    end: int
    perms: str
    path: str

    @property
    def writable(self) -> bool:
        return "w" in self.perms

    @property
    def anonymous(self) -> bool:
        return self.path == "" or self.path == "[heap]" or self.path.startswith("[anon")


def launch_owned_server(log_path: Path | None = None) -> tuple[subprocess.Popen, int]:
    lab_root = Path(os.environ["PALMOD_LAB_ROOT"])
    server = Path(os.environ["PALMOD_SERVER"])
    port = int(os.environ.get("PALMOD_LAB_PORT", "8211"))
    if log_path is None:
        log_path = lab_root / ".palmod-lab" / "server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("wb")
    proc = subprocess.Popen(
        [str(server), "Pal", f"-port={port}", "-useperfthreads",
         "-NoAsyncLoadingThread"],
        cwd=str(lab_root), stdout=handle, stderr=subprocess.STDOUT,
    )
    proc._palmod_log = handle  # type: ignore[attr-defined]
    return proc, port


def _port_bound(port: int) -> bool:
    result = subprocess.run(
        ["ss", "-lunH", f"sport = :{port}"],
        capture_output=True, text=True, check=False,
    )
    return bool(result.stdout.strip())


def wait_ready(proc: subprocess.Popen, port: int, timeout: int) -> bool:
    waited = 0
    while waited < timeout:
        if proc.poll() is not None:
            return False
        if _port_bound(port):
            return True
        time.sleep(2)
        waited += 2
    return False


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
    handle = getattr(proc, "_palmod_log", None)
    if handle is not None:
        handle.close()


def read_live(pid: int, va: int, length: int) -> bytes | None:
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as handle:
            handle.seek(va)
            return handle.read(length)
    except (PermissionError, OSError):
        return None


def rss_mib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 0


def thread_count(pid: int) -> int:
    try:
        return len(list(Path(f"/proc/{pid}/task").iterdir()))
    except OSError:
        return 0


def iter_regions(pid: int) -> list[Region]:
    regions: list[Region] = []
    try:
        lines = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except OSError:
        return regions
    for line in lines:
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        bounds, perms = parts[0], parts[1]
        start_hex, _, end_hex = bounds.partition("-")
        path = parts[5] if len(parts) == 6 else ""
        regions.append(Region(int(start_hex, 16), int(end_hex, 16), perms, path))
    return regions


def scan_pointer(pid: int, region: Region, value: int, chunk: int = 4 << 20) -> list[int]:
    """8-byte-aligned virtual addresses in `region` whose qword equals `value`."""
    needle = struct.pack("<Q", value)
    hits: list[int] = []
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as handle:
            position = region.start
            while position < region.end:
                span = min(chunk, region.end - position)
                handle.seek(position)
                try:
                    data = handle.read(span)
                except OSError:
                    break
                if not data:
                    break
                index = data.find(needle)
                while index != -1:
                    va = position + index
                    if va % 8 == 0:
                        hits.append(va)
                    index = data.find(needle, index + 1)
                # Overlap so a needle straddling a chunk edge is not missed.
                position += span - (len(needle) - 1) if span == chunk else span
    except (PermissionError, OSError):
        return hits
    return hits
