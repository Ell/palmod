"""Optional capstone-backed ABI recovery for exec thunks and native functions.

Capstone is an *optional* extra (like Ghidra/Frida): this module imports it
lazily so the rest of `palrevlib` stays dependency-free. Everything here reports
ABI *hints* recovered structurally from disassembly — an arity estimate from the
thunk's marshalling calls and the implementation's incoming argument registers —
not a full decompilation.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from palrevlib.elf import LoadSegment, va_to_file_offset


def _capstone():
    try:
        import capstone  # noqa: PLC0415
    except ModuleNotFoundError as error:  # pragma: no cover - env dependent
        raise RuntimeError(
            "capstone is required for ABI decoding; install it into a venv: "
            "python -m venv .venv && .venv/bin/pip install capstone"
        ) from error
    return capstone


# System V AMD64 argument registers, mapped from every sub-register name to the
# canonical 64-bit parent so `edi`/`di`/`dil` all count as `rdi`.
_INT_ARGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_SUBREG = {
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9": "r9", "r9d": "r9", "r9w": "r9", "r9b": "r9",
}
_ZEROING = {"xor", "sub", "pxor", "xorps", "xorpd"}


def _disassembler():
    cs = _capstone()
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    return md


def _code_at(data: bytes, segments: list[LoadSegment], va: int, length: int) -> bytes:
    offset = va_to_file_offset(segments, va)
    if offset is None:
        raise ValueError(f"VA {va:#x} is not file-backed")
    return data[offset : offset + length]


@dataclass(slots=True)
class ThunkReport:
    thunk_va: int
    impl_va: int
    call_targets: list[int] = field(default_factory=list)
    impl_call_index: int | None = None

    @property
    def marshalling_calls(self) -> int:
        """Calls before the tail call into the implementation (arity hint)."""
        return self.impl_call_index if self.impl_call_index is not None else 0


def analyze_thunk(data: bytes, segments: list[LoadSegment], thunk_va: int,
                  impl_va: int, window: int = 1024) -> ThunkReport:
    md = _disassembler()
    report = ThunkReport(thunk_va=thunk_va, impl_va=impl_va)
    code = _code_at(data, segments, thunk_va, window)
    for insn in md.disasm(code, thunk_va):
        if insn.mnemonic == "ret":
            break
        if insn.mnemonic == "call" and insn.bytes and insn.bytes[0] == 0xE8:
            disp = struct.unpack_from("<i", insn.bytes, 1)[0]
            target = insn.address + insn.size + disp
            if target == impl_va and report.impl_call_index is None:
                report.impl_call_index = len(report.call_targets)
            report.call_targets.append(target)
    return report


@dataclass(slots=True)
class AbiFootprint:
    int_args: list[str] = field(default_factory=list)
    float_args: list[str] = field(default_factory=list)
    stopped_at_call: bool = False

    def describe(self) -> str:
        ints = ", ".join(self.int_args) or "none"
        floats = ", ".join(self.float_args) or "none"
        return (f"{len(self.int_args)} integer/ptr [{ints}] + "
                f"{len(self.float_args)} float [{floats}]")


def abi_footprint(data: bytes, segments: list[LoadSegment], impl_va: int,
                  max_insns: int = 80, window: int = 512) -> AbiFootprint:
    """Recover incoming argument registers read-before-written in the prologue.

    Walks the function until the first `call` (after which arg registers are
    clobbered), tracking which System V argument registers are read as inputs.
    Register self-zeroing idioms (`xor r,r`) count as writes, not reads.
    """
    md = _disassembler()
    footprint = AbiFootprint()
    written: set[str] = set()
    seen_float: set[str] = set()
    code = _code_at(data, segments, impl_va, window)
    for count, insn in enumerate(md.disasm(code, impl_va)):
        if count >= max_insns:
            break
        if insn.mnemonic == "call":
            footprint.stopped_at_call = True
            break
        reads, writes = insn.regs_access()
        read_names = {insn.reg_name(r) for r in reads}
        write_names = {insn.reg_name(r) for r in writes}
        # A same-operand zeroing idiom reads its register only to clobber it.
        if insn.mnemonic in _ZEROING:
            ops = insn.op_str.split(",")
            if len(ops) == 2 and ops[0].strip() == ops[1].strip():
                read_names -= write_names
        for name in read_names:
            parent = _SUBREG.get(name)
            if parent and parent not in written and parent not in footprint.int_args:
                footprint.int_args.append(parent)
            if name and name.startswith("xmm") and name not in seen_float and name not in write_names:
                seen_float.add(name)
                footprint.float_args.append(name)
        for name in write_names:
            parent = _SUBREG.get(name)
            if parent:
                written.add(parent)
    footprint.int_args.sort(key=lambda r: _INT_ARGS.index(r) if r in _INT_ARGS else 99)
    footprint.float_args.sort()
    return footprint
