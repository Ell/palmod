"""Tests for the optional capstone-backed ABI recovery.

These skip cleanly when capstone is not installed, so the default dependency-free
`make reverse-test` stays green; run them with a venv that has capstone.
"""
from __future__ import annotations

import struct
import unittest

from palrevlib.elf import LoadSegment

try:
    import capstone  # noqa: F401
    from palrevlib.disasm import abi_footprint, analyze_thunk
    HAVE_CAPSTONE = True
except ModuleNotFoundError:
    HAVE_CAPSTONE = False

BASE_VA = 0x400000


def one_segment(code: bytes) -> list[LoadSegment]:
    return [LoadSegment(file_offset=0, file_size=len(code),
                        virtual_address=BASE_VA, memory_size=len(code), flags=5)]


@unittest.skipUnless(HAVE_CAPSTONE, "capstone not installed")
class AbiFootprintTests(unittest.TestCase):
    def test_reads_int_and_float_args_before_call(self):
        code = bytes.fromhex(
            "4889f8"    # mov rax, rdi   -> rdi is an incoming arg
            "4889f1"    # mov rcx, rsi   -> rsi is an incoming arg, rcx written
            "31d2"      # xor edx, edx   -> zeroing, rdx written not read
            "0f28c8"    # movaps xmm1, xmm0 -> xmm0 is a float arg
            "e800000000"  # call ...     -> stop scanning here
            "c3"        # ret
        )
        fp = abi_footprint(bytes(code), one_segment(code), BASE_VA)
        self.assertEqual(fp.int_args, ["rdi", "rsi"])
        self.assertEqual(fp.float_args, ["xmm0"])
        self.assertTrue(fp.stopped_at_call)
        # rcx was written before any read, so it is not counted as an argument.
        self.assertNotIn("rcx", fp.int_args)


@unittest.skipUnless(HAVE_CAPSTONE, "capstone not installed")
class ThunkLinkageTests(unittest.TestCase):
    def test_finds_tail_call_into_implementation(self):
        impl_va = BASE_VA + 0x1000
        # call helper (rel to +0x100), call impl (rel to impl_va), ret
        helper_rel = struct.pack("<i", 0x100 - 5)          # from addr 0 -> 0x100
        impl_rel = struct.pack("<i", (impl_va - BASE_VA) - 10)  # from addr 5 -> impl
        code = b"\xe8" + helper_rel + b"\xe8" + impl_rel + b"\xc3"
        report = analyze_thunk(bytes(code), one_segment(code), BASE_VA, impl_va)
        self.assertEqual(len(report.call_targets), 2)
        self.assertEqual(report.impl_call_index, 1)
        self.assertEqual(report.call_targets[1], impl_va)


if __name__ == "__main__":
    unittest.main()
