from __future__ import annotations

import struct
import unittest

from palrevlib.scanner import MemoryRange, scan_uht_name_function_pairs


class UhtPairScannerTests(unittest.TestCase):
    def test_finds_aligned_name_function_pair_and_scores_neighbors(self) -> None:
        table_va = 0x0080_0000
        wanted_name_va = 0x0090_1230
        executable = [MemoryRange(0x0040_0000, 0x0070_0000)]
        data = b"".join(
            (
                struct.pack("<QQ", 0x0090_1000, 0x0040_1000),
                struct.pack("<QQ", wanted_name_va, 0x0040_2000),
                struct.pack("<QQ", 0x0090_2000, 0x0040_3000),
            )
        )

        hits = scan_uht_name_function_pairs(
            data,
            data_va=table_va,
            string_va=wanted_name_va,
            executable_ranges=executable,
        )

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].table_entry_va, table_va + 16)
        self.assertEqual(hits[0].function_va, 0x0040_2000)
        self.assertEqual(hits[0].score, 95)
        self.assertEqual(
            hits[0].reasons,
            (
                "name_pointer_matches",
                "paired_pointer_is_executable",
                "previous_pair_has_executable_target",
                "next_pair_has_executable_target",
            ),
        )

    def test_ignores_unaligned_and_non_executable_pairs(self) -> None:
        wanted_name_va = 0x0090_1230
        unaligned = b"x" + struct.pack("<QQ", wanted_name_va, 0x0040_2000)
        non_executable = struct.pack("<QQ", wanted_name_va, 0x00A0_2000)

        self.assertEqual(
            scan_uht_name_function_pairs(
                unaligned,
                data_va=0x0080_0000,
                string_va=wanted_name_va,
                executable_ranges=[MemoryRange(0x0040_0000, 0x0070_0000)],
            ),
            [],
        )
        self.assertEqual(
            scan_uht_name_function_pairs(
                non_executable,
                data_va=0x0080_0000,
                string_va=wanted_name_va,
                executable_ranges=[MemoryRange(0x0040_0000, 0x0070_0000)],
            ),
            [],
        )

    def test_rejects_non_64_bit_pointer_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "64-bit"):
            scan_uht_name_function_pairs(
                b"",
                data_va=0,
                string_va=0,
                executable_ranges=[],
                pointer_size=4,
            )


if __name__ == "__main__":
    unittest.main()
