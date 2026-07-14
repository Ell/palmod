from __future__ import annotations

import sys
import unittest
from pathlib import Path

from palrevlib.elf import ElfError, build_id, sha256_file


class ElfTests(unittest.TestCase):
    def test_reads_build_id_from_running_python(self) -> None:
        executable = Path(sys.executable).resolve()
        identifier = build_id(executable)
        self.assertRegex(identifier, r"^[0-9a-f]+$")
        self.assertGreaterEqual(len(identifier), 8)
        self.assertRegex(sha256_file(executable), r"^[0-9a-f]{64}$")

    def test_rejects_non_elf(self) -> None:
        with self.assertRaisesRegex(ElfError, "not an ELF"):
            build_id(__file__)


if __name__ == "__main__":
    unittest.main()
