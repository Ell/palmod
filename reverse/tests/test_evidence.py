from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from palrevlib.evidence import (
    Candidate,
    canonical_json_bytes,
    make_candidate_profile,
    make_evidence,
    write_json_atomic,
)


class EvidenceTests(unittest.TestCase):
    def test_evidence_and_profile_are_deterministic_and_unvalidated(self) -> None:
        candidate = Candidate(
            reflected_name="RequestAddItem_ToServer",
            string_va=0xC9AD28,
            table_entry_va=0x1234,
            exec_thunk_va=0x6BDF6B0,
            implementation_candidates=(0x6ED5FA0,),
            score=95,
            reasons=("fixture",),
        )
        evidence = make_evidence(
            binary_path="/secret/location/PalServer-Linux-Shipping",
            binary_sha256="aa" * 32,
            elf_build_id="AABBCCDD",
            image_base=0x200000,
            candidates=[candidate],
            input_refs={"ue4ss": "c2ac"},
            analyzer={"name": "test", "version": "1"},
        )
        profile = make_candidate_profile(
            profile_id="fixture",
            evidence=evidence,
            selected={
                "request_add_item_to_server": {
                    "address_kind": "elf_va",
                    "exec_thunk": "0x0000000006bdf6b0",
                }
            },
            steam={"build_id": 1},
        )

        self.assertEqual(evidence["status"], "candidate_unvalidated")
        self.assertEqual(profile["status"], "candidate_unvalidated")
        self.assertIsNone(profile["signature"])
        self.assertNotIn(b"secret/location", canonical_json_bytes(evidence))
        self.assertEqual(
            canonical_json_bytes(json.loads(canonical_json_bytes(profile))),
            canonical_json_bytes(profile),
        )

    def test_atomic_writer_makes_parseable_compact_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "nested", "out.json")
            write_json_atomic(path, {"z": 1, "a": 2})
            self.assertEqual(path.read_bytes(), b'{"a":2,"z":1}\n')


if __name__ == "__main__":
    unittest.main()
