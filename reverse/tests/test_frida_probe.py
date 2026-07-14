from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

from palrevlib.elf import build_id, sha256_file


PROBE_PATH = Path(__file__).parents[1] / "frida" / "probe.py"
SPEC = importlib.util.spec_from_file_location("palmod_frida_probe", PROBE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class FridaProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = Path(sys.executable).resolve()
        self.profile = {
            "schema": 1,
            "status": "candidate",
            "profile_id": "fixture",
            "elf": {
                "sha256": sha256_file(self.executable),
                "build_id": build_id(self.executable),
                "file_size": self.executable.stat().st_size,
            },
            "anchors": {
                "request_add_item_exec_thunk": {
                    "expected_bytes": "41 56 ?? 48"
                }
            },
            "functions": {
                "request_add_item_to_server": {"exec_thunk_rva": 1234}
            },
        }

    def test_candidate_profile_requires_explicit_research_gate(self) -> None:
        with self.assertRaisesRegex(PermissionError, "allow-candidate"):
            probe.verify_target(
                self.profile, os.getpid(), allow_candidate_profile=False
            )
        self.assertEqual(
            probe.verify_target(
                self.profile, os.getpid(), allow_candidate_profile=True
            ),
            self.executable,
        )

    def test_config_is_bounded_and_agent_has_no_mutation_mode(self) -> None:
        config = probe.make_config(
            self.profile,
            self.executable,
            function_name="request_add_item_to_server",
            hook_kinds=["exec-thunk"],
            max_events=5,
            backtrace_depth=2,
            mode="observe",
            mutation_allowed=False,
            crash_risk_accepted=False,
        )
        self.assertEqual(config["hooks"][0]["expected_pattern"], [0x41, 0x56, None, 0x48])
        self.assertFalse(config["mutation_allowed"])
        rendered = probe.render_agent(config)
        self.assertNotIn("__PALMOD_CONFIG__", rendered)
        self.assertIn('"mode":"observe"', rendered)

    def test_profile_parser_rejects_unknown_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory, "bad.toml")
            path.write_text('schema = 1\nstatus = "trusted-ish"\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "profile status"):
                probe.load_profile(path)


if __name__ == "__main__":
    unittest.main()
