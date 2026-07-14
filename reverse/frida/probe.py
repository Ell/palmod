#!/usr/bin/env python3
"""Fingerprint-gated launcher for passive Frida observations.

Frida changes target code briefly to install Interceptor trampolines, but this
agent never calls game functions and never writes game data. It records only
hook entry, thread ID, and an optional bounded native backtrace.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

REVERSE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVERSE_ROOT))

from palrevlib.elf import build_id, sha256_file  # noqa: E402


def parse_pattern(value: str | None) -> list[int | None]:
    if value is None:
        return []
    result: list[int | None] = []
    for token in value.split():
        result.append(None if token in {"?", "??"} else int(token, 16))
    return result


def load_profile(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        profile = tomllib.load(handle)
    if profile.get("schema") != 1:
        raise ValueError("unsupported profile schema")
    if profile.get("status") not in {"candidate", "validated"}:
        raise ValueError("profile status must be candidate or validated")
    return profile


def verify_target(
    profile: dict[str, Any], pid: int, *, allow_candidate_profile: bool
) -> Path:
    if profile["status"] == "candidate" and not allow_candidate_profile:
        raise PermissionError(
            "candidate profiles require --allow-candidate-profile for passive research"
        )
    executable = Path(os.readlink(f"/proc/{pid}/exe"))
    fingerprint = profile["elf"]
    actual_size = executable.stat().st_size
    actual_sha256 = sha256_file(executable)
    actual_build_id = build_id(executable)
    mismatches: list[str] = []
    if actual_sha256.lower() != str(fingerprint["sha256"]).lower():
        mismatches.append("sha256")
    if actual_build_id.lower() != str(fingerprint["build_id"]).lower():
        mismatches.append("build_id")
    if actual_size != int(fingerprint["file_size"]):
        mismatches.append("file_size")
    if mismatches:
        raise RuntimeError(
            "target/profile fingerprint mismatch: " + ", ".join(mismatches)
        )
    return executable


def make_config(
    profile: dict[str, Any],
    executable: Path,
    *,
    function_name: str,
    hook_kinds: list[str],
    max_events: int,
    backtrace_depth: int,
    mode: str,
    mutation_allowed: bool,
    crash_risk_accepted: bool,
) -> dict[str, Any]:
    functions = profile["functions"]
    if function_name not in functions:
        raise ValueError(f"profile has no function named {function_name}")
    function = functions[function_name]
    anchors = profile.get("anchors", {})
    anchor_prefix = (
        "request_add_item"
        if function_name == "request_add_item_to_server"
        else function_name
    )
    anchor_by_kind = {
        "exec-thunk": anchors.get(f"{anchor_prefix}_exec_thunk", {}),
        "implementation": anchors.get(f"{anchor_prefix}_implementation", {}),
    }
    rva_by_kind = {
        "exec-thunk": function.get("exec_thunk_rva"),
        "implementation": function.get("implementation_rva"),
    }
    hooks = []
    for kind in hook_kinds:
        rva = rva_by_kind[kind]
        if rva is None:
            raise ValueError(f"profile has no {kind} address")
        hooks.append(
            {
                "expected_pattern": parse_pattern(
                    anchor_by_kind[kind].get("expected_bytes")
                ),
                "name": f"{function_name}.{kind}",
                "rva": int(rva),
            }
        )
    return {
        "backtrace_depth": backtrace_depth,
        "crash_risk_accepted": crash_risk_accepted,
        "hooks": hooks,
        "max_events": max_events,
        "mode": mode,
        "module_name": executable.name,
        "mutation_allowed": mutation_allowed,
        "profile_id": profile["profile_id"],
    }


def render_agent(config: dict[str, Any]) -> str:
    template = Path(__file__).with_name("passive_agent.js").read_text(encoding="utf-8")
    token = "__PALMOD_CONFIG__"
    if template.count(token) != 1:
        raise RuntimeError("passive agent template token is missing or ambiguous")
    return template.replace(
        token,
        json.dumps(config, sort_keys=True, separators=(",", ":")),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument(
        "--function",
        default="enter_chat",
        help="profile function key (default: enter_chat)",
    )
    parser.add_argument(
        "--hook",
        action="append",
        choices=("exec-thunk", "implementation"),
        default=None,
    )
    parser.add_argument("--allow-candidate-profile", action="store_true")
    parser.add_argument("--max-events", type=int, default=100)
    parser.add_argument("--backtrace-depth", type=int, default=8)
    parser.add_argument("--duration", default="30")
    parser.add_argument("--mode", default="observe")
    parser.add_argument("--allow-mutation", action="store_true")
    parser.add_argument("--i-accept-crash-risk", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_events < 1 or args.max_events > 10_000:
        raise ValueError("--max-events must be in [1, 10000]")
    if args.backtrace_depth < 0 or args.backtrace_depth > 64:
        raise ValueError("--backtrace-depth must be in [0, 64]")
    if args.allow_mutation != args.i_accept_crash_risk:
        raise PermissionError(
            "mutation requires both --allow-mutation and --i-accept-crash-risk"
        )
    if args.mode != "observe" and not args.allow_mutation:
        raise PermissionError("non-observe mode requires explicit mutation opt-ins")

    profile = load_profile(args.profile)
    executable = verify_target(
        profile, args.pid, allow_candidate_profile=args.allow_candidate_profile
    )
    config = make_config(
        profile,
        executable,
        function_name=args.function,
        hook_kinds=args.hook or ["implementation"],
        max_events=args.max_events,
        backtrace_depth=args.backtrace_depth,
        mode=args.mode,
        mutation_allowed=args.allow_mutation,
        crash_risk_accepted=args.i_accept_crash_risk,
    )
    if args.dry_run:
        print(json.dumps(config, sort_keys=True, indent=2))
        return 0

    frida = shutil.which("frida")
    if frida is None:
        raise FileNotFoundError("frida CLI is not installed")
    rendered = render_agent(config)
    descriptor, temporary_name = tempfile.mkstemp(prefix="palmod-probe-", suffix=".js")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        command = [
            frida,
            "--attach-pid",
            str(args.pid),
            "--load",
            temporary_name,
            "--quiet",
            "--timeout",
            args.duration,
            "--runtime",
            "v8",
            "--exit-on-error",
            "--no-auto-reload",
        ]
        return subprocess.run(command, check=False).returncode
    finally:
        Path(temporary_name).unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, PermissionError, RuntimeError, ValueError) as error:
        print(f"palmod passive probe: {error}", file=sys.stderr)
        raise SystemExit(2) from error
