"""Deterministic evidence and candidate-profile serialization.

Nothing emitted by this module is a validation result.  Candidate profiles are
deliberately unsigned and are rejected by the production loader.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
STATUS = "candidate_unvalidated"


def hex_address(value: int | None) -> str | None:
    return None if value is None else f"0x{value:016x}"


@dataclass(frozen=True, slots=True)
class CodePreimage:
    role: str
    va: int
    expected_bytes: str
    note: str = "candidate-entry-bytes"

    def to_json(self) -> dict[str, str | None]:
        return {
            "expected_bytes": self.expected_bytes,
            "note": self.note,
            "role": self.role,
            "va": hex_address(self.va),
        }


@dataclass(frozen=True, slots=True)
class Candidate:
    reflected_name: str
    string_va: int
    table_entry_va: int | None
    exec_thunk_va: int | None
    implementation_candidates: tuple[int, ...] = field(default_factory=tuple)
    score: int = 0
    reasons: tuple[str, ...] = field(default_factory=tuple)
    labels_created: tuple[str, ...] = field(default_factory=tuple)
    code_preimages: tuple[CodePreimage, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        return {
            "code_preimages": [item.to_json() for item in self.code_preimages],
            "exec_thunk_va": hex_address(self.exec_thunk_va),
            "implementation_candidates": [
                hex_address(value) for value in self.implementation_candidates
            ],
            "labels_created": list(self.labels_created),
            "reasons": list(self.reasons),
            "reflected_name": self.reflected_name,
            "score": self.score,
            "string_va": hex_address(self.string_va),
            "table_entry_va": hex_address(self.table_entry_va),
            "validation": {
                "dynamic_observation": False,
                "game_thread_confirmed": False,
                "prototype_confirmed": False,
            },
        }


def canonical_json_bytes(value: Any) -> bytes:
    """Return the bytes covered by hashes/signatures.

    Sorting keys and using a fixed compact encoding makes reruns byte-stable.
    """

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def write_json_atomic(path: str | os.PathLike[str], value: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(value)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def make_evidence(
    *,
    binary_path: str,
    binary_sha256: str,
    elf_build_id: str,
    image_base: int,
    candidates: Iterable[Candidate],
    input_refs: dict[str, str],
    analyzer: dict[str, Any],
    string_hits: dict[str, Iterable[int]] | None = None,
) -> dict[str, Any]:
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            candidate.reflected_name,
            candidate.string_va,
            candidate.table_entry_va or -1,
        ),
    )
    return {
        "analyzer": analyzer,
        "binary": {
            "elf_build_id": elf_build_id.lower(),
            "image_base": hex_address(image_base),
            "path_basename": Path(binary_path).name,
            "sha256": binary_sha256.lower(),
        },
        "candidates": [candidate.to_json() for candidate in ordered],
        "reference_revisions": dict(sorted(input_refs.items())),
        "reflected_string_hits": {
            name: [hex_address(value) for value in sorted(values)]
            for name, values in sorted((string_hits or {}).items())
        },
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "warning": (
            "Static-analysis candidates only. Addresses and prototypes must be "
            "confirmed by build-matched passive probes before any mutation."
        ),
    }


def make_candidate_profile(
    *,
    profile_id: str,
    evidence: dict[str, Any],
    selected: dict[str, dict[str, Any]],
    steam: dict[str, int | str],
) -> dict[str, Any]:
    """Build the unsigned envelope consumed by research tooling.

    `selected` is explicit on purpose: a scanner finding several plausible
    functions must not silently promote its highest-scored guess.
    """

    payload = {
        "binary": evidence["binary"],
        "compatibility_state": "candidate",
        "locations": dict(sorted(selected.items())),
        "platform": {"arch": "x86_64", "os": "linux"},
        "profile_id": profile_id,
        "profile_schema_version": SCHEMA_VERSION,
        "provenance": {
            "evidence_sha256": hashlib.sha256(
                canonical_json_bytes(evidence)
            ).hexdigest(),
            "reference_revisions": evidence["reference_revisions"],
        },
        "steam": dict(sorted(steam.items())),
    }
    return {
        "payload": payload,
        "signature": None,
        "signature_algorithm": "ed25519",
        "signing_key_id": None,
        "status": STATUS,
    }
