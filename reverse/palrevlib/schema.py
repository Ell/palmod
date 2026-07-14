"""Query layer over a generated reflection dump (build/*-reflection.json).

Turns the raw dump into the lookups the rest of the pipeline needs: field
offsets by name, function parameter layouts, struct membership. This is the
consumable form of "our own mappings" — profile generation and the native
adapters read offsets from here instead of hardcoding them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

FUNCTION_KINDS = {"Function", "DelegateFunction", "SparseDelegateFunction"}


@dataclass(frozen=True, slots=True)
class Field:
    name: str
    type: str | None
    offset: int | None
    elem_size: int | None
    inner: str | None = None
    inner_size: int | None = None


class Schema:
    def __init__(self, structs: list[dict]):
        self._structs = {s["name"]: s for s in structs if s.get("name")}

    @classmethod
    def load(cls, path: str | Path) -> "Schema":
        data = json.loads(Path(path).read_text())
        return cls(data["structs"])

    def __len__(self) -> int:
        return len(self._structs)

    def kind(self, name: str) -> str | None:
        s = self._structs.get(name)
        return s.get("kind") if s else None

    def fields(self, name: str) -> list[Field]:
        s = self._structs.get(name)
        if not s:
            return []
        return [Field(p.get("name"), p.get("type"), p.get("offset"),
                      p.get("elem_size"), p.get("inner"), p.get("inner_size"))
                for p in s.get("properties", [])]

    def field(self, struct: str, field: str) -> Field | None:
        return next((f for f in self.fields(struct) if f.name == field), None)

    def field_offset(self, struct: str, field: str) -> int | None:
        f = self.field(struct, field)
        return f.offset if f else None

    def function_params(self, name: str) -> list[Field] | None:
        s = self._structs.get(name)
        if s and s.get("kind") in FUNCTION_KINDS:
            return self.fields(name)
        return None

    def function_thunk_rva(self, name: str) -> int | None:
        """The UFunction::Func (exec thunk) RVA — the by-name hook's swap target."""
        s = self._structs.get(name)
        if s and s.get("kind") in FUNCTION_KINDS:
            return s.get("func_rva")
        return None

    def function_path(self, name: str) -> str | None:
        """The full UE path of a function (e.g. /Script/Pal.Class:Func)."""
        s = self._structs.get(name)
        if s and s.get("kind") in FUNCTION_KINDS:
            return s.get("path")
        return None

    def function_names(self) -> list[str]:
        """Names of every function-kind struct, sorted."""
        return sorted(n for n, s in self._structs.items()
                      if s.get("kind") in FUNCTION_KINDS)

    def find(self, substring: str) -> list[str]:
        return sorted(n for n in self._structs if substring in n)
