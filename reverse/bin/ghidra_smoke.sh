#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
temporary="$(mktemp -d -t palmod-ghidra-smoke.XXXXXX)"
trap 'rm -rf "$temporary"' EXIT

PALMOD_GHIDRA_PROJECTS="$temporary/projects" \
  "$repo_root/reverse/bin/ghidra_scan.sh" \
  /bin/true "$temporary/evidence.json" PALMOD_SMOKE_SENTINEL

python - "$temporary/evidence.json" <<'PY'
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert evidence["analyzer"]["name"] == "palmod-ghidra-reflection-scan"
assert evidence["reflected_string_hits"]["PALMOD_SMOKE_SENTINEL"] == []
assert evidence["candidates"] == []
print("Ghidra/PyGhidra smoke evidence verified")
PY
