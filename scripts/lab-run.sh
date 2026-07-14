#!/usr/bin/env bash
# Run a reverse/ python tool against the disposable lab with the isolated env set
# and preflight passed. The tool owns its own server child (needed for
# /proc/<pid>/mem under yama ptrace_scope=1).
#
#   scripts/lab-run.sh reverse/bin/dump_reflection.py [args...]
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "$here/.." && pwd)"
# shellcheck source=scripts/lab-env.sh
source "$here/lab-env.sh"

[[ $# -ge 1 ]] || { echo "usage: lab-run.sh <python tool> [args...]" >&2; exit 2; }
tool="$1"; shift

echo "lab-run: preflight..."
"$here/lab-preflight.sh" >/dev/null

exec env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$repo/reverse" \
  "${PALMOD_PYTHON:-python3}" "$repo/$tool" "$@"
