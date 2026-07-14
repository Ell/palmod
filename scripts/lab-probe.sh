#!/usr/bin/env bash
# Locate live UFunction::Func slots in the running lab server (reflection-hook prep).
#
#   scripts/lab-probe.sh [profile.toml]
#
# Sets up the isolated lab environment, runs preflight, then hands off to a
# Python probe that owns PalServer (so /proc/<pid>/mem is readable under yama
# ptrace_scope=1), scans its memory for each reflected function's exec-thunk
# pointer, and reports the writable slots (the reflection swap targets). Always
# stops the child. Read-only: no hooks, no mutation.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "$here/.." && pwd)"
# shellcheck source=scripts/lab-env.sh
source "$here/lab-env.sh"
# shellcheck source=scripts/lab-lib.sh
source "$here/lab-lib.sh"

profile="${1:-$repo/profiles/candidates/palworld-linux-24088465.toml}"
python_bin="${PALMOD_PYTHON:-python3}"

echo "lab-probe: preflight..."
"$here/lab-preflight.sh" >/dev/null

exec env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$repo/reverse" \
  "$python_bin" "$repo/reverse/bin/probe_live.py" "$profile"
