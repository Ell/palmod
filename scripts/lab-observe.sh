#!/usr/bin/env bash
# Passive live-image observation of the lab server (evidence-ladder rung 3 seed).
#
#   scripts/lab-observe.sh [profile.toml]
#
# Sets up the isolated lab environment, runs preflight, then hands off to a
# Python observer that launches PalServer as its own child (so /proc/<pid>/mem
# is readable under yama ptrace_scope=1), verifies every profile anchor against
# live memory, and always stops the child. Read-only: no hooks, no mutation, so
# it is safe against the unsigned candidate profile.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "$here/.." && pwd)"
# shellcheck source=scripts/lab-env.sh
source "$here/lab-env.sh"
# shellcheck source=scripts/lab-lib.sh
source "$here/lab-lib.sh"

profile="${1:-$repo/profiles/candidates/palworld-linux-24088465.toml}"
python_bin="${PALMOD_PYTHON:-python3}"

echo "lab-observe: preflight..."
"$here/lab-preflight.sh" >/dev/null

exec env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$repo/reverse" \
  "$python_bin" "$repo/reverse/bin/observe_live.py" "$profile"
