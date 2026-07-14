#!/usr/bin/env bash
# Run the lab server under gdb with the EnterChat capture breakpoints, so a
# connected client's chat messages dump their decoded FString for reversing.
#
#   scripts/lab-capture.sh
#
# The server is a child of gdb (required to breakpoint under yama ptrace_scope=1)
# and keeps running: the breakpoints dump and continue. Read the capture at
# $PALMOD_LAB_STATE/enter_chat_capture.log. Stop with: pkill -f 'gdb .*PalServer'.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "$here/.." && pwd)"
# shellcheck source=scripts/lab-env.sh
source "$here/lab-env.sh"
# shellcheck source=scripts/lab-lib.sh
source "$here/lab-lib.sh"

command -v gdb >/dev/null || { echo "lab-capture: gdb is required" >&2; exit 1; }

echo "lab-capture: preflight..."
"$here/lab-preflight.sh" >/dev/null

gdb_script="${PALMOD_CAPTURE_GDB:-$repo/reverse/gdb/enter_chat_capture.gdb}"
mkdir -p "$PALMOD_LAB_STATE"
cd "$PALMOD_LAB_ROOT"
# Fully disable debuginfod so gdb never blocks on network fetches for the 196 MB
# binary and the EOS/Steam shared objects.
export DEBUGINFOD_URLS=""
echo "lab-capture: launching PalServer under gdb on udp/$PALMOD_LAB_PORT"
echo "lab-capture: gdb script $gdb_script; log dir $PALMOD_LAB_STATE"
exec gdb -batch -nx -iex "set debuginfod enabled off" \
  -x "$gdb_script" \
  --args "$PALMOD_SERVER" Pal -port="$PALMOD_LAB_PORT" \
  -useperfthreads -NoAsyncLoadingThread
