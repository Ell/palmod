#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 )); then
  echo "usage: $0 BINARY EVIDENCE_JSON [REFLECTED_NAME ...]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
binary="$(realpath "$1")"
out="$(realpath -m "$2")"
shift 2
strings=("$@")
if (( ${#strings[@]} == 0 )); then
  strings=(
    RequestAddItem_ToServer
    RequestAddItem_ForDebug
    AddItem_ServerInternal
    EnterChat
    SendChatToBroadcast
    BroadcastChatMessage
    UPalNetworkPlayerComponent
    APalPlayerController
  )
fi

tools_root="${PALMOD_TOOLS_ROOT:-$HOME/.local/share/palmod/tools}"
ghidra="${GHIDRA_INSTALL_DIR:-$tools_root/ghidra_12.1.2_PUBLIC}"
venv="${PALMOD_PYGHIDRA_VENV:-$tools_root/pyghidra-venv}"
if [[ ! -x "$ghidra/support/analyzeHeadless" || ! -x "$venv/bin/pyghidra" ]]; then
  echo "Ghidra/PyGhidra is missing; run reverse/bin/install_ghidra.sh" >&2
  exit 1
fi

binary_size="$(stat -c %s "$binary")"
available_kib="$(awk '/MemAvailable:/ { print $2 }' /proc/meminfo)"
minimum_kib=$((16 * 1024 * 1024))
if (( binary_size >= 100 * 1024 * 1024 )); then
  if (( available_kib < minimum_kib )); then
    echo "refusing full Ghidra analysis: ${available_kib} KiB available; require 16 GiB" >&2
    echo "close memory-heavy applications, then retry (or use scan_elf.py)" >&2
    exit 1
  fi
  if pgrep -f '[P]alworld-Win64-Shipping|[P]alServer-Linux-Shipping' >/dev/null; then
    echo "refusing full Ghidra analysis while Palworld or PalServer is running" >&2
    echo "use the bounded scan_elf.py fallback, or stop the game/server first" >&2
    exit 1
  fi
fi

mkdir -p "$(dirname "$out")" "${PALMOD_GHIDRA_PROJECTS:-$HOME/.cache/palmod/ghidra}"
sha256="$(sha256sum "$binary" | cut -d' ' -f1)"
project="palmod-${sha256:0:16}"
script_args=(
  --out "$out"
  --ue4ss-ref c2ac246447a8bcd92541070cb474044e7a2bbbe6
  --patternsleuth-ref fd48670daac28202301f10d487d051f262bc28c8
  --create-labels
)
for reflected_name in "${strings[@]}"; do
  script_args+=(--string "$reflected_name")
done
if [[ "$sha256" == a05788ead7619db22a1509c43241c16d289ed7040e8bcbb2e36e13e223e822f9 ]]; then
  script_args+=(
    --expected-sha256 "$sha256"
    --expected-build-id 217802a00653a9c4
    --known-implementation RequestAddItem_ToServer=0x06ed5fa0
    --known-implementation RequestAddItem_ForDebug=0x074cc460
    --known-implementation AddItem_ServerInternal=0x074cc500
    --known-implementation EnterChat=0x074ef9e0
    --known-implementation SendChatToBroadcast=0x070f9f40
    --known-implementation BroadcastChatMessage=0x0720a0e0
  )
fi

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk}"
export PATH="$JAVA_HOME/bin:$PATH"
export GHIDRA_INSTALL_DIR="$ghidra"
analysis_cores="${PALMOD_ANALYSIS_CORES:-4}"
if [[ ! "$analysis_cores" =~ ^[1-4]$ ]]; then
  echo "PALMOD_ANALYSIS_CORES must be an integer from 1 through 4" >&2
  exit 2
fi
# PyGhidra embeds the JVM in Python. Bound both Java's heap and its view of the
# CPU count, and lower CPU/I/O priority so analysis cannot starve an interactive
# desktop again.
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Xmx6g -XX:ActiveProcessorCount=$analysis_cores"
exec nice -n 15 ionice -c 3 "$venv/bin/pyghidra" \
  --install-dir "$ghidra" \
  --project-path "${PALMOD_GHIDRA_PROJECTS:-$HOME/.cache/palmod/ghidra}" \
  --project-name "$project" \
  "$binary" "$repo_root/reverse/ghidra/palmod_scan.py" "${script_args[@]}"
