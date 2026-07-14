#!/usr/bin/env bash
set -euo pipefail

lab_root="${PALMOD_LAB_ROOT:-$HOME/.cache/palmod/lab/24088465}"
binary="$lab_root/Pal/Binaries/Linux/PalServer-Linux-Shipping"
steamclient_source="$lab_root/linux64/steamclient.so"
steamclient_target="$lab_root/Pal/Binaries/Linux/steamclient.so"
expected_sha="${PALMOD_EXPECTED_SHA256:-a05788ead7619db22a1509c43241c16d289ed7040e8bcbb2e36e13e223e822f9}"
expected_build_id="${PALMOD_EXPECTED_BUILD_ID:-217802a00653a9c4}"
minimum_available_kib="${PALMOD_MIN_AVAILABLE_KIB:-12582912}"

fail() {
  printf 'preflight: %s\n' "$*" >&2
  exit 1
}

# Guard against pointing the disposable lab at a real server install. Set
# PALMOD_PRODUCTION_TREE to your live server's directory to have the lab refuse
# to run against it (or any path beneath it).
production_tree="${PALMOD_PRODUCTION_TREE:-}"
if [[ -n "$production_tree" ]]; then
  case "$lab_root" in
    "$production_tree"|"$production_tree"/*)
      fail "refusing to use the production server tree as a lab: $production_tree"
      ;;
  esac
fi

[[ -f "$binary" ]] || fail "server binary is missing: $binary"
[[ -x "$binary" ]] || fail "server binary is not executable: $binary"
[[ -f "$steamclient_source" ]] || {
  fail "mounted Steam Linux runtime is missing (install app depot 1006): $steamclient_source"
}
[[ -f "$steamclient_target" ]] || {
  fail "steamclient.so has not been staged beside PalServer: $steamclient_target"
}
cmp -s -- "$steamclient_source" "$steamclient_target" || {
  fail "staged steamclient.so differs from the mounted runtime"
}

actual_sha="$(sha256sum "$binary" | awk '{print $1}')"
[[ "$actual_sha" == "$expected_sha" ]] || {
  fail "SHA-256 mismatch: expected $expected_sha, got $actual_sha"
}

actual_build_id="$(readelf -n "$binary" | awk '/Build ID:/ { print $3; exit }')"
[[ "$actual_build_id" == "$expected_build_id" ]] || {
  fail "GNU build ID mismatch: expected $expected_build_id, got $actual_build_id"
}

available_kib="$(awk '/MemAvailable:/ { print $2; exit }' /proc/meminfo)"
[[ -n "$available_kib" ]] || fail "could not read MemAvailable from /proc/meminfo"
if (( available_kib < minimum_available_kib )); then
  fail "only $((available_kib / 1024)) MiB memory is available; require $((minimum_available_kib / 1024)) MiB"
fi

socket_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/palmod"
if [[ -e "$socket_dir/control.sock" ]]; then
  fail "a stale or active control socket already exists: $socket_dir/control.sock"
fi

printf 'lab_root=%s\n' "$lab_root"
printf 'binary=%s\n' "$binary"
printf 'sha256=%s\n' "$actual_sha"
printf 'build_id=%s\n' "$actual_build_id"
printf 'memory_available_mib=%s\n' "$((available_kib / 1024))"
printf 'status=ready\n'
