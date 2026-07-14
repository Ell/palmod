#!/usr/bin/env bash
# Shared helpers for the Palmod disposable-server lab harness.
# Source AFTER scripts/lab-env.sh. Not meant to be executed directly.

: "${PALMOD_LAB_STATE:=$PALMOD_LAB_ROOT/.palmod-lab}"
: "${PALMOD_LAB_PORT:=8211}"
: "${PALMOD_LAB_READY_TIMEOUT:=180}"

lab_log_file() { printf '%s/server.log\n' "$PALMOD_LAB_STATE"; }
lab_pid_file() { printf '%s/server.pid\n' "$PALMOD_LAB_STATE"; }

lab_pid() {
  local pid_file; pid_file="$(lab_pid_file)"
  [[ -f "$pid_file" ]] && cat "$pid_file"
}

lab_running() {
  local pid; pid="$(lab_pid)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

# True when the server's UDP game port is bound.
lab_port_bound() {
  ss -lunH "sport = :$PALMOD_LAB_PORT" 2>/dev/null | grep -q .
}

# Launch PalServer detached, record its PID, and echo it. Extra args forwarded.
# PalServer requires the project root as cwd and "Pal" as its first argument.
lab_launch() {
  mkdir -p "$PALMOD_LAB_STATE"
  local log; log="$(lab_log_file)"
  : > "$log"
  (
    cd "$PALMOD_LAB_ROOT" || exit 97
    exec "$PALMOD_SERVER" Pal \
      -port="$PALMOD_LAB_PORT" -useperfthreads -NoAsyncLoadingThread "$@"
  ) >>"$log" 2>&1 &
  local pid=$!
  echo "$pid" > "$(lab_pid_file)"
  echo "$pid"
}

# Wait until the given PID binds the game port. 0=ready, 1=timeout, 2=exited.
lab_wait_ready() {
  local pid="$1"
  local waited=0
  while (( waited < PALMOD_LAB_READY_TIMEOUT )); do
    kill -0 "$pid" 2>/dev/null || return 2
    lab_port_bound && return 0
    sleep 2
    waited=$(( waited + 2 ))
  done
  return 1
}

# Graceful stop of a PID: SIGINT, wait, then SIGKILL.
lab_stop_pid() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 0
  kill -INT "$pid" 2>/dev/null || true
  local waited=0
  while (( waited < 30 )); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 1
    waited=$(( waited + 1 ))
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# Resident memory of a PID in MiB (0 if gone).
lab_rss_mib() {
  local pid="$1" kib
  kib="$(awk '/VmRSS:/ { print $2 }' "/proc/$pid/status" 2>/dev/null)"
  echo "$(( ${kib:-0} / 1024 ))"
}
