#!/usr/bin/env bash
# Lifecycle wrapper for the disposable Palworld lab server.
#
#   scripts/lab-server.sh start [-- extra PalServer args]
#   scripts/lab-server.sh stop
#   scripts/lab-server.sh status
#   scripts/lab-server.sh logs
#
# Runs preflight before starting, isolates all mutable state under the lab root,
# and never touches any production server tree.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lab-env.sh
source "$here/lab-env.sh"
# shellcheck source=scripts/lab-lib.sh
source "$here/lab-lib.sh"

usage() { sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

cmd_start() {
  if lab_running; then
    echo "lab-server: already running (pid $(lab_pid))"
    return 0
  fi
  echo "lab-server: preflight..."
  "$here/lab-preflight.sh" >/dev/null
  echo "lab-server: launching PalServer on udp/$PALMOD_LAB_PORT (timeout ${PALMOD_LAB_READY_TIMEOUT}s)"
  local pid; pid="$(lab_launch "$@")"
  echo "lab-server: pid $pid, log $(lab_log_file)"
  if lab_wait_ready "$pid"; then
    echo "lab-server: ready (rss $(lab_rss_mib "$pid") MiB, udp/$PALMOD_LAB_PORT bound)"
  else
    local status=$?
    if [[ $status == 2 ]]; then
      echo "lab-server: process exited during startup; see log below" >&2
      tail -n 20 "$(lab_log_file)" >&2 || true
      rm -f "$(lab_pid_file)"
      return 1
    fi
    echo "lab-server: still not bound after ${PALMOD_LAB_READY_TIMEOUT}s (pid $pid alive); check logs" >&2
    return 1
  fi
}

cmd_stop() {
  local pid; pid="$(lab_pid || true)"
  if [[ -z "${pid:-}" ]]; then echo "lab-server: not running"; return 0; fi
  echo "lab-server: stopping pid $pid"
  lab_stop_pid "$pid"
  rm -f "$(lab_pid_file)"
  echo "lab-server: stopped"
}

cmd_status() {
  if lab_running; then
    local pid; pid="$(lab_pid)"
    echo "state=running pid=$pid rss_mib=$(lab_rss_mib "$pid") port_bound=$(lab_port_bound && echo yes || echo no)"
  else
    echo "state=stopped"
  fi
}

cmd_logs() { tail -n "${PALMOD_LAB_LOG_LINES:-40}" "$(lab_log_file)" 2>/dev/null || echo "no log yet"; }

case "${1:-}" in
  start) shift; cmd_start "$@" ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  logs) cmd_logs ;;
  *) usage; exit 2 ;;
esac
