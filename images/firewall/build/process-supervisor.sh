#!/bin/sh

# The caller owns EXIT cleanup. This helper keeps the currently running
# transaction in a distinct process group so a signal delivered only to the
# caller can still cancel and reap the complete transaction.
active_bounded_pid=

bounded_signal() {
  signal=$1
  status=$2
  trap '' HUP INT TERM
  if [ -n "$active_bounded_pid" ]; then
    kill -s "$signal" "$active_bounded_pid" 2>/dev/null || true
    kill -s "$signal" -- "-$active_bounded_pid" 2>/dev/null || true
    if wait "$active_bounded_pid"; then
      :
    else
      :
    fi
    active_bounded_pid=
  fi
  exit "$status"
}

run_bounded_command() {
  if [ "$#" -lt 3 ]; then
    echo "HOLD: bounded command requires a deadline, kill grace, and command" >&2
    return 2
  fi
  duration=$1
  kill_after=$2
  shift 2
  setsid timeout --signal=TERM --kill-after="$kill_after" "$duration" "$@" &
  active_bounded_pid=$!
  if wait "$active_bounded_pid"; then
    bounded_status=0
  else
    bounded_status=$?
  fi
  active_bounded_pid=
  return "$bounded_status"
}
