#!/bin/sh
set -eu

credential=/run/credentials/pulse.service/pulse-admin-password
if [ ! -r "$credential" ]; then
  echo "Pulse administrative credential is unavailable" >&2
  exit 1
fi

password=$(cat "$credential")
# Keep this check byte-oriented. In a POSIX bracket expression, GNU grep
# treats the escaped r/n as ordinary characters rather than CR/LF escapes.
if [ ! -s "$credential" ] ||
  [ "$(wc -l < "$credential")" -ne 0 ] ||
  LC_ALL=C grep -q "$(printf '\r')" "$credential"
then
  echo "Pulse administrative credential is invalid" >&2
  exit 1
fi

export PULSE_AUTH_USER=admin
export PULSE_AUTH_PASS="$password"
exec /opt/pulse/bin/pulse
