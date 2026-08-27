#!/bin/sh
set -eu

credential=/run/credentials/pulse.service/pulse-admin-password
if [ ! -r "$credential" ]; then
  echo "Pulse administrative credential is unavailable" >&2
  exit 1
fi

password=$(cat "$credential")
if [ -z "$password" ] || printf '%s' "$password" | grep -q '[\r\n]'; then
  echo "Pulse administrative credential is invalid" >&2
  exit 1
fi

export PULSE_AUTH_USER=admin
export PULSE_AUTH_PASS="$password"
exec /opt/pulse/bin/pulse
