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

proxy_credential=/run/credentials/pulse.service/pulse-proxy-auth-secret
if [ ! -r "$proxy_credential" ]; then
  echo "Pulse proxy-auth credential is unavailable" >&2
  exit 1
fi
proxy_secret=$(cat "$proxy_credential")
if [ ! -s "$proxy_credential" ] ||
  [ "$(wc -l < "$proxy_credential")" -ne 0 ] ||
  LC_ALL=C grep -q "$(printf '\r')" "$proxy_credential"
then
  echo "Pulse proxy-auth credential is invalid" >&2
  exit 1
fi
case "$proxy_secret" in
  ''|*[!A-Za-z0-9._~+/_=-]*)
    echo "Pulse proxy-auth credential contains unsupported characters" >&2
    exit 1
    ;;
esac

export PULSE_AUTH_USER=admin
export PULSE_AUTH_PASS="$password"
export PROXY_AUTH_SECRET="$proxy_secret"
export PROXY_AUTH_USER_HEADER=Remote-User
export PROXY_AUTH_ROLE_HEADER=Remote-Role
export PROXY_AUTH_ADMIN_ROLE=admin
exec /opt/pulse/bin/pulse
