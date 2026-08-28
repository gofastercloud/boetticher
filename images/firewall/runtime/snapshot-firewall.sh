#!/bin/sh
set -eu

# This is the only privileged operation used by the telemetry collector. It
# has a fixed read-only nft invocation and publishes one bounded snapshot for
# the non-root daemon; it never accepts arguments or mutates the ruleset.
umask 027
directory=/run/boetticher
target=$directory/firewall-ruleset.json
mkdir -p "$directory"
temporary=$(mktemp "$directory/firewall-ruleset.XXXXXX")
cleanup() {
  rm -f "$temporary"
}
trap cleanup EXIT INT TERM

/usr/sbin/nft --json list ruleset > "$temporary"
size=$(/usr/bin/stat -c '%s' "$temporary")
if [ "$size" -gt 4194304 ]; then
  exit 75
fi
/usr/bin/chown root:boetticher-telemetry "$temporary"
/usr/bin/chmod 0640 "$temporary"
/usr/bin/mv -f "$temporary" "$target"
trap - EXIT INT TERM
