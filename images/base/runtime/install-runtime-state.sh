#!/bin/sh
set -eu

case "${1:-}" in
  module-config)
    directory=/etc/boetticher
    target=$directory/module.yaml
    mode=0640
    ;;
  artifact-identity)
    directory=/usr/lib/boetticher
    target=$directory/artifact.json
    mode=0644
    ;;
  *)
    echo "unsupported boetticher runtime state" >&2
    exit 2
    ;;
esac

install -d -m 0750 "$directory"
temporary=$(mktemp "$directory/.runtime-state.XXXXXX")
trap 'rm -f "$temporary"' EXIT
install -m "$mode" /dev/stdin "$temporary"
chown root:root "$temporary"
mv -f -- "$temporary" "$target"
trap - EXIT
