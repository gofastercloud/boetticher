#!/bin/sh
set -eu

case "${1:-}" in
  module-config)
    directory=/etc/boetticher
    target=$directory/module.yaml
    mode=0640
    directory_mode=0751
    ;;
  artifact-identity)
    directory=/usr/lib/boetticher
    target=$directory/artifact.json
    mode=0644
    directory_mode=0755
    ;;
  *)
    echo "unsupported boetticher runtime state" >&2
    exit 2
    ;;
esac

install -d -m "$directory_mode" "$directory"
temporary=$(mktemp "$directory/.runtime-state.XXXXXX")
trap 'rm -f "$temporary"' EXIT
install -m "$mode" /dev/stdin "$temporary"
chown root:root "$temporary"
mv -f -- "$temporary" "$target"
trap - EXIT
