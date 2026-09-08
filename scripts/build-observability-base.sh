#!/bin/sh
set -eu

output=${1:-/var/lib/vz/template/cache/boetticher-observability-base-0.1.0-amd64.tar.zst}
definition=${2:-${BOETTICHER_OBSERVABILITY_BASE_DEFINITION:-/opt/boetticher/current/controller/observability/base/debian.yaml}}
[ "$(id -u)" -eq 0 ] || { echo 'observability base builder requires root' >&2; exit 1; }
[ -r "$definition" ] || { echo "observability base definition is missing: $definition" >&2; exit 1; }
command -v mmdebstrap >/dev/null 2>&1 || { echo 'observability base builder requires mmdebstrap' >&2; exit 1; }
command -v zstd >/dev/null 2>&1 || { echo 'observability base builder requires zstd' >&2; exit 1; }
release=$(sed -n 's/^release: *//p' "$definition")
mirror=$(sed -n 's/^  mirror: *//p' "$definition")
packages=$(awk '/^  packages:$/ { in_packages=1; next } in_packages && /^    - / { sub(/^    - /, ""); printf "%s%s", separator, $0; separator=","; next } in_packages { exit }' "$definition")
[ "$release" = trixie ] || { echo 'observability base release is not pinned to trixie' >&2; exit 1; }
[ -n "$mirror" ] || { echo 'observability base mirror is missing' >&2; exit 1; }
[ -n "$packages" ] || { echo 'observability base package set is missing' >&2; exit 1; }
parent=$(dirname "$output")
install -d -m 0755 "$parent"
work=$(mktemp -d "$parent/.boetticher-observability-base.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
rootfs=$work/rootfs
mmdebstrap --variant=minbase --architectures=amd64 --aptopt=Acquire::Check-Valid-Until=false --aptopt=Acquire::Retries=3 --aptopt=Acquire::Languages=none --include="$packages" "$release" "$rootfs" "$mirror"
mkdir -p "$rootfs/etc/boetticher"
tar --zstd -C "$rootfs" -cf "$work/base.tar.zst" .
install -m 0644 "$work/base.tar.zst" "$output.new"
mv -f "$output.new" "$output"
printf 'observability base: PASS %s\n' "$output"
