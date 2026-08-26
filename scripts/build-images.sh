#!/bin/sh
set -eu

# This is the checked-in image-build implementation. It never executes an
# operator-supplied shell hook. Full construction is Linux-only; macOS
# controllers use the bootstrap builder VM.
target=${1:-images}
case "$target" in
  image-base|image-dns-blocky|image-dns-adguard|image-logging|image-monitoring|image-firewall|image-portal|images) ;;
  *) echo "unknown image target: $target" >&2; exit 2 ;;
esac

if [ "$(uname -s)" != Linux ]; then
  echo "HOLD: appliance construction requires the supported Linux builder environment; use boetticher bootstrap on macOS" >&2
  exit 2
fi

for tool in distrobuilder sha256sum tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "HOLD: required Linux image-build tool is unavailable: $tool" >&2
    exit 2
  fi
done

output_root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
mkdir -p "$output_root"

build_one() {
  name=$1
  definition=$2
  output="$output_root/$name"
  mkdir -p "$output"
  distrobuilder build-lxc "$definition" "$output/$name.tar.zst"
  sha256sum "$output/$name.tar.zst" > "$output/content.sha256"
}

case "$target" in
  image-base) build_one boetticher-base images/base/debian.yaml ;;
  image-dns-blocky) build_one boetticher-dns-blocky images/dns/blocky/image.yaml ;;
  image-dns-adguard) build_one boetticher-dns-adguard images/dns/adguard/image.yaml ;;
  image-logging) build_one boetticher-logging images/logging/image.yaml ;;
  image-monitoring) build_one boetticher-monitoring images/monitoring/image.yaml ;;
  image-portal) build_one boetticher-portal images/portal/image.yaml ;;
  image-firewall)
    echo "HOLD: firewall QCOW2 construction requires the supported Linux VM-image builder" >&2
    exit 2
    ;;
  images)
    "$0" image-base
    "$0" image-dns-blocky
    "$0" image-logging
    "$0" image-monitoring
    "$0" image-portal
    "$0" image-firewall
    ;;
esac
