#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
  printf '%s\n' 'HOLD: the Debian archive keyring installer must run on Linux' >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'HOLD: installing the Debian archive keyring requires root' >&2
  exit 2
fi

# Ubuntu hosts can ship an older Debian keyring than the pinned Debian
# snapshot needs. Install the official Debian data package after verifying its
# exact published digest; never disable APT signature verification.
keyring_version=2025.1
keyring_sha256=9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac
keyring_url="https://deb.debian.org/debian/pool/main/d/debian-archive-keyring/debian-archive-keyring_${keyring_version}_all.deb"

current_version=$(dpkg-query -W -f='${Version}' debian-archive-keyring 2>/dev/null || true)
if [ -n "$current_version" ] && dpkg --compare-versions "$current_version" ge "$keyring_version"; then
  printf '%s\n' "Debian archive keyring: PASS $current_version"
  exit 0
fi

temporary=$(mktemp /tmp/boetticher-debian-archive-keyring.XXXXXX.deb)
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT HUP INT TERM
curl --fail --location --silent --show-error --output "$temporary" "$keyring_url"
printf '%s  %s\n' "$keyring_sha256" "$temporary" | sha256sum --check --status
dpkg --install "$temporary"
installed_version=$(dpkg-query -W -f='${Version}' debian-archive-keyring)
dpkg --compare-versions "$installed_version" ge "$keyring_version"
printf '%s\n' "Debian archive keyring: PASS $installed_version"
