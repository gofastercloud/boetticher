#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
  printf '%s\n' 'HOLD: the local image builder must run inside Linux' >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'HOLD: local builder setup requires root for mmdebstrap, chroot, and libguestfs' >&2
  exit 2
fi

# Keep this toolchain pinned so local builds use the same supported Go minor
# release as the project without relying on automatic toolchain downloads.
go_version=1.26.8
go_sha256=d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b
go_root=/opt/boetticher/go
go_install="$go_root/$go_version"
trivy_version=0.69.3
trivy_sha256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
native_builder=${BOETTICHER_LOCAL_NATIVE:-0}
native_stage=${BOETTICHER_LOCAL_NATIVE_STAGE:-host}
native_root=${BOETTICHER_LOCAL_NATIVE_ROOT:-/var/lib/boetticher/local-builder/root}
source_root=${BOETTICHER_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)}
case "$native_builder" in
  0) kernel_package=linux-image-virtual ;;
  1)
    kernel_package=linux-image-virtual
    if [ "$native_stage" = host ]; then
      apt_source_override=$(mktemp /var/tmp/boetticher-local-builder-host-sources.XXXXXX)
      cleanup_host_setup() {
        rm -f -- "$apt_source_override"
      }
      trap cleanup_host_setup EXIT HUP INT TERM
      printf '%s\n' \
        'deb http://deb.debian.org/debian trixie main' \
        'deb http://deb.debian.org/debian trixie-updates main' \
        'deb http://security.debian.org/debian-security trixie-security main' \
        > "$apt_source_override"
      host_apt_options="-o Dir::Etc::sourcelist=$apt_source_override -o Dir::Etc::sourceparts=-"
      apt-get $host_apt_options -o Acquire::Retries=3 update
      apt-get $host_apt_options -o Acquire::Retries=3 install --yes --no-install-recommends mmdebstrap
      if [ ! -x "$native_root/usr/bin/virt-customize" ]; then
        native_temporary="$native_root.tmp.$$"
        rm -rf -- "$native_temporary"
        mkdir -p "$(dirname "$native_root")"
        mmdebstrap --variant=minbase --architectures=amd64 \
          --include=ca-certificates,curl,debian-archive-keyring,git,jq,libguestfs-tools,mmdebstrap,qemu-utils,time,zstd,linux-image-amd64 \
          --aptopt=Acquire::Retries=3 \
          trixie "$native_temporary" http://deb.debian.org/debian
        mv -- "$native_temporary" "$native_root"
      fi
      install -d -m 0755 "$native_root/var/lib/boetticher/local-builder/source"
      tar -C "$source_root" -cf - . | tar -C "$native_root/var/lib/boetticher/local-builder/source" -xf -
      install -d -m 0755 "$native_root/proc"
      mount -t proc proc "$native_root/proc"
      if BOETTICHER_LOCAL_NATIVE=1 \
        BOETTICHER_LOCAL_NATIVE_STAGE=guest \
        BOETTICHER_SOURCE_ROOT=/var/lib/boetticher/local-builder/source \
        chroot "$native_root" /bin/sh /var/lib/boetticher/local-builder/source/scripts/local-builder-setup.sh; then
        native_setup_status=0
      else
        native_setup_status=$?
      fi
      umount "$native_root/proc"
      if [ "$native_setup_status" -ne 0 ]; then
        exit "$native_setup_status"
      fi
      trap - EXIT HUP INT TERM
      rm -f -- "$apt_source_override"
      printf '%s\n' 'Local builder: PASS isolated native Debian root configured'
      printf '%s\n' "Local builder root: $native_root"
      exit 0
    fi
    kernel_package= ;;
  *) printf '%s\n' 'HOLD: BOETTICHER_LOCAL_NATIVE must be 0 or 1' >&2; exit 2 ;;
esac

export DEBIAN_FRONTEND=noninteractive
if [ "$native_builder" = 1 ] && [ "$native_stage" = host ]; then
  printf '%s\n' 'HOLD: native builder host setup did not complete' >&2
  exit 2
fi

source_override=
cleanup_source_override() {
  if [ -n "$source_override" ]; then
    rm -f -- "$source_override"
  fi
}
trap cleanup_source_override EXIT HUP INT TERM
if [ "$native_builder" = 1 ] && [ "$native_stage" = host ]; then
  source_override=$(mktemp /var/tmp/boetticher-local-builder-sources.XXXXXX)
  printf '%s\n' \
    'deb http://deb.debian.org/debian trixie main' \
    'deb http://deb.debian.org/debian trixie-updates main' \
    'deb http://security.debian.org/debian-security trixie-security main' \
    > "$source_override"
fi
apt_options=
if [ -n "$source_override" ]; then
  apt_options="-o Dir::Etc::sourcelist=$source_override -o Dir::Etc::sourceparts=-"
fi
apt-get $apt_options -o Acquire::Retries=3 update
apt-get $apt_options -o Acquire::Retries=3 install --yes --no-install-recommends \
  ca-certificates curl debian-archive-keyring git jq libguestfs-tools mmdebstrap \
  qemu-utils time zstd $kernel_package
"$source_root/scripts/install-debian-archive-keyring.sh"

if [ ! -x "$go_install/bin/go" ]; then
  temporary=$(mktemp -d /tmp/boetticher-go.XXXXXX)
  cleanup() {
    rm -rf -- "$temporary"
  }
  trap cleanup EXIT HUP INT TERM
  archive="$temporary/go.tar.gz"
  curl --fail --location --silent --show-error \
    --output "$archive" "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz"
  printf '%s  %s\n' "$go_sha256" "$archive" | sha256sum --check --status
  tar -xzf "$archive" -C "$temporary"
  install -d "$go_install"
  cp -a "$temporary/go/." "$go_install/"
  cleanup
  trap - EXIT HUP INT TERM
fi

if ! trivy --version 2>/dev/null | grep -Fq "Version: $trivy_version"; then
  temporary=$(mktemp -d /tmp/boetticher-trivy.XXXXXX)
  cleanup_trivy() {
    rm -rf -- "$temporary"
  }
  trap cleanup_trivy EXIT HUP INT TERM
  archive="$temporary/trivy.tar.gz"
  curl --fail --location --silent --show-error \
    --output "$archive" "https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/trivy_${trivy_version}_Linux-64bit.tar.gz"
  printf '%s  %s\n' "$trivy_sha256" "$archive" | sha256sum --check --status
  tar -xzf "$archive" -C "$temporary"
  install -m 0755 "$temporary/trivy" /usr/local/bin/trivy
  cleanup_trivy
  trap - EXIT HUP INT TERM
fi

install -d -m 0755 "$go_root"
ln -sfn "$go_install" "$go_root/current"
install -d -m 0755 /var/cache/boetticher /var/tmp/boetticher-image-build

PATH="$go_root/current/bin:$PATH" go version
trivy --version | sed -n '1p'
printf '%s\n' 'Local builder: PASS dependencies and pinned Go toolchain installed'
printf '%s\n' 'Local builder cache: /var/cache/boetticher'
