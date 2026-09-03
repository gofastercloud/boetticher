#!/bin/sh
set -eu

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/local-builder.sh init
scripts/local-builder.sh build image-TARGET
scripts/local-builder.sh build images [image-TARGET ...]
scripts/local-builder.sh scan scan-TARGET

On macOS, set BOETTICHER_LOCAL_BUILDER_SSH to the native amd64 Linux build
host. On Linux, this script runs the native builder directly. The build host
must provide the persistent cache and output mount.
USAGE
}

fail() {
  printf 'HOLD: %s\n' "$1" >&2
  exit 2
}

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'run from inside the Boetticher checkout'
builder_ssh=${BOETTICHER_LOCAL_BUILDER_SSH:-}
builder_identity=${BOETTICHER_LOCAL_BUILDER_IDENTITY:-}
builder_known_hosts=${BOETTICHER_LOCAL_BUILDER_KNOWN_HOSTS:-}
cache_root=${BOETTICHER_LOCAL_CACHE_ROOT:-/var/cache/boetticher}
work_root=${BOETTICHER_LOCAL_IMAGE_WORK:-/var/tmp/boetticher-image-build}
artifact_output=${BOETTICHER_LOCAL_ARTIFACT_OUTPUT:-generated/artifacts}
remote_root=/var/lib/boetticher/local-builder
remote_source="$remote_root/source"
remote_output="$remote_root/output"
remote_native_root="$remote_root/root"
remote_native_output="$remote_native_root$remote_output"

case "$cache_root$work_root$artifact_output" in
  *[![:alnum:]_./:-]*) fail 'local builder paths may contain only letters, digits, _, ., /, :, and -' ;;
esac
case "$builder_identity$builder_known_hosts" in
  *[![:alnum:]_./:-]*) fail 'native builder identity and known-hosts paths may contain only letters, digits, _, ., /, :, and -' ;;
esac

if [ "$#" -lt 1 ]; then
  usage
  exit 2
fi

run_linux() {
  runner=$1
  shift
  case "$runner" in
    build) script=./scripts/build-images.sh ;;
    scan) script=./scripts/scan-images.sh ;;
    *) fail "unsupported local builder operation: $runner" ;;
  esac
  export PATH="/opt/boetticher/go/current/bin:$PATH"
  export BOETTICHER_CACHE_ROOT="$cache_root"
  export BOETTICHER_IMAGE_WORK="$work_root"
  export BOETTICHER_ARTIFACT_OUTPUT="$artifact_output"
  export BOETTICHER_LOCAL_FAST=1
  exec "$repo_root/$script" "$@"
}

native_ssh() {
  if [ -n "$builder_identity" ] && [ -n "$builder_known_hosts" ]; then
    ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$builder_known_hosts" -o IdentitiesOnly=yes -i "$builder_identity" "$builder_ssh" "$@"
  elif [ -n "$builder_identity" ]; then
    ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$builder_identity" "$builder_ssh" "$@"
  elif [ -n "$builder_known_hosts" ]; then
    ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$builder_known_hosts" "$builder_ssh" "$@"
  else
    ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes "$builder_ssh" "$@"
  fi
}

require_native_mount() {
  [ -n "$builder_ssh" ] || fail 'BOETTICHER_LOCAL_BUILDER_SSH is required for the native Linux build host'
  if [ -n "$builder_identity" ] && [ ! -f "$builder_identity" ]; then
    fail 'BOETTICHER_LOCAL_BUILDER_IDENTITY does not name a regular file'
  fi
  if ! native_ssh 'test -d /var/lib/boetticher/local-builder && mountpoint -q /var/lib/boetticher/local-builder && test -w /var/lib/boetticher/local-builder'; then
    fail 'native build host must mount the dedicated build disk at /var/lib/boetticher/local-builder'
  fi
}

validate_remote_target() {
  runner=$1
  shift
  for target in "$@"; do
    case "$runner:$target" in
	  build:image-base|build:image-dns-blocky|build:image-logging|build:image-monitoring|build:image-firewall|build:image-tailnet-router|build:image-airvpn|build:image-bifrost|build:image-printer|build:image-arr|build:image-aiops|build:image-gatus|build:image-network-probe|build:images) ;;
	  scan:scan-base|scan:scan-dns-blocky|scan:scan-logging|scan:scan-monitoring|scan:scan-firewall|scan:scan-tailnet-router|scan:scan-airvpn|scan:scan-bifrost|scan:scan-printer|scan:scan-arr|scan:scan-aiops|scan:scan-gatus|scan:scan-network-probe|scan:scan-images) ;;
      *) fail "unsupported native builder target: $target" ;;
    esac
  done
}

sync_native_source() {
  require_native_mount
  [ -n "$builder_ssh" ] || fail 'BOETTICHER_LOCAL_BUILDER_SSH is required for the native Linux build host'
  case "$builder_ssh" in
    *[![:alnum:]@._:-]*) fail 'BOETTICHER_LOCAL_BUILDER_SSH contains unsupported characters' ;;
  esac
  native_ssh 'rm -rf -- /var/lib/boetticher/local-builder/source; install -d -m 0755 /var/lib/boetticher/local-builder/source'
  tar -C "$repo_root" \
    --no-xattrs \
    --no-mac-metadata \
    --exclude .git \
    --exclude .runtime \
    --exclude secrets \
    --exclude generated/artifacts \
    --exclude generated/runtime \
    -cf - . | native_ssh 'tar -xf - -C /var/lib/boetticher/local-builder/source'
}

setup_native_builder() {
  [ "$artifact_output" = generated/artifacts ] || fail 'native builder mode requires the default generated/artifacts output path'
  sync_native_source
  native_ssh \
    "env BOETTICHER_LOCAL_NATIVE=1 BOETTICHER_SOURCE_ROOT=$remote_source sh $remote_source/scripts/local-builder-setup.sh"
}

pull_native_output() {
  mkdir -p "$repo_root/generated"
  native_ssh \
    "tar -C $remote_native_output -cf - generated" | tar -C "$repo_root" -xf -
}

run_native_builder() {
  runner=$1
  shift
  [ "$artifact_output" = generated/artifacts ] || fail 'native builder mode requires the default generated/artifacts output path'
  validate_remote_target "$runner" "$@"
  sync_native_source
  case "$runner" in
    build) script=./scripts/build-images.sh ;;
    scan) script=./scripts/scan-images.sh ;;
    *) fail "unsupported local builder operation: $runner" ;;
  esac
  remote_args=
  for target in "$@"; do
    remote_args="$remote_args $target"
  done
  if native_ssh \
    "env BOETTICHER_NATIVE_SOURCE=$remote_source BOETTICHER_NATIVE_ROOT=$remote_native_root BOETTICHER_NATIVE_OUTPUT=$remote_native_output sh $remote_source/scripts/native-builder-run.sh $runner$remote_args"; then
    pull_native_output
  else
    status=$?
    return "$status"
  fi
}

operation=$1
shift
case "$operation" in
  init)
    [ "$#" -eq 0 ] || { usage; exit 2; }
    case "$(uname -s)" in
      Darwin) setup_native_builder ;;
      Linux)
        exec "$repo_root/scripts/local-builder-setup.sh"
        ;;
      *) fail 'local builder supports macOS or Linux only' ;;
    esac
    ;;
  build|scan)
    [ "$#" -gt 0 ] || { usage; exit 2; }
    case "$(uname -s)" in
      Darwin) run_native_builder "$operation" "$@" ;;
      Linux)
        run_linux "$operation" "$@"
        ;;
      *) fail 'local builder supports macOS or Linux only' ;;
    esac
    ;;
  *) usage; exit 2 ;;
esac
