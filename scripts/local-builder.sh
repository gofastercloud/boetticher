#!/bin/sh
set -eu

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/local-builder.sh init
scripts/local-builder.sh build image-TARGET
scripts/local-builder.sh build images [image-TARGET ...]
scripts/local-builder.sh scan scan-TARGET

On macOS, init creates or starts the amd64 OrbStack machine named by
BOETTICHER_LOCAL_BUILDER_MACHINE. Set
BOETTICHER_LOCAL_BUILDER_MODE=ssh and BOETTICHER_LOCAL_BUILDER_SSH to use a
native amd64 Linux builder instead. Builds use a persistent Linux cache.
USAGE
}

fail() {
  printf 'HOLD: %s\n' "$1" >&2
  exit 2
}

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'run from inside the Boetticher checkout'
machine=${BOETTICHER_LOCAL_BUILDER_MACHINE:-boetticher-builder}
builder_mode=${BOETTICHER_LOCAL_BUILDER_MODE:-orbstack}
builder_ssh=${BOETTICHER_LOCAL_BUILDER_SSH:-}
cache_root=${BOETTICHER_LOCAL_CACHE_ROOT:-/var/cache/boetticher}
work_root=${BOETTICHER_LOCAL_IMAGE_WORK:-/var/tmp/boetticher-image-build}
artifact_output=${BOETTICHER_LOCAL_ARTIFACT_OUTPUT:-generated/artifacts}
remote_root=/var/lib/boetticher/local-builder
remote_source="$remote_root/source"
remote_output="$remote_root/output"
remote_native_root="$remote_root/root"
remote_native_output="$remote_native_root$remote_output"

case "$builder_mode" in
  orbstack|ssh) ;;
  *) fail "unsupported local builder mode: $builder_mode" ;;
esac

case "$cache_root$work_root$artifact_output" in
  *[![:alnum:]_./:-]*) fail 'local builder paths may contain only letters, digits, _, ., /, :, and -' ;;
esac

if [ "$#" -lt 1 ]; then
  usage
  exit 2
fi

setup_orbstack_machine() {
  command -v orbctl >/dev/null 2>&1 || fail 'orbctl is required on macOS; install and start OrbStack first'
  if ! orbctl status >/dev/null 2>&1; then
    fail 'OrbStack is not running; start OrbStack and rerun make local-builder-init'
  fi
  if ! orbctl list -q | grep -Fxq "$machine"; then
    orbctl create --arch amd64 --cpus 4 --memory 8G --disk 80G ubuntu:24.04 "$machine"
  else
    orbctl start "$machine"
  fi
  linux_repo_root=$repo_root
  case "$repo_root" in
    /Users/*) linux_repo_root="/mnt/mac$repo_root" ;;
  esac
  orb -m "$machine" -u root env BOETTICHER_SOURCE_ROOT="$linux_repo_root" sh "$linux_repo_root/scripts/local-builder-setup.sh"
}

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

run_orbstack() {
  runner=$1
  shift
  command -v orb >/dev/null 2>&1 || fail 'orb is required on macOS; install and start OrbStack first'
  if ! orbctl status >/dev/null 2>&1; then
    fail 'OrbStack is not running; start OrbStack and rerun the local builder'
  fi
  if ! orbctl list -q | grep -Fxq "$machine"; then
    fail "OrbStack machine $machine is missing; run make local-builder-init"
  fi
  orbctl start "$machine" >/dev/null
  linux_repo_root=$repo_root
  case "$repo_root" in
    /Users/*) linux_repo_root="/mnt/mac$repo_root" ;;
  esac
  orb -m "$machine" -u root sh -s -- "$linux_repo_root" "$cache_root" "$work_root" "$artifact_output" "$runner" "$@" <<'LINUX_RUN'
set -eu
repo_root=$1
cache_root=$2
work_root=$3
artifact_output=$4
runner=$5
shift 5
cd "$repo_root"
export PATH="/opt/boetticher/go/current/bin:$PATH"
export BOETTICHER_CACHE_ROOT="$cache_root"
export BOETTICHER_IMAGE_WORK="$work_root"
export BOETTICHER_ARTIFACT_OUTPUT="$artifact_output"
export BOETTICHER_LOCAL_FAST=1
case "$runner" in
  build) exec ./scripts/build-images.sh "$@" ;;
  scan) exec ./scripts/scan-images.sh "$@" ;;
  *) printf 'HOLD: unsupported local builder operation: %s\n' "$runner" >&2; exit 2 ;;
esac
LINUX_RUN
}

validate_remote_target() {
  runner=$1
  shift
  for target in "$@"; do
    case "$runner:$target" in
      build:image-base|build:image-dns-blocky|build:image-logging|build:image-monitoring|build:image-firewall|build:image-portal|build:image-tailnet-router|build:image-airvpn|build:image-bifrost|build:image-printer|build:image-arr|build:image-aiops|build:image-gatus|build:image-network-probe|build:images) ;;
      scan:scan-base|scan:scan-dns-blocky|scan:scan-logging|scan:scan-monitoring|scan:scan-firewall|scan:scan-portal|scan:scan-tailnet-router|scan:scan-airvpn|scan:scan-bifrost|scan:scan-printer|scan:scan-arr|scan:scan-aiops|scan:scan-gatus|scan:scan-network-probe|scan:scan-images) ;;
      *) fail "unsupported native builder target: $target" ;;
    esac
  done
}

sync_native_source() {
  [ -n "$builder_ssh" ] || fail 'BOETTICHER_LOCAL_BUILDER_SSH is required for the ssh builder mode'
  case "$builder_ssh" in
    *[![:alnum:]@._:-]*) fail 'BOETTICHER_LOCAL_BUILDER_SSH contains unsupported characters' ;;
  esac
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$builder_ssh" 'rm -rf -- /var/lib/boetticher/local-builder/source; install -d -m 0755 /var/lib/boetticher/local-builder/source'
  tar -C "$repo_root" \
    --no-xattrs \
    --no-mac-metadata \
    --exclude .git \
    --exclude .runtime \
    --exclude secrets \
    --exclude generated/artifacts \
    --exclude generated/runtime \
    -cf - . | ssh -o BatchMode=yes -o ConnectTimeout=10 "$builder_ssh" 'tar -xf - -C /var/lib/boetticher/local-builder/source'
}

setup_native_builder() {
  [ "$artifact_output" = generated/artifacts ] || fail 'ssh builder mode requires the default generated/artifacts output path'
  sync_native_source
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$builder_ssh" \
    "env BOETTICHER_LOCAL_NATIVE=1 BOETTICHER_SOURCE_ROOT=$remote_source sh $remote_source/scripts/local-builder-setup.sh"
}

pull_native_output() {
  mkdir -p "$repo_root/generated"
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$builder_ssh" \
    "tar -C $remote_native_output -cf - generated" | tar -C "$repo_root" -xf -
}

run_native_builder() {
  runner=$1
  shift
  [ "$artifact_output" = generated/artifacts ] || fail 'ssh builder mode requires the default generated/artifacts output path'
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
  if ssh -o BatchMode=yes -o ConnectTimeout=10 "$builder_ssh" \
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
      Darwin)
        case "$builder_mode" in
          orbstack) setup_orbstack_machine ;;
          ssh) setup_native_builder ;;
        esac
        ;;
      Linux)
        if [ "$builder_mode" = ssh ]; then
          setup_native_builder
        else
          exec "$repo_root/scripts/local-builder-setup.sh"
        fi
        ;;
      *) fail 'local builder supports macOS or Linux only' ;;
    esac
    ;;
  build|scan)
    [ "$#" -gt 0 ] || { usage; exit 2; }
    case "$(uname -s)" in
      Darwin)
        case "$builder_mode" in
          orbstack) run_orbstack "$operation" "$@" ;;
          ssh) run_native_builder "$operation" "$@" ;;
        esac
        ;;
      Linux)
        if [ "$builder_mode" = ssh ]; then
          run_native_builder "$operation" "$@"
        else
          run_linux "$operation" "$@"
        fi
        ;;
      *) fail 'local builder supports macOS or Linux only' ;;
    esac
    ;;
  *) usage; exit 2 ;;
esac
