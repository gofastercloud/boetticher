#!/bin/sh
set -eu

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/local-builder.sh init
  scripts/local-builder.sh init-storage
  scripts/local-builder.sh build image-TARGET
  scripts/local-builder.sh build images [image-TARGET ...]
  scripts/local-builder.sh scan scan-TARGET

On macOS, set BOETTICHER_LOCAL_BUILDER_SSH to the native amd64 Linux build
host. On Linux, this script runs the native builder directly. The standard
workspace is /var/lib/boetticher/local-builder on the build host's root
filesystem; it must not be a Proxmox guest-storage disk.
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
builder_device=${BOETTICHER_LOCAL_BUILDER_DEVICE:-}
storage_confirmed=${BOETTICHER_LOCAL_BUILDER_STORAGE_CONFIRMED:-0}
storage_reinitialize=${BOETTICHER_LOCAL_BUILDER_STORAGE_REINITIALIZE:-0}
cache_root=${BOETTICHER_LOCAL_CACHE_ROOT:-/var/cache/boetticher}
work_root=${BOETTICHER_LOCAL_IMAGE_WORK:-/var/tmp/boetticher-image-build}
artifact_output=${BOETTICHER_LOCAL_ARTIFACT_OUTPUT:-generated/artifacts}
remote_root=/var/lib/boetticher/local-builder
remote_source="$remote_root/source"
remote_output="$remote_root/output"
remote_native_root="$remote_root/root"
remote_native_output="$remote_native_root$remote_output"

native_image_targets='image-base image-dns-blocky image-logging image-monitoring image-tailnet-router image-airvpn image-bifrost image-printer image-arr image-aiops image-gatus image-network-probe image-firewall'
native_scan_names='boetticher-base boetticher-dns-blocky boetticher-logging boetticher-monitoring boetticher-firewall boetticher-tailnet-router boetticher-airvpn boetticher-bifrost boetticher-printer boetticher-arr boetticher-aiops boetticher-gatus boetticher-network-probe'

case "$builder_ssh" in
  *[![:alnum:]@._:-]*) fail 'BOETTICHER_LOCAL_BUILDER_SSH contains unsupported characters' ;;
esac
case "$cache_root$work_root$artifact_output" in
  *[![:alnum:]_./:-]*) fail 'local builder paths may contain only letters, digits, _, ., /, :, and -' ;;
esac
case "$builder_identity$builder_known_hosts" in
  *[![:alnum:]_./:-]*) fail 'native builder identity and known-hosts paths may contain only letters, digits, _, ., /, :, and -' ;;
esac
if [ -n "$builder_device" ]; then
  case "$builder_device" in
    /dev/disk/by-id/*) ;;
    *) fail 'BOETTICHER_LOCAL_BUILDER_DEVICE must be one direct /dev/disk/by-id path' ;;
  esac
  case "$builder_device" in
    *[![:alnum:]_./:+-]*) fail 'BOETTICHER_LOCAL_BUILDER_DEVICE contains unsupported characters' ;;
  esac
fi

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
  export GOROOT=/opt/boetticher/go/current
  export PATH="$GOROOT/bin:$PATH"
  export BOETTICHER_CACHE_ROOT="$cache_root"
  export BOETTICHER_IMAGE_WORK="$work_root"
  export BOETTICHER_ARTIFACT_OUTPUT="$artifact_output"
  export BOETTICHER_LOCAL_FAST=1
  exec "$repo_root/$script" "$@"
}

native_ssh() {
  if [ -n "$builder_identity" ] && [ -n "$builder_known_hosts" ]; then
    /usr/bin/ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ForwardX11=no -o UserKnownHostsFile="$builder_known_hosts" -o IdentitiesOnly=yes -i "$builder_identity" "$builder_ssh" "$@"
  elif [ -n "$builder_identity" ]; then
    /usr/bin/ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ForwardX11=no -o IdentitiesOnly=yes -i "$builder_identity" "$builder_ssh" "$@"
  elif [ -n "$builder_known_hosts" ]; then
    /usr/bin/ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ForwardX11=no -o UserKnownHostsFile="$builder_known_hosts" "$builder_ssh" "$@"
  else
    /usr/bin/ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o ForwardAgent=no -o ForwardX11=no "$builder_ssh" "$@"
  fi
}

validate_native_connection() {
  [ -n "$builder_ssh" ] || fail 'BOETTICHER_LOCAL_BUILDER_SSH is required for the native Linux build host'
  if [ -n "$builder_identity" ] && [ ! -f "$builder_identity" ]; then
    fail 'BOETTICHER_LOCAL_BUILDER_IDENTITY does not name a regular file'
  fi
  if [ -n "$builder_known_hosts" ] && [ ! -f "$builder_known_hosts" ]; then
    fail 'BOETTICHER_LOCAL_BUILDER_KNOWN_HOSTS does not name a regular file'
  fi
}

require_native_workspace() {
  validate_native_connection
  [ -z "$builder_device" ] || fail 'BOETTICHER_LOCAL_BUILDER_DEVICE is only valid for the separate maintainer storage initializer'
  workspace_check='test ! -L /var/lib/boetticher/local-builder && install -d -m 0755 /var/lib/boetticher/local-builder && test -w /var/lib/boetticher/local-builder && test "$(findmnt -no TARGET -T /var/lib/boetticher/local-builder)" = /'
  if ! native_ssh "$workspace_check"; then
    fail 'native build host must keep /var/lib/boetticher/local-builder on its root filesystem'
  fi
}

run_native_storage_init() {
  [ -n "$builder_device" ] || fail 'BOETTICHER_LOCAL_BUILDER_DEVICE is required for native builder storage setup'
  case "$storage_confirmed" in
    1|yes|true) ;;
    *) fail 'native builder storage setup is destructive; repeat with explicit confirmation' ;;
  esac
  case "$storage_reinitialize" in
    0|no|false|1|yes|true) ;;
    *) fail 'BOETTICHER_LOCAL_BUILDER_STORAGE_REINITIALIZE must be 0 or 1' ;;
  esac
  case "$(uname -s)" in
    Darwin)
      validate_native_connection
      native_ssh "env BOETTICHER_LOCAL_BUILDER_DEVICE=$builder_device BOETTICHER_LOCAL_BUILDER_STORAGE_CONFIRMED=$storage_confirmed BOETTICHER_LOCAL_BUILDER_STORAGE_REINITIALIZE=$storage_reinitialize sh -s" < "$repo_root/scripts/local-builder-storage.sh"
      ;;
    Linux)
      exec env BOETTICHER_LOCAL_BUILDER_DEVICE="$builder_device" BOETTICHER_LOCAL_BUILDER_STORAGE_CONFIRMED="$storage_confirmed" BOETTICHER_LOCAL_BUILDER_STORAGE_REINITIALIZE="$storage_reinitialize" "$repo_root/scripts/local-builder-storage.sh"
      ;;
    *) fail 'local builder supports macOS or Linux only' ;;
  esac
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
  require_native_workspace
  [ -n "$builder_ssh" ] || fail 'BOETTICHER_LOCAL_BUILDER_SSH is required for the native Linux build host'
  native_ssh 'rm -rf -- /var/lib/boetticher/local-builder/source; install -d -m 0755 /var/lib/boetticher/local-builder/source'
  source_archive=$(mktemp "${TMPDIR:-/tmp}/boetticher-source.XXXXXX")
  if ! GOCACHE=${GOCACHE:-/tmp/boetticher-gocache} go run ./cmd/local-builder-archive -mode source -root "$repo_root" > "$source_archive"; then
    rm -f -- "$source_archive"
    fail 'could not create the public native-builder source archive'
  fi
  if ! native_ssh 'tar --extract --gzip --file=- --no-same-owner --no-same-permissions --directory=/var/lib/boetticher/local-builder/source' < "$source_archive"; then
    rm -f -- "$source_archive"
    fail 'could not transfer the public native-builder source archive'
  fi
  rm -f -- "$source_archive"
}

artifact_module() {
  artifact=$1
  module=${artifact#image-}
  [ "$module" = dns-blocky ] && module=dns
  printf '%s\n' "$module"
}

remote_artifact_reusable() {
  artifact=$1
  module=$(artifact_module "$artifact")
  native_ssh "cd $remote_source && env GOCACHE=/var/cache/boetticher/go /opt/boetticher/go/current/bin/go run ./cmd/artifact-reuse -root $remote_output -module $module" >/dev/null 2>&1
}

filter_reusable_targets() {
  operation=$1
  shift
  mode=$1
  original_args=$*
  reusable=0
  pending=
  case "$operation:$mode" in
    build:images)
      shift
      selected=$*
      [ -n "$selected" ] || selected=$native_image_targets
      for target in $selected; do
        if remote_artifact_reusable "$target"; then
          printf 'measurement stage=artifact_reuse status=hit artifact=%s\n' "${target#image-}"
          reusable=$((reusable + 1))
        else
          pending="$pending $target"
        fi
      done
      ;;
    scan:scan-images)
      shift
      selected=$*
      [ -n "$selected" ] || selected=$native_scan_names
      for target in $selected; do
        image_target=image-${target#boetticher-}
        [ "$target" = boetticher-dns-blocky ] && image_target=image-dns-blocky
        if remote_artifact_reusable "$image_target"; then
          printf 'measurement stage=artifact_reuse status=hit artifact=%s\n' "$target"
          reusable=$((reusable + 1))
        else
          pending="$pending $target"
        fi
      done
      ;;
    build:*|scan:*)
      target=$1
      case "$operation:$target" in
        build:image-*) image_target=$target ;;
        scan:scan-*) image_target=image-${target#scan-} ;;
        *) image_target= ;;
      esac
      if [ -n "$image_target" ] && remote_artifact_reusable "$image_target"; then
        printf 'measurement stage=artifact_reuse status=hit artifact=%s\n' "${image_target#image-}"
        reusable=1
      fi
      ;;
  esac
  if [ "$reusable" -gt 0 ] && [ -z "$pending" ]; then
    return 0
  fi
  if [ "$reusable" -gt 0 ]; then
    native_filtered_args="$mode $pending"
  else
    native_filtered_args="$original_args"
  fi
  return 1
}

setup_native_builder() {
  [ "$artifact_output" = generated/artifacts ] || fail 'native builder mode requires the default generated/artifacts output path'
  sync_native_source
  native_ssh \
    "env BOETTICHER_LOCAL_NATIVE=1 BOETTICHER_SOURCE_ROOT=$remote_source sh $remote_source/scripts/local-builder-setup.sh"
}

pull_native_output() {
  mkdir -p "$repo_root/generated"
  output_archive=$(mktemp "${TMPDIR:-/tmp}/boetticher-native-output.XXXXXX")
  if ! native_ssh "tar -C $remote_native_output -cf - generated" > "$output_archive"; then
    rm -f -- "$output_archive"
    fail 'could not retrieve native builder output'
  fi
  if ! GOCACHE=${GOCACHE:-/tmp/boetticher-gocache} go run ./cmd/local-builder-archive -mode output -root "$repo_root" < "$output_archive"; then
    rm -f -- "$output_archive"
    fail 'native builder output failed bounded archive validation'
  fi
  rm -f -- "$output_archive"
}

run_native_builder() {
  runner=$1
  shift
  [ "$artifact_output" = generated/artifacts ] || fail 'native builder mode requires the default generated/artifacts output path'
  validate_remote_target "$runner" "$@"
  sync_native_source
  if filter_reusable_targets "$runner" "$@"; then
    return 0
  fi
  set -- $native_filtered_args
  case "$runner" in
    build) script=./scripts/build-images.sh ;;
    scan) script=./scripts/scan-images.sh ;;
    *) fail "unsupported local builder operation: $runner" ;;
  esac
  remote_args=
  for target in "$@"; do
    remote_args="$remote_args $target"
  done
  native_run_id=$$
  abort_native_builder() {
    native_ssh "if [ -f $remote_native_output/.native-builder-run.pid ]; then IFS=' ' read -r recorded_run_id recorded_pid < $remote_native_output/.native-builder-run.pid || true; if [ \"\$recorded_run_id\" = \"$native_run_id\" ]; then case \"\$recorded_pid\" in ''|*[!0-9]*) ;; *) kill -TERM -- -\"\$recorded_pid\" 2>/dev/null || kill -TERM \"\$recorded_pid\" 2>/dev/null || true ;; esac; fi; fi" >/dev/null 2>&1 || true
  }
  trap abort_native_builder INT TERM HUP
  if native_ssh \
    "env BOETTICHER_NATIVE_RUN_ID=$native_run_id BOETTICHER_NATIVE_SOURCE=$remote_source BOETTICHER_NATIVE_ROOT=$remote_native_root BOETTICHER_NATIVE_OUTPUT=$remote_native_output sh $remote_source/scripts/native-builder-run.sh $runner$remote_args"; then
    trap - INT TERM HUP
    pull_native_output
  else
    status=$?
    abort_native_builder
    trap - INT TERM HUP
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
  init-storage)
    [ "$#" -eq 0 ] || { usage; exit 2; }
    run_native_storage_init
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
