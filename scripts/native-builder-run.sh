#!/bin/sh
set -eu

operation=${1:-}
shift || true
case "$operation" in
  build) script=./scripts/build-images.sh ;;
  scan) script=./scripts/scan-images.sh ;;
  *) printf 'HOLD: unsupported native builder operation: %s\n' "$operation" >&2; exit 2 ;;
esac

native_root=${BOETTICHER_NATIVE_ROOT:-/var/lib/boetticher/local-builder/root}
native_source=${BOETTICHER_NATIVE_SOURCE:-/var/lib/boetticher/local-builder/source}
native_output=${BOETTICHER_NATIVE_OUTPUT:-/var/lib/boetticher/local-builder/output}
native_run_id=${BOETTICHER_NATIVE_RUN_ID:-$$}
for path in "$native_root" "$native_source" "$native_output"; do
  case "$path" in
    /var/lib/boetticher/local-builder/*) ;;
    *) printf 'HOLD: native builder path is outside its fixed workspace: %s\n' "$path" >&2; exit 2 ;;
  esac
done
[ -x "$native_root/bin/sh" ] || { printf '%s\n' 'HOLD: isolated native Debian root is not initialized' >&2; exit 2; }

native_guest_source="$native_root/var/lib/boetticher/local-builder/source"
rm -rf -- "$native_guest_source"
install -d -m 0755 "$native_guest_source"
tar -C "$native_source" -cf - . | tar -C "$native_guest_source" -xf -
install -d -m 0755 "$native_root/var/lib/boetticher/local-builder/output"
install -d -m 0700 "$native_root/tmp/boetticher-runtime"
run_pid_file="$native_output/.native-builder-run.pid"
if [ -e "$run_pid_file" ]; then
  IFS=' ' read -r existing_run_id existing_pid < "$run_pid_file" || true
  : "$existing_run_id"
  case "$existing_pid" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "$existing_pid" 2>/dev/null; then
        printf '%s\n' 'HOLD: another native builder run is active' >&2
        exit 2
      fi
      rm -f -- "$run_pid_file"
      ;;
  esac
fi
printf '%s %s\n' "$native_run_id" "$$" > "$run_pid_file"
chmod 0600 "$run_pid_file"

mounted_dev=0
mounted_kvm=0
mounted_fuse=0
mounted_pts=0
mounted_proc=0
cleanup() {
  if [ "$mounted_proc" -eq 1 ]; then
    umount "$native_root/proc" 2>/dev/null || true
  fi
  if [ "$mounted_pts" -eq 1 ]; then
    umount "$native_root/dev/pts" 2>/dev/null || true
  fi
  if [ "$mounted_kvm" -eq 1 ]; then
    umount "$native_root/dev/kvm" 2>/dev/null || true
  fi
  if [ "$mounted_fuse" -eq 1 ]; then
    umount "$native_root/dev/fuse" 2>/dev/null || true
  fi
  if [ "$mounted_dev" -eq 1 ]; then
    umount "$native_root/dev" 2>/dev/null || true
  fi
  if [ -f "$run_pid_file" ]; then
    IFS=' ' read -r recorded_run_id recorded_pid < "$run_pid_file" || true
    if [ "$recorded_pid" = "$$" ] && { [ -z "$native_run_id" ] || [ "$recorded_run_id" = "$native_run_id" ]; }; then
      rm -f -- "$run_pid_file"
    fi
  fi
}
trap cleanup EXIT HUP INT TERM
install -d -m 0755 "$native_root/dev" "$native_root/proc"
mount -t tmpfs -o mode=0755,nosuid tmpfs "$native_root/dev"
mounted_dev=1
for device in null zero random urandom tty console full; do
  case "$device" in
    null) major=1; minor=3 ;;
    zero) major=1; minor=5 ;;
    random) major=1; minor=8 ;;
    urandom) major=1; minor=9 ;;
    tty) major=5; minor=0 ;;
    console) major=5; minor=1 ;;
    full) major=1; minor=7 ;;
  esac
  mknod -m 0666 "$native_root/dev/$device" c "$major" "$minor"
done
install -d -m 0755 "$native_root/dev/pts"
mknod -m 0660 "$native_root/dev/kvm" c 10 232
mknod -m 0666 "$native_root/dev/fuse" c 10 229
ln -s pts/ptmx "$native_root/dev/ptmx"
mount -t devpts -o gid=5,mode=620,ptmxmode=666 devpts "$native_root/dev/pts"
mounted_pts=1
mount --bind /dev/kvm "$native_root/dev/kvm"
mounted_kvm=1
mount --bind /dev/fuse "$native_root/dev/fuse"
mounted_fuse=1
mount -t proc proc "$native_root/proc"
mounted_proc=1

chroot "$native_root" /usr/bin/env \
  GOROOT=/opt/boetticher/go/current \
  PATH=/opt/boetticher/go/current/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  XDG_RUNTIME_DIR=/tmp/boetticher-runtime \
  BOETTICHER_CACHE_ROOT=/var/cache/boetticher \
  BOETTICHER_IMAGE_WORK=/var/tmp/boetticher-image-build \
  BOETTICHER_ARTIFACT_OUTPUT=/var/lib/boetticher/local-builder/output/generated/artifacts \
  BOETTICHER_EVIDENCE_ROOT=/var/lib/boetticher/local-builder/output \
  BOETTICHER_LOCAL_FAST=1 \
  /bin/sh -c 'cd /var/lib/boetticher/local-builder/source && exec "$@"' /bin/sh "$script" "$@"
