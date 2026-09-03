#!/bin/sh
set -eu

mount_path=/var/lib/boetticher/local-builder
marker_path=$mount_path/.boetticher-native-builder
device=${BOETTICHER_LOCAL_BUILDER_DEVICE:-}
confirmed=${BOETTICHER_LOCAL_BUILDER_STORAGE_CONFIRMED:-0}
reinitialize=${BOETTICHER_LOCAL_BUILDER_STORAGE_REINITIALIZE:-0}

hold() {
  printf 'HOLD: %s\n' "$1" >&2
  exit 2
}

if [ "$(uname -s)" != Linux ]; then
  hold 'native builder storage setup must run on Linux'
fi
if [ "$(id -u)" -ne 0 ]; then
  hold 'native builder storage setup requires root'
fi
if [ -z "$device" ]; then
  hold 'BOETTICHER_LOCAL_BUILDER_DEVICE must name the exact build disk'
fi
case "$device" in
  /dev/disk/by-id/*) ;;
  *) hold 'BOETTICHER_LOCAL_BUILDER_DEVICE must be one direct /dev/disk/by-id path' ;;
esac
case "$device" in
  *[![:alnum:]_./:+-]*) hold 'BOETTICHER_LOCAL_BUILDER_DEVICE contains unsupported characters' ;;
esac
case "$confirmed" in
  1|yes|true) ;;
  *) hold 'native builder storage setup is destructive; repeat with explicit confirmation' ;;
esac
case "$reinitialize" in
  0|no|false) reinitialize=no ;;
  1|yes|true) reinitialize=yes ;;
  *) hold 'BOETTICHER_LOCAL_BUILDER_STORAGE_REINITIALIZE must be 0 or 1' ;;
esac

for tool in awk blkid cp find findmnt grep install lsblk mkfs.ext4 mount mountpoint mktemp mv readlink swapon wipefs; do
  command -v "$tool" >/dev/null 2>&1 || hold "required native builder storage tool is unavailable: $tool"
done
command -v pvs >/dev/null 2>&1 || hold 'required native builder storage tool is unavailable: pvs'
if [ ! -f /etc/fstab ] || [ -L /etc/fstab ]; then
  hold '/etc/fstab must be a regular file'
fi

test -e "$device" && test -b "$(readlink -f "$device")" || hold 'configured build device is absent or not a block device'
resolved=$(readlink -f "$device")
[ "$(lsblk -ndo TYPE "$resolved")" = disk ] || hold 'configured build device must resolve to a whole disk'

root_source=$(findmnt -no SOURCE /) || hold 'cannot determine the Linux system filesystem'
root_device=$root_source
while parent=$(lsblk -ndo PKNAME "$root_device"); do
  [ -n "$parent" ] || break
  root_device=/dev/$parent
done
[ "$resolved" != "$root_device" ] || hold 'refusing the Linux system disk as the native builder disk'

is_target_device_or_partition() {
  candidate=$(readlink -f "$1")
  case "$candidate" in
    "$resolved"|"$resolved"[0-9]*|"$resolved"p[0-9]*) return 0 ;;
  esac
  return 1
}

if lsblk -nrpo MOUNTPOINT "$resolved" | awk 'NF { found=1 } END { exit found ? 0 : 1 }'; then
  hold 'refusing a build disk with a mounted filesystem or mounted partition'
fi
if swapon --noheadings --raw --output NAME 2>/dev/null | (
  while IFS= read -r swap; do
    [ -n "$swap" ] && is_target_device_or_partition "$swap" && exit 0
  done
  exit 1
); then
  hold 'refusing a build disk with active swap'
fi
if pvs --noheadings -o pv_name 2>/dev/null | (
  while IFS= read -r pv; do
    pv=$(printf '%s' "$pv" | awk '{$1=$1; print}')
    [ -n "$pv" ] && is_target_device_or_partition "$pv" && exit 0
  done
  exit 1
); then
  hold 'refusing a build disk already used by LVM'
fi

fstab_entry=$(awk '$2 == "/var/lib/boetticher/local-builder" && $1 !~ /^#/ { print; exit }' /etc/fstab)
if mountpoint -q "$mount_path"; then
  mounted_source=$(findmnt -no SOURCE "$mount_path") || hold 'cannot inspect the existing native builder mount'
  [ "$(readlink -f "$mounted_source")" = "$resolved" ] || hold 'native builder mount is backed by an unexpected device'
  [ -w "$mount_path" ] || hold 'native builder mount is not writable'
  filesystem=$(blkid -s TYPE -o value "$resolved" 2>/dev/null || true)
  uuid=$(blkid -s UUID -o value "$resolved" 2>/dev/null || true)
  [ "$filesystem" = ext4 ] && [ -n "$uuid" ] || hold 'existing native builder mount is not an identifiable ext4 filesystem'
  expected="UUID=$uuid $mount_path ext4 defaults,nofail 0 2"
  [ -z "$fstab_entry" ] || [ "$fstab_entry" = "$expected" ] || hold 'existing /etc/fstab entry conflicts with the native builder disk'
  if [ -z "$fstab_entry" ]; then
    fstab_tmp=$(mktemp /etc/.fstab.boetticher-builder.XXXXXX)
    trap 'rm -f "$fstab_tmp"' EXIT HUP INT TERM
    cp -p /etc/fstab "$fstab_tmp"
    printf '%s\n' "$expected" >> "$fstab_tmp"
    mv -f "$fstab_tmp" /etc/fstab
    trap - EXIT HUP INT TERM
    fstab_tmp=
  fi
else
  if [ -n "$fstab_entry" ]; then
    filesystem=$(blkid -s TYPE -o value "$resolved" 2>/dev/null || true)
    uuid=$(blkid -s UUID -o value "$resolved" 2>/dev/null || true)
    expected="UUID=$uuid $mount_path ext4 defaults,nofail 0 2"
    [ "$fstab_entry" = "$expected" ] || hold 'existing /etc/fstab entry conflicts with the native builder disk'
    [ "$filesystem" = ext4 ] && [ -n "$uuid" ] || hold 'existing native builder fstab entry has no matching ext4 filesystem'
    install -d -m 0755 "$mount_path"
    mount "$mount_path"
  else
    install -d -m 0755 "$mount_path"
    if find "$mount_path" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
      hold 'native builder mount directory is not empty before initialization'
    fi
    if wipefs -n "$resolved" 2>/dev/null | grep -q .; then
      [ "$reinitialize" = yes ] || hold 'build disk has existing signatures; repeat with explicit reinitialization after reviewing the exact stable device'
      wipefs --all --force "$resolved"
      command -v partprobe >/dev/null 2>&1 && partprobe "$resolved" || true
      command -v udevadm >/dev/null 2>&1 && udevadm settle || true
      if wipefs -n "$resolved" 2>/dev/null | grep -q .; then
        hold 'build disk signatures remain after reinitialization'
      fi
    fi
    mkfs.ext4 -F -L boetticher-builder "$resolved"
    filesystem=$(blkid -s TYPE -o value "$resolved" 2>/dev/null || true)
    uuid=$(blkid -s UUID -o value "$resolved" 2>/dev/null || true)
    [ "$filesystem" = ext4 ] && [ -n "$uuid" ] || hold 'new native builder filesystem could not be identified'
    expected="UUID=$uuid $mount_path ext4 defaults,nofail 0 2"
    fstab_tmp=$(mktemp /etc/.fstab.boetticher-builder.XXXXXX)
    trap 'rm -f "$fstab_tmp"' EXIT HUP INT TERM
    cp -p /etc/fstab "$fstab_tmp"
    printf '%s\n' "$expected" >> "$fstab_tmp"
    mv -f "$fstab_tmp" /etc/fstab
    trap - EXIT HUP INT TERM
    fstab_tmp=
    mount "$mount_path"
  fi
fi

mounted_source=$(findmnt -no SOURCE "$mount_path") || hold 'native builder mount did not become active'
[ "$(readlink -f "$mounted_source")" = "$resolved" ] || hold 'native builder mount resolved to an unexpected device'
[ -w "$mount_path" ] || hold 'native builder mount is not writable'

if [ -e "$marker_path" ]; then
  if [ ! -f "$marker_path" ] || ! grep -Fxq 'boetticher native builder storage v1' "$marker_path"; then
    hold 'native builder ownership marker has unexpected content'
  fi
else
  marker_tmp=$(mktemp "$mount_path/.boetticher-native-builder.XXXXXX")
  trap 'rm -f "$marker_tmp"' EXIT HUP INT TERM
  printf '%s\n' 'boetticher native builder storage v1' > "$marker_tmp"
  chmod 0644 "$marker_tmp"
  mv -f "$marker_tmp" "$marker_path"
  trap - EXIT HUP INT TERM
  marker_tmp=
fi

printf 'Native builder storage: PASS\n'
printf 'Native builder device: %s\n' "$device"
printf 'Native builder mount: %s\n' "$mount_path"
