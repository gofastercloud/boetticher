#!/bin/sh
set -eu

# shellcheck source=images/firewall/build/process-supervisor.sh
. /tmp/boetticher-firewall-process-supervisor

if [ "$#" -eq 0 ]; then
  echo "HOLD: firewall package installer requires at least one package" >&2
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "HOLD: firewall package installer requires GNU timeout" >&2
  exit 2
fi
if ! command -v setsid >/dev/null 2>&1; then
  echo "HOLD: firewall package installer requires setsid" >&2
  exit 2
fi

efi_mounted_by_installer=0
cleanup() {
  status=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [ "$efi_mounted_by_installer" -eq 1 ] && mountpoint -q /boot/efi; then
    if ! timeout --signal=TERM --kill-after=5s 30s sync -f /boot/efi; then
      echo "HOLD: firewall package installer could not flush the EFI system partition" >&2
      status=2
    fi
    if ! timeout --signal=TERM --kill-after=5s 30s umount /boot/efi; then
      echo "HOLD: firewall package installer could not unmount the EFI system partition" >&2
      status=2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'bounded_signal HUP 129' HUP
trap 'bounded_signal INT 130' INT
trap 'bounded_signal TERM 143' TERM

if [ -L /boot/efi ]; then
  echo "HOLD: firewall EFI mount point must not be a symbolic link" >&2
  exit 2
fi
install -d -m 0755 /boot/efi
if ! mountpoint -q /boot/efi; then
  if [ ! -b /dev/sda15 ]; then
    echo "HOLD: pinned firewall image is missing EFI system partition /dev/sda15" >&2
    exit 2
  fi
  efi_mounted_by_installer=1
  mount -t vfat -o umask=077 /dev/sda15 /boot/efi
fi

efi_source=$(findmnt --noheadings --output SOURCE --target /boot/efi)
efi_type=$(findmnt --noheadings --output FSTYPE --target /boot/efi)
if [ "$efi_source" != /dev/sda15 ]; then
  echo "HOLD: firewall EFI mount point has unexpected source: $efi_source" >&2
  exit 2
fi
if [ "$efi_type" != vfat ]; then
  echo "HOLD: firewall EFI system partition has unexpected filesystem type: $efi_type" >&2
  exit 2
fi

rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list
export DEBIAN_FRONTEND=noninteractive
run_bounded_command 30m apt-get --no-download upgrade --yes --no-install-recommends
run_bounded_command 30m apt-get --no-download install --yes --no-install-recommends "$@"
apt-get clean
rm -rf /var/lib/apt/lists/*
rm -f /etc/resolv.conf
