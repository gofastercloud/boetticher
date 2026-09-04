#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  echo "HOLD: firewall package installer requires at least one package" >&2
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "HOLD: firewall package installer requires GNU timeout" >&2
  exit 2
fi

efi_mounted_by_installer=0
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$efi_mounted_by_installer" -eq 1 ] && mountpoint -q /boot/efi; then
    if ! sync; then
      echo "HOLD: firewall package installer could not flush the EFI system partition" >&2
      status=2
    fi
    if ! umount /boot/efi; then
      echo "HOLD: firewall package installer could not unmount the EFI system partition" >&2
      status=2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
DEBIAN_FRONTEND=noninteractive timeout --signal=TERM --kill-after=30s 30m apt-get --no-download upgrade --yes --no-install-recommends
DEBIAN_FRONTEND=noninteractive timeout --signal=TERM --kill-after=30s 30m apt-get --no-download install --yes --no-install-recommends "$@"
apt-get clean
rm -rf /var/lib/apt/lists/*
rm -f /etc/resolv.conf
