#!/bin/sh
set -eu

image=${1:?firewall image is required}
for tool in virt-cat virt-ls; do
  command -v "$tool" >/dev/null 2>&1 || { echo "HOLD: $tool is required for firewall image smoke tests" >&2; exit 2; }
done
packages=$(virt-cat -a "$image" /var/lib/dpkg/status)
for package in nftables kea-dhcp4-server kea-dhcp-ddns-server chrony openssh-server cloud-init zabbix-agent2 systemd-journal-remote; do
  printf '%s\n' "$packages" | grep -q "Package: $package" || { echo "firewall image is missing package $package" >&2; exit 1; }
done
printf '%s\n' "$packages" | grep -q '^Package: openssh-server$' || exit 1
printf '%s\n' "$(virt-cat -a "$image" /etc/passwd)" | grep -q '^labadmin:' || { echo "firewall image is missing labadmin" >&2; exit 1; }
virt-ls -a "$image" /etc/sysctl.d | grep -qx 'boetticher-forwarding.conf'
virt-ls -a "$image" /usr/lib/boetticher | grep -qx 'boetticher-first-boot.sh'
if virt-ls -a "$image" /home/labadmin/.ssh/authorized_keys >/dev/null 2>&1; then
  echo "firewall image contains an embedded operator key" >&2
  exit 1
fi
