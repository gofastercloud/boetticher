#!/bin/sh
set -eu

rootfs=${1:?firewall LXC rootfs is required}
./scripts/smoke-appliance.sh boetticher-firewall-lxc "$rootfs"

for package in nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq chrony openssh-server systemd-journal-remote; do
  chroot "$rootfs" dpkg-query -W -f='${binary:Package}\n' "$package" >/dev/null
done
for helper in boetticher-firewall-telemetry snapshot-firewall inspect-firewall; do
  test -x "$rootfs/usr/lib/boetticher/$helper"
done
for unit in boetticher-firewall-snapshot.service boetticher-firewall-snapshot.timer boetticher-firewall-telemetry.service; do
  test -f "$rootfs/etc/systemd/system/$unit"
done
test ! -e "$rootfs/usr/bin/qemu-ga"
test ! -e "$rootfs/etc/pve"
grep -Fq '"kind":"lxc"' "$rootfs/usr/lib/boetticher/artifact.json"
grep -Fq 'net.ipv4.ip_forward=0' "$rootfs/etc/sysctl.d/boetticher-forwarding.conf"
grep -Fq 'net.ipv6.conf.all.forwarding=0' "$rootfs/etc/sysctl.d/boetticher-forwarding.conf"
grep -Fq 'CapabilityBoundingSet=' "$rootfs/etc/systemd/system/boetticher-firewall-telemetry.service"
