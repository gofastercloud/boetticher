#!/bin/sh
set -eu

image=${1:?firewall image is required}
for tool in virt-cat virt-ls; do
  command -v "$tool" >/dev/null 2>&1 || { echo "HOLD: $tool is required for firewall image smoke tests" >&2; exit 2; }
done
packages=$(virt-cat -a "$image" /var/lib/dpkg/status)
for package in nftables kea-dhcp4-server kea-dhcp-ddns-server chrony openssh-server cloud-init systemd-journal-remote; do
  printf '%s\n' "$packages" | grep -q "Package: $package" || { echo "firewall image is missing package $package" >&2; exit 1; }
done
printf '%s\n' "$packages" | grep -q '^Package: openssh-server$' || exit 1
printf '%s\n' "$(virt-cat -a "$image" /etc/passwd)" | grep -q '^labadmin:' || { echo "firewall image is missing labadmin" >&2; exit 1; }
virt-cat -a "$image" /usr/lib/boetticher/artifact.json | grep -Eq '"definition_sha256"[[:space:]]*:[[:space:]]*"[a-fA-F0-9]{64}"' || { echo "firewall image is missing definition identity" >&2; exit 1; }
if virt-cat -a "$image" /usr/lib/boetticher/artifact.json | grep -q 'content_sha256'; then
  echo "firewall artifact definition identity must not embed content checksum" >&2
  exit 1
fi
virt-ls -a "$image" /etc/sysctl.d | grep -qx 'boetticher-forwarding.conf'
for setting in 'net.ipv4.ip_forward=0' 'net.ipv6.conf.all.forwarding=0'; do
  virt-cat -a "$image" /etc/sysctl.d/boetticher-forwarding.conf | grep -Fxq "$setting" || { echo "firewall image is missing fail-closed forwarding setting: $setting" >&2; exit 1; }
done
virt-ls -a "$image" /usr/lib/boetticher | grep -qx 'boetticher-first-boot.sh'
virt-cat -a "$image" /etc/ssh/sshd_config.d/boetticher-host-key.conf | grep -qx 'HostKey /var/lib/boetticher/identity/ssh/ssh_host_ed25519_key'
virt-ls -a "$image" /usr/lib/boetticher | grep -qx 'inspect-firewall'
virt-cat -a "$image" /etc/sudoers.d/boetticher-firewall | grep -Fq '/usr/lib/boetticher/inspect-firewall status'
virt-cat -a "$image" /etc/sudoers.d/boetticher-firewall | grep -Fq '/usr/lib/boetticher/inspect-firewall kernel-logs *'
for setting in 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin prohibit-password'; do
  virt-cat -a "$image" /etc/ssh/sshd_config.d/boetticher.conf | grep -Fxq "$setting" || { echo "firewall image is missing SSH hardening setting: $setting" >&2; exit 1; }
done
if printf '%s\n' "$packages" | grep -Eq '^Package: (postgresql|zabbix|zabbix-agent)'; then
  echo "firewall image contains an obsolete monitoring package" >&2
  exit 1
fi
if virt-ls -a "$image" /home/labadmin/.ssh/authorized_keys >/dev/null 2>&1; then
  echo "firewall image contains an embedded operator key" >&2
  exit 1
fi
if virt-ls -a "$image" /etc/ssh | grep -q '^ssh_host_'; then
  echo "firewall image contains baked SSH host keys" >&2
  exit 1
fi
