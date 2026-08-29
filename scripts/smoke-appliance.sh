#!/bin/sh
set -eu

name=${1:?artifact name is required}
rootfs=${2:?rootfs path is required}
run() {
  printf '%s\n' "boetticher smoke check: $*"
  chroot "$rootfs" "$@" >/dev/null 2>&1
}

printf '%s\n' 'boetticher smoke check: module descriptor absence'
test ! -e "$rootfs/etc/boetticher/module.yaml"
printf '%s\n' 'boetticher smoke check: artifact identity presence'
test -s "$rootfs/usr/lib/boetticher/artifact.json"
printf '%s\n' 'boetticher smoke check: artifact definition checksum'
grep -Eq '"definition_sha256"[[:space:]]*:[[:space:]]*"[a-fA-F0-9]{64}"' "$rootfs/usr/lib/boetticher/artifact.json"
if grep -q 'content_sha256' "$rootfs/usr/lib/boetticher/artifact.json"; then
  echo "artifact definition identity must not embed the built content checksum" >&2
  exit 1
fi
printf '%s\n' 'boetticher smoke check: authorized key absence'
test ! -e "$rootfs/home/labadmin/.ssh/authorized_keys"
test ! -e "$rootfs/root/.ssh/authorized_keys"
printf '%s\n' 'boetticher smoke check: SSH host identity absence'
if find "$rootfs/etc/ssh" -maxdepth 1 -name 'ssh_host_*' -print -quit | grep -q .; then
  echo "artifact contains baked SSH host identity" >&2
  exit 1
fi
printf '%s\n' 'boetticher smoke check: durable labadmin privilege absence'
if grep -Eq '^[[:space:]]*labadmin[[:space:]]+ALL=' "$rootfs/etc/sudoers.d/boetticher"; then
  echo "base appliance contains a durable labadmin sudo rule" >&2
  exit 1
fi

case "$name" in
  boetticher-base)
    printf '%s\n' 'boetticher smoke check: base user and files'
    run id labadmin
    test -x "$rootfs/usr/sbin/sshd"
    run /usr/lib/systemd/systemd-journal-upload --version
    run journalctl --version
    test -d "$rootfs/etc/boetticher" -a -d "$rootfs/usr/lib/boetticher"
    test -x "$rootfs/usr/lib/boetticher/install-runtime-state"
    test -f "$rootfs/etc/systemd/journald.conf.d/boetticher.conf"
    test -f "$rootfs/etc/systemd/journal-upload.conf"
    run visudo -cf /etc/sudoers
    printf '%s\n' 'boetticher smoke check: base secret and host identity absence'
    test ! -e "$rootfs/home/labadmin/.ssh/authorized_keys"
    test ! -e "$rootfs/root/.ssh/authorized_keys"
    ;;
  boetticher-dns-blocky)
    printf '%s\n' 'boetticher smoke check: blocky version'
    chroot "$rootfs" /usr/local/bin/blocky version 2>&1 | grep -Fq '0.34.0'
    printf '%s\n' 'boetticher smoke check: PowerDNS and Chrony binaries'
    run pdns_server --version
    run chronyd --version
    printf '%s\n' 'boetticher smoke check: Blocky files and provider separation'
    test -x "$rootfs/usr/local/bin/blocky"
    test -f "$rootfs/etc/boetticher/dns/filtering/boetticher.hosts"
    test -f "$rootfs/etc/systemd/system/blocky.service"
    test ! -e "$rootfs/opt/AdGuardHome/AdGuardHome"
    ;;
  boetticher-logging)
    run /usr/lib/systemd/systemd-journal-remote --version
    run journalctl --version
    ;;
  boetticher-monitoring)
    run nginx -v
    test -x "$rootfs/opt/pulse/bin/pulse"
    test -f "$rootfs/opt/pulse/VERSION"
    grep -Fxq '6.1.2' "$rootfs/opt/pulse/VERSION"
    test -x "$rootfs/usr/lib/boetticher/run-pulse"
    test -f "$rootfs/etc/systemd/system/pulse.service"
    grep -Fxq 'Environment=BIND_ADDRESS=127.0.0.1' "$rootfs/etc/systemd/system/pulse.service"
    test -d "$rootfs/var/lib/pulse"
    test ! -e "$rootfs/etc/systemd/system/pulse-update.service"
    test ! -e "$rootfs/etc/systemd/system/pulse-update.timer"
    if find "$rootfs" -type f \( -name 'pulse-agent' -o -name 'pulse-agent-*' \) -print -quit | grep -q .; then
      echo "monitoring artifact contains a Pulse agent" >&2
      exit 1
    fi
    if chroot "$rootfs" dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Eq '^(postgresql|zabbix|zabbix-agent)'; then
      echo "monitoring artifact contains an obsolete database or monitoring agent" >&2
      exit 1
    fi
    if grep -R -n -E 'pulse_admin_password|pulse_proxmox_token|pulse_api_token|synthetic-secret' "$rootfs/opt/pulse" "$rootfs/usr/lib/boetticher" 2>/dev/null; then
      echo "monitoring artifact contains a monitoring credential" >&2
      exit 1
    fi
    ;;
  boetticher-portal)
    run nginx -v
    ;;
  boetticher-tailnet-router)
    run tailscale version
    run tailscaled --version
    chroot "$rootfs" tailscale version 2>&1 | grep -Fq '1.76.6'
    test -x "$rootfs/usr/sbin/tailscaled"
    test ! -e "$rootfs/etc/tailscale/auth.key"
    if grep -R -n -E 'advertise-exit-node|auth-key|auth_key' "$rootfs/etc" "$rootfs/usr/lib" 2>/dev/null; then
      echo "tailnet-router artifact contains forbidden exit-node or auth-key configuration" >&2
      exit 1
    fi
    ;;
  boetticher-litellm)
    run nginx -v
    run /opt/litellm/bin/python --version
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3 | grep -Fxq '3.13.5-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3-venv | grep -Fxq '3.13.5-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3-pip | grep -Fxq '25.1.1+dfsg-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' nginx | grep -Fxq '1.26.3-3+deb13u7'
    chroot "$rootfs" /opt/litellm/bin/python -c 'from importlib.metadata import version; assert version("litellm") == "1.74.9"'
    test -f "$rootfs/etc/systemd/system/litellm.service"
    grep -Fq -- '--host 127.0.0.1' "$rootfs/etc/systemd/system/litellm.service"
    test ! -e "$rootfs/etc/boetticher/litellm/config.yaml"
    test ! -e "$rootfs/etc/nginx/sites-enabled/default"
    test ! -e "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
    if find "$rootfs/etc/nginx" -type f \( -name '*.pem' -o -name '*.key' \) -print -quit | grep -q .; then
      echo "litellm artifact contains generated TLS material" >&2
      exit 1
    fi
    ;;
  boetticher-printer)
    run nginx -v
    run /opt/octoprint/bin/python --version
    chroot "$rootfs" /opt/octoprint/bin/octoprint --version | grep -Fq '1.11.8'
    chroot "$rootfs" getent passwd octoprint | grep -Fq ':2200:2200:'
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3 | grep -Fxq '3.13.5-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' nginx | grep -Fxq '1.26.3-3+deb13u7'
    test -f "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq -- '--host=127.0.0.1' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'DevicePolicy=closed' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'DeviceAllow=char-ttyUSB rw' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'ProtectSystem=strict' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'MemoryDenyWriteExecute=yes' "$rootfs/etc/systemd/system/octoprint.service"
    test ! -e "$rootfs/var/lib/octoprint/config.yaml"
    test ! -e "$rootfs/etc/nginx/sites-enabled/default"
    if find "$rootfs/etc/nginx" -type f \( -name '*.pem' -o -name '*.key' \) -print -quit | grep -q .; then
      echo "printer artifact contains generated TLS material" >&2
      exit 1
    fi
    ;;
  boetticher-gatus)
    run /usr/local/bin/gatus version
    test -x "$rootfs/usr/local/bin/gatus"
    test -f "$rootfs/etc/systemd/system/gatus.service"
    grep -Fq -- 'User=gatus' "$rootfs/etc/systemd/system/gatus.service"
    test ! -e "$rootfs/etc/boetticher/gatus/config.yaml"
    ;;
  *)
    echo "unknown smoke target: $name" >&2
    exit 2
    ;;
esac
