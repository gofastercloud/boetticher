#!/bin/sh
set -eu

finish() {
  status=$?
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "Smoke: PASS"
  else
    printf '%s\n' "Smoke: FAIL (exit $status)" >&2
  fi
  exit "$status"
}
trap finish EXIT

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
    test -x "$rootfs/usr/lib/systemd/systemd-journal-upload"
    test -x "$rootfs/usr/bin/journalctl"
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
    test -x "$rootfs/usr/sbin/pdns_server"
    test -x "$rootfs/usr/sbin/chronyd"
    printf '%s\n' 'boetticher smoke check: Blocky files and authoritative separation'
    test -x "$rootfs/usr/local/bin/blocky"
    test -f "$rootfs/etc/boetticher/dns/filtering/boetticher.hosts"
    test -f "$rootfs/etc/systemd/system/blocky.service"
    grep -Fxq 'User=blocky' "$rootfs/etc/systemd/system/blocky.service"
    grep -Fxq 'Group=blocky' "$rootfs/etc/systemd/system/blocky.service"
    grep -Fxq 'ExecStart=/usr/local/bin/blocky --config /etc/blocky/config.yml' "$rootfs/etc/systemd/system/blocky.service"
    test -d "$rootfs/var/lib/blocky"
    ;;
  boetticher-logging)
    test -x "$rootfs/usr/lib/systemd/systemd-journal-remote"
    test -x "$rootfs/usr/bin/journalctl"
    test -x "$rootfs/usr/local/libexec/boetticher-log-query"
    grep -Fxq 'ExecStart=/usr/local/libexec/boetticher-log-query' "$rootfs/etc/systemd/system/boetticher-log-query.service"
    ;;
  boetticher-monitoring)
    test -x "$rootfs/usr/sbin/nginx"
    test -x "$rootfs/opt/pulse/bin/pulse"
    test -f "$rootfs/opt/pulse/VERSION"
    grep -Fxq '6.1.2' "$rootfs/opt/pulse/VERSION"
    test -x "$rootfs/usr/lib/boetticher/run-pulse"
    test -f "$rootfs/etc/systemd/system/pulse.service"
    grep -Fxq 'User=pulse' "$rootfs/etc/systemd/system/pulse.service"
    grep -Fxq 'Group=pulse' "$rootfs/etc/systemd/system/pulse.service"
    grep -Fxq 'ExecStart=/usr/lib/boetticher/run-pulse' "$rootfs/etc/systemd/system/pulse.service"
    grep -Fxq 'Environment=BIND_ADDRESS=127.0.0.1' "$rootfs/etc/systemd/system/pulse.service"
    test -d "$rootfs/var/lib/pulse"
    chroot "$rootfs" runuser -u pulse -- test -x /usr/lib/boetticher/run-pulse
    chroot "$rootfs" runuser -u pulse -- test -x /opt/pulse/bin/pulse
    chroot "$rootfs" runuser -u pulse -- test -r /opt/pulse/VERSION
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
    test -x "$rootfs/usr/sbin/nginx"
    ;;
  boetticher-tailnet-router)
    test -x "$rootfs/usr/bin/tailscale"
    test -x "$rootfs/usr/sbin/tailscaled"
    chroot "$rootfs" tailscale version 2>&1 | grep -Fq '1.76.6'
    test -x "$rootfs/usr/sbin/tailscaled"
    test ! -e "$rootfs/etc/tailscale/auth.key"
    if grep -R -n -E 'advertise-exit-node|auth-key|auth_key' "$rootfs/etc" "$rootfs/usr/lib" 2>/dev/null; then
      echo "tailnet-router artifact contains forbidden exit-node or auth-key configuration" >&2
      exit 1
    fi
    ;;
  boetticher-litellm)
    test -x "$rootfs/usr/sbin/nginx"
    test -x "$rootfs/opt/litellm/bin/python"
    test -x "$rootfs/opt/litellm/bin/litellm"
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3 | grep -Fxq '3.13.5-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3-venv | grep -Fxq '3.13.5-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3-pip | grep -Fxq '25.1.1+dfsg-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' nginx | grep -Fxq '1.26.3-3+deb13u7'
    chroot "$rootfs" /opt/litellm/bin/python -c 'from importlib.metadata import version; assert version("litellm") == "1.74.9"'
    test -f "$rootfs/etc/systemd/system/litellm.service"
    test -x "$rootfs/usr/lib/boetticher/litellm-start"
    grep -Fq -- '--host 127.0.0.1' "$rootfs/etc/systemd/system/litellm.service"
    grep -Fq -- 'User=root' "$rootfs/etc/systemd/system/litellm.service"
    grep -Fxq 'Group=root' "$rootfs/etc/systemd/system/litellm.service"
    grep -Fxq 'ExecStart=/usr/lib/boetticher/litellm-start --config /etc/boetticher/litellm/config.yaml --host 127.0.0.1 --port 4000' "$rootfs/etc/systemd/system/litellm.service"
    grep -Fq -- 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID' "$rootfs/etc/systemd/system/litellm.service"
    test -x "$rootfs/usr/bin/setpriv"
    test ! -e "$rootfs/etc/boetticher/litellm/config.yaml"
    test ! -e "$rootfs/etc/nginx/sites-enabled/default"
    test ! -e "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
    chroot "$rootfs" runuser -u litellm -- test -x /opt/litellm/bin/litellm
    if find "$rootfs/etc/nginx" -type f \( -name '*.pem' -o -name '*.key' \) -print -quit | grep -q .; then
      echo "litellm artifact contains generated TLS material" >&2
      exit 1
    fi
    ;;
  boetticher-printer)
    test -x "$rootfs/usr/sbin/nginx"
    test -x "$rootfs/opt/octoprint/bin/python"
    test -x "$rootfs/opt/octoprint/bin/octoprint"
    chroot "$rootfs" getent passwd octoprint | grep -Fq ':2200:2200:'
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3 | grep -Fxq '3.13.5-1'
    chroot "$rootfs" dpkg-query -W -f='${Version}' nginx | grep -Fxq '1.26.3-3+deb13u7'
    test -f "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fxq 'User=octoprint' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fxq 'Group=octoprint' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fxq 'ExecStart=/opt/octoprint/bin/octoprint serve --host=127.0.0.1 --port=5000 --basedir=/var/lib/octoprint' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq -- '--host=127.0.0.1' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'DevicePolicy=closed' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'DeviceAllow=char-ttyUSB rw' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'ProtectSystem=strict' "$rootfs/etc/systemd/system/octoprint.service"
    grep -Fq 'MemoryDenyWriteExecute=yes' "$rootfs/etc/systemd/system/octoprint.service"
    chroot "$rootfs" runuser -u octoprint -- test -x /opt/octoprint/bin/octoprint
    chroot "$rootfs" runuser -u octoprint -- test -d /var/lib/octoprint
    test ! -e "$rootfs/var/lib/octoprint/config.yaml"
    test ! -e "$rootfs/etc/nginx/sites-enabled/default"
    if find "$rootfs/etc/nginx" -type f \( -name '*.pem' -o -name '*.key' \) -print -quit | grep -q .; then
      echo "printer artifact contains generated TLS material" >&2
      exit 1
    fi
    ;;
  boetticher-streamdeck)
    test -x "$rootfs/opt/streamdeck/bin/boetticher-streamdeck"
    run /opt/streamdeck/bin/python --version
    chroot "$rootfs" getent passwd streamdeck | grep -Fq ':2200:2200:'
    chroot "$rootfs" dpkg-query -W -f='${Version}' python3 | grep -Fxq '3.13.5-1'
    test -f "$rootfs/etc/systemd/system/streamdeck-status.service"
    grep -Fq 'User=streamdeck' "$rootfs/etc/systemd/system/streamdeck-status.service"
    grep -Fq 'DevicePolicy=closed' "$rootfs/etc/systemd/system/streamdeck-status.service"
    grep -Fq 'DeviceAllow=char-usb_device rw' "$rootfs/etc/systemd/system/streamdeck-status.service"
    grep -Fq 'ProtectSystem=strict' "$rootfs/etc/systemd/system/streamdeck-status.service"
    grep -Fq 'MemoryDenyWriteExecute=yes' "$rootfs/etc/systemd/system/streamdeck-status.service"
    ;;
  boetticher-aiops)
    test -x "$rootfs/usr/local/libexec/boetticher-aiops"
    test -f "$rootfs/etc/systemd/system/boetticher-aiops.service"
    test -f "$rootfs/etc/systemd/system/boetticher-aiops.socket"
    test -f "$rootfs/etc/systemd/system/holmes.service"
    test -f "$rootfs/etc/boetticher-aiops/config.yaml"
    grep -Fq 'HOLMES_HOST=127.0.0.1' "$rootfs/etc/systemd/system/holmes.service"
    grep -Fq 'IPAddressDeny=any' "$rootfs/etc/systemd/system/boetticher-aiops.service"
    grep -Fq 'IPAddressAllow=localhost' "$rootfs/etc/systemd/system/boetticher-aiops.service"
    grep -Fq 'NoNewPrivileges=true' "$rootfs/etc/systemd/system/boetticher-aiops.service"
    grep -Fq 'ProtectSystem=strict' "$rootfs/etc/systemd/system/boetticher-aiops.service"
    grep -Fxq 'User=boetticher-aiops' "$rootfs/etc/systemd/system/boetticher-aiops.service"
    grep -Fxq 'ExecStart=/usr/local/libexec/boetticher-aiops' "$rootfs/etc/systemd/system/boetticher-aiops.service"
    grep -Fxq 'User=holmes' "$rootfs/etc/systemd/system/holmes.service"
    grep -Fxq 'ExecStart=/opt/holmes/bin/python -u /opt/holmes/server.py' "$rootfs/etc/systemd/system/holmes.service"
    chroot "$rootfs" runuser -u boetticher-aiops -- test -x /usr/local/libexec/boetticher-aiops
    chroot "$rootfs" runuser -u holmes -- test -r /opt/holmes/server.py
    test ! -e "$rootfs/etc/boetticher-aiops/runtime.env"
    ;;
  boetticher-gatus)
    printf '%s\n' 'boetticher smoke check: Gatus executable'
    test -x "$rootfs/usr/local/bin/gatus"
    test -f "$rootfs/etc/systemd/system/gatus.service"
    grep -Fq -- 'User=gatus' "$rootfs/etc/systemd/system/gatus.service"
    grep -Fxq 'Group=gatus' "$rootfs/etc/systemd/system/gatus.service"
    grep -Fxq 'ExecStart=/usr/local/bin/gatus --config-path /etc/boetticher/gatus/config.yaml' "$rootfs/etc/systemd/system/gatus.service"
    chroot "$rootfs" runuser -u gatus -- test -x /usr/local/bin/gatus
    test ! -e "$rootfs/etc/boetticher/gatus/config.yaml"
    ;;
  boetticher-network-probe)
    for path in /usr/sbin/arping /usr/bin/dig /usr/bin/iperf3 /usr/bin/nc /usr/bin/nmap /usr/bin/tcpdump /usr/bin/curl /usr/bin/openssl /usr/bin/jq; do
      test -x "$rootfs$path"
    done
    test -x "$rootfs/usr/local/libexec/boetticher-network-probe"
    test ! -e "$rootfs/etc/systemd/system/boetticher-network-probe.service"
    ;;
  *)
    echo "unknown smoke target: $name" >&2
    exit 2
    ;;
esac
