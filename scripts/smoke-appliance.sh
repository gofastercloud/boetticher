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

fail_check() {
  printf '%s\n' "boetticher smoke failure: $*" >&2
  exit 1
}

require_absent() {
  label=$1
  path=$2
  if [ -e "$path" ]; then
    fail_check "$label: $path"
  fi
}

require_executable() {
  label=$1
  path=$2
  if [ ! -x "$path" ]; then
    fail_check "$label: $path"
  fi
}

require_chroot_executable() {
  label=$1
  path=$2
  if ! chroot "$rootfs" test -x "$path"; then
    fail_check "$label: $path"
  fi
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
require_absent 'artifact contains labadmin authorized key' "$rootfs/home/labadmin/.ssh/authorized_keys"
require_absent 'artifact contains root authorized key' "$rootfs/root/.ssh/authorized_keys"
printf '%s\n' 'boetticher smoke check: SSH host identity absence'
host_key=$(find "$rootfs/etc/ssh" -maxdepth 1 -name 'ssh_host_*' -print -quit)
if [ -n "$host_key" ]; then
  fail_check "artifact contains baked SSH host identity: $host_key"
fi
printf '%s\n' 'boetticher smoke check: durable labadmin privilege absence'
if [ ! -f "$rootfs/etc/sudoers.d/boetticher" ]; then
  fail_check "base sudoers policy is missing: $rootfs/etc/sudoers.d/boetticher"
fi
sudo_rule=$(grep -En '^[[:space:]]*labadmin[[:space:]]+ALL=' "$rootfs/etc/sudoers.d/boetticher" || true)
if [ -n "$sudo_rule" ]; then
  fail_check "base appliance contains a durable labadmin sudo rule: $sudo_rule"
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
    test -x "$rootfs/usr/local/bin/step"
    chroot "$rootfs" /usr/local/bin/step version 2>&1 | grep -Fq 'Smallstep CLI/0.30.6'
    test -f "$rootfs/etc/systemd/journald.conf.d/boetticher.conf"
    test -f "$rootfs/etc/systemd/journal-upload.conf"
    run visudo -cf /etc/sudoers
    printf '%s\n' 'boetticher smoke check: base secret and host identity absence'
    test ! -e "$rootfs/home/labadmin/.ssh/authorized_keys"
    test ! -e "$rootfs/root/.ssh/authorized_keys"
    ;;
  boetticher-dns-blocky)
    printf '%s\n' 'boetticher smoke check: Smallstep CA binary'
    test -x "$rootfs/usr/local/bin/step-ca"
    chroot "$rootfs" /usr/local/bin/step-ca version 2>&1 | grep -Fq 'Smallstep CA/0.30.2'
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
  boetticher-bifrost)
    require_executable 'bifrost nginx executable is missing' "$rootfs/usr/sbin/nginx"
    require_executable 'Bifrost executable is missing' "$rootfs/usr/local/libexec/boetticher-bifrost"
    require_executable 'Bifrost-compatible capabilities executable is missing' "$rootfs/usr/local/libexec/boetticher-bifrost-model-capabilities"
    chroot "$rootfs" getent passwd bifrost | grep -Eq '^bifrost:'
    chroot "$rootfs" dpkg-query -W -f='${Version}' nginx | grep -Fxq '1.26.3-3+deb13u7'
    test -f "$rootfs/etc/systemd/system/bifrost.service"
    grep -Fq -- 'ExecStart=/usr/local/libexec/boetticher-bifrost serve --config /etc/boetticher/bifrost/config.json' "$rootfs/etc/systemd/system/bifrost.service"
    grep -Fxq 'User=bifrost' "$rootfs/etc/systemd/system/bifrost.service"
    grep -Fxq 'Group=bifrost' "$rootfs/etc/systemd/system/bifrost.service"
    grep -Fxq 'CapabilityBoundingSet=' "$rootfs/etc/systemd/system/bifrost.service"
    test ! -e "$rootfs/etc/boetticher/bifrost/config.json"
    test ! -e "$rootfs/etc/nginx/sites-enabled/default"
    test ! -e "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
    if find "$rootfs/etc/nginx" -type f \( -name '*.pem' -o -name '*.key' \) -print -quit | grep -q .; then
      echo "bifrost artifact contains generated TLS material" >&2
      exit 1
    fi
    ;;
  boetticher-network-probe)
    for path in /usr/sbin/arping /usr/bin/dig /usr/bin/iperf3 /usr/bin/nc /usr/bin/nmap /usr/bin/tcpdump /usr/bin/curl /usr/bin/openssl /usr/bin/jq; do
      require_chroot_executable "network-probe dependency is missing" "$path"
    done
    require_chroot_executable 'network-probe executable is missing' /usr/local/libexec/boetticher-network-probe
    if [ -e "$rootfs/etc/systemd/system/boetticher-network-probe.service" ]; then
      fail_check "network-probe artifact contains an unexpected systemd service: $rootfs/etc/systemd/system/boetticher-network-probe.service"
    fi
    ;;
  *)
    echo "unknown smoke target: $name" >&2
    exit 2
    ;;
esac
