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
    run psql --version
    run nginx -v
    run zabbix_server --version
    run zabbix_agent2 --version
    chroot "$rootfs" /usr/sbin/zabbix_server --version 2>&1 | grep -q '7\.0\.30'
    test -f "$rootfs/usr/share/zabbix-sql-scripts/postgresql/server.sql.gz"
    test -x "$rootfs/usr/lib/boetticher/prepare-zabbix-config"
    test -f "$rootfs/etc/systemd/system/zabbix-server.service.d/boetticher-credentials.conf"
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
    chroot "$rootfs" /opt/litellm/bin/python -c 'import litellm; assert litellm.__version__ == "1.74.9"'
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
  *)
    echo "unknown smoke target: $name" >&2
    exit 2
    ;;
esac
