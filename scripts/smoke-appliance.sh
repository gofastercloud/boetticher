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

case "$name" in
  boetticher-base)
    printf '%s\n' 'boetticher smoke check: base user and files'
    run id labadmin
    test -x "$rootfs/usr/sbin/sshd"
    run systemd-journal-upload --version
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
    chroot "$rootfs" /usr/local/bin/blocky --version 2>&1 | grep -Fq '0.34.0'
    run pdns_server --version
    run chronyd --version
    test -x "$rootfs/usr/local/bin/blocky"
    test -f "$rootfs/etc/boetticher/dns/filtering/boetticher.hosts"
    test -f "$rootfs/etc/systemd/system/blocky.service"
    test ! -e "$rootfs/opt/AdGuardHome/AdGuardHome"
    ;;
  boetticher-logging)
    run systemd-journal-remote --version
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
  *)
    echo "unknown smoke target: $name" >&2
    exit 2
    ;;
esac
