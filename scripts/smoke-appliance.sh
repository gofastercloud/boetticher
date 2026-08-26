#!/bin/sh
set -eu

name=${1:?artifact name is required}
rootfs=${2:?rootfs path is required}
run() {
  chroot "$rootfs" "$@" >/dev/null 2>&1
}

test ! -e "$rootfs/etc/boetticher/module.yaml"
test ! -e "$rootfs/usr/lib/boetticher/artifact.json"
test ! -e "$rootfs/home/labadmin/.ssh/authorized_keys"
test ! -e "$rootfs/root/.ssh/authorized_keys"

case "$name" in
  boetticher-base)
    run id labadmin
    test -x "$rootfs/usr/sbin/sshd"
    run systemd-journal-upload --version
    run journalctl --version
    test -d "$rootfs/etc/boetticher" -a -d "$rootfs/usr/lib/boetticher"
    test -x "$rootfs/usr/lib/boetticher/install-runtime-state"
    test -f "$rootfs/etc/systemd/journald.conf.d/boetticher.conf"
    test -f "$rootfs/etc/systemd/journal-upload.conf"
    run visudo -cf /etc/sudoers
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
