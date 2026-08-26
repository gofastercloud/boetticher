#!/bin/sh
set -eu

name=${1:?artifact name is required}
rootfs=${2:?rootfs path is required}
run() {
  chroot "$rootfs" "$@" >/dev/null 2>&1
}

case "$name" in
  boetticher-base)
    run id labadmin
    test -x "$rootfs/usr/sbin/sshd"
    test -d "$rootfs/etc/boetticher" -a -d "$rootfs/usr/lib/boetticher"
    test ! -e "$rootfs/root/.ssh/authorized_keys"
    ;;
  boetticher-dns-blocky)
    run blocky --version
    run pdns_server --version
    run chronyd --version
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
    ;;
  boetticher-portal)
    run nginx -v
    ;;
  *)
    echo "unknown smoke target: $name" >&2
    exit 2
    ;;
esac
