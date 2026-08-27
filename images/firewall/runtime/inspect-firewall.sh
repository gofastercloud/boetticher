#!/bin/sh
set -eu

operation=${1:-}
case "$operation" in
  status)
    [ "$#" -eq 1 ] || exit 64
    printf 'forwarding=%s\n' "$(/usr/bin/cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || printf unknown)"
    for service in nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq; do
      printf 'service.%s=' "$service"
      /usr/bin/systemctl is-active "$service" 2>/dev/null || true
    done
    for interface in wan0 trusted0 servers0 sandbox0 mgmt0 transit0 infra0; do
      printf 'iface.%s=' "$interface"
      /usr/sbin/ip -br addr show "$interface" 2>/dev/null || printf absent
    done
    ;;
  ruleset)
    [ "$#" -eq 1 ] || exit 64
    exec /usr/sbin/nft --json list ruleset
    ;;
  table)
    [ "$#" -eq 1 ] || exit 64
    exec /usr/sbin/nft list table inet boetticher_filter
    ;;
  leases)
    [ "$#" -eq 1 ] || exit 64
    exec /usr/bin/cat /var/lib/kea/kea-leases4.csv
    ;;
  kernel-logs)
    [ "$#" -eq 3 ] || exit 64
    limit=$2
    case "$limit" in
      ''|*[!0-9]*) exit 64 ;;
    esac
    [ "$limit" -ge 1 ] && [ "$limit" -le 1000 ] || exit 64
    case "$3" in
      all) pattern=boetticher ;;
      HOME|TRUSTED|SERVERS|SANDBOX|MGMT|TRANSIT|INFRA) pattern="boetticher $3" ;;
      *) exit 64 ;;
    esac
    exec /usr/bin/journalctl -k -n "$limit" --no-pager -g "$pattern"
    ;;
  *)
    exit 64
    ;;
esac
