package host

import "strings"

const (
	bridgeIPv6TestGuestA = 991
	bridgeIPv6TestGuestB = 992
	bridgeIPv6TestVLAN   = 40
	bridgeIPv6TestImage  = "boetticher-network-probe-1.0.0-amd64.tar.zst"
)

// BridgeIPv6TestCommand is a bounded native Proxmox regression journey. The
// EXIT trap stops, destroys, and verifies both temporary guests; cleanup
// failures remain a failed result.
func BridgeIPv6TestCommand() (string, error) {
	return strings.TrimSpace(`set -eu
ids="991 992"
cleanup_rc=0
cleanup() {
  test_rc=$?
  trap - EXIT HUP INT TERM
  set +e
  for id in $ids; do
    if pct status "$id" >/dev/null 2>&1; then
      pct shutdown "$id" --timeout 30 >/dev/null 2>&1 || pct stop "$id" --timeout 30 >/dev/null 2>&1 || cleanup_rc=99
      pct destroy "$id" --purge >/dev/null 2>&1 || cleanup_rc=99
    fi
  done
  for id in $ids; do
    if pct status "$id" >/dev/null 2>&1; then cleanup_rc=99; fi
  done
  if pvesm list boetticher-data 2>/dev/null | grep -Eq 'vm-(991|992)-disk-0'; then cleanup_rc=99; fi
  if [ "$test_rc" -eq 0 ] && [ "$cleanup_rc" -ne 0 ]; then test_rc="$cleanup_rc"; fi
  exit "$test_rc"
}
trap cleanup EXIT HUP INT TERM
for id in $ids; do
  if pct status "$id" >/dev/null 2>&1; then echo "reserved temporary VMID $id is already in use" >&2; exit 80; fi
done
test "$(sysctl -n net.ipv6.conf.vmbr1.disable_ipv6)" = 1
test -z "$(ip -6 -o addr show dev vmbr1)"
test -f /var/lib/vz/template/cache/boetticher-network-probe-1.0.0-amd64.tar.zst
pct create 991 local:vztmpl/boetticher-network-probe-1.0.0-amd64.tar.zst --hostname boetticher-ipv6-test-a --cores 1 --memory 128 --swap 0 --rootfs boetticher-data:1 --net0 name=eth0,bridge=vmbr1,tag=40,firewall=0,ip=manual,ip6=manual --unprivileged 1 --onboot 0 --start 0 --description "temporary Boetticher vmbr1 IPv6 bridge test"
pct create 992 local:vztmpl/boetticher-network-probe-1.0.0-amd64.tar.zst --hostname boetticher-ipv6-test-b --cores 1 --memory 128 --swap 0 --rootfs boetticher-data:1 --net0 name=eth0,bridge=vmbr1,tag=40,firewall=0,ip=manual,ip6=manual --unprivileged 1 --onboot 0 --start 0 --description "temporary Boetticher vmbr1 IPv6 bridge test"
pct start 991
pct start 992
sleep 2
a=$(pct exec 991 -- sh -c "ip -6 -o addr show dev eth0 scope link | awk '{print \$4}' | cut -d/ -f1 | head -n1")
b=$(pct exec 992 -- sh -c "ip -6 -o addr show dev eth0 scope link | awk '{print \$4}' | cut -d/ -f1 | head -n1")
test -n "$a"
test -n "$b"
pct exec 991 -- ping -6 -c 3 -W 2 "$b"
pct exec 992 -- ping -6 -c 3 -W 2 "$a"
test "$(sysctl -n net.ipv6.conf.vmbr1.disable_ipv6)" = 1
test -z "$(ip -6 -o addr show dev vmbr1)"
test -z "$(bridge link | awk '$NF == "vmbr1" { print; exit }')"
echo "IPv6 link-local forwarding: PASS"`), nil
}
