package arrstack

import (
	"fmt"
	"strconv"
)

const (
	DockerBridge       = "btcr-arrstack0"
	DockerBridgeSubnet = "172.30.20.0/24"
)

// GuestPolicyScript installs the guest-owned Docker boundary. OpenWrt DNAT
// keeps a public peer's source address, so the router is a layer-2 provenance
// check, never an assumed replacement peer address.
func GuestPolicyScript(peerPort int, monitoring ...bool) (string, error) {
	if peerPort < 1 || peerPort > 65535 {
		return "", fmt.Errorf("arrstack peer port must be 1..65535")
	}
	port := strconv.Itoa(peerPort)
	monitorRules := ""
	monitorInput := ""
	monitorIPTables := ""
	if len(monitoring) > 0 && monitoring[0] {
		monitorInput = `    iifname "$uplink" ether saddr "$gateway_mac" ip saddr 10.10.10.20 tcp dport { 9100, 9110 } accept
`
		monitorRules = `    iifname "$uplink" oifname "$bridge" ether saddr "$gateway_mac" ip saddr 10.10.10.20 tcp dport 9110 accept
`
		monitorIPTables = `iptables -w -A DOCKER-USER -i "$uplink" -o "$bridge" -m mac --mac-source "$gateway_mac" -s 10.10.10.20 -p tcp --dport 9110 -j ACCEPT
`
	}
	return fmt.Sprintf(`#!/bin/sh
set -eu
bridge=%s
subnet=%s
gateway=%s
guest=%s
guest_mac=%s
private4='{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }'

# Require exactly the reviewed SERVERS NIC and its directly-connected router.
set -- $(ip -o -4 addr show | awk -v want="$guest/24" '$4 == want { n++; dev=$2 } END { if (n == 1) print dev; else exit 1 }')
test "$#" = 1
uplink=$1
test "$(ip -o link show dev "$uplink" | awk '{ for (i = 1; i <= NF; i++) if ($i == "link/ether") { print $(i + 1); exit } }')" = "$guest_mac"
ip route get "$gateway" from "$guest" | awk -v gateway="$gateway" -v guest="$guest" -v uplink="$uplink" '
  $1 == gateway && $2 == "from" && $3 == guest {
    for (i = 4; i < NF; i++) if ($i == "dev" && $(i + 1) == uplink) exit 0
  }
  { exit 1 }
'
gateway_mac=$(ip neigh show to "$gateway" dev "$uplink" | awk '/lladdr/ && $0 !~ /FAILED/ { for (i = 1; i <= NF; i++) if ($i == "lladdr") { print $(i + 1); exit } }')
printf '%%s\n' "$gateway_mac" | grep -Eq '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$' || { echo "arrstack router neighbour is unavailable" >&2; exit 1; }
sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1

# The nft batch replaces every owned hook and default-deny rule together,
# before Docker starts. destroy is idempotent when the table is absent.
nft -f - <<EOF
destroy table inet boetticher_arrstack
table inet boetticher_arrstack {
  chain input {
    type filter hook input priority filter; policy drop;
    meta nfproto ipv6 drop
    iifname "lo" accept
    ct state established,related accept
    iifname "$uplink" ether saddr "$gateway_mac" ip saddr { 10.10.30.0/24, 10.10.5.10 } tcp dport 443 accept
%s
  }
	  chain forward {
    type filter hook forward priority filter - 1; policy drop;
    meta nfproto ipv6 drop
    ct state established,related accept
    iifname "$bridge" oifname "$bridge" accept
    iifname "$bridge" oifname "$uplink" ip daddr "$gateway" tcp dport 53 accept
    iifname "$bridge" oifname "$uplink" ip daddr "$gateway" udp dport { 53, 123 } accept
    iifname "$bridge" oifname "$uplink" ip daddr "$gateway" drop
    iifname "$bridge" oifname "$uplink" ip daddr $private4 drop
    iifname "$bridge" oifname "$uplink" accept
    iifname "$uplink" oifname "$bridge" ether saddr "$gateway_mac" ip saddr { 10.10.30.0/24, 10.10.5.10 } tcp dport 443 accept
%s
    iifname "$uplink" oifname "$bridge" ether saddr "$gateway_mac" ip saddr $private4 drop
    iifname "$uplink" oifname "$bridge" ether saddr "$gateway_mac" tcp dport %s accept
    iifname "$uplink" oifname "$bridge" ether saddr "$gateway_mac" udp dport %s accept
  }
  chain postrouting {
    type nat hook postrouting priority srcnat - 1; policy accept;
    iifname "$bridge" oifname "$uplink" ip saddr %s snat to %s
  }
  chain postrouting_guard {
    type filter hook postrouting priority srcnat + 1; policy accept;
    meta nfproto ipv6 drop
    oifname "$uplink" ip saddr != %s drop
  }
}
EOF

# Docker evaluates DOCKER-USER before its generated forwarding rules. nftables
# remains the egress classifier; this chain retains the boundary across Docker
# rule regeneration.
iptables -w -N DOCKER-USER 2>/dev/null || true
iptables -w -F DOCKER-USER
iptables -w -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A DOCKER-USER -i "$bridge" -o "$bridge" -j ACCEPT
iptables -w -A DOCKER-USER -i "$bridge" -o "$uplink" -j ACCEPT
iptables -w -A DOCKER-USER -i "$uplink" -o "$bridge" -m mac --mac-source "$gateway_mac" -s 10.10.30.0/24 -p tcp --dport 443 -j ACCEPT
iptables -w -A DOCKER-USER -i "$uplink" -o "$bridge" -m mac --mac-source "$gateway_mac" -s 10.10.5.10 -p tcp --dport 443 -j ACCEPT
%s
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  iptables -w -A DOCKER-USER -i "$uplink" -o "$bridge" -s "$net" -j DROP
done
iptables -w -A DOCKER-USER -i "$uplink" -o "$bridge" -m mac --mac-source "$gateway_mac" -p tcp --dport %s -j ACCEPT
iptables -w -A DOCKER-USER -i "$uplink" -o "$bridge" -m mac --mac-source "$gateway_mac" -p udp --dport %s -j ACCEPT
iptables -w -A DOCKER-USER -j DROP
`, DockerBridge, DockerBridgeSubnet, GuestGateway, GuestAddress, GuestMAC, monitorInput, monitorRules, port, port, DockerBridgeSubnet, GuestAddress, GuestAddress, monitorIPTables, port, port), nil
}
