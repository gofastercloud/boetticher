package tailnet

import (
	"fmt"
	"github.com/gofastercloud/boetticher/internal/model"
	"strings"
)

// NonPublicIPv4 excludes LAB, HOME, loopback, link-local, multicast and
// documentation/benchmark ranges from the router's own public transport.
const NonPublicIPv4 = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4"

func Destinations() []string {
	result := []string{"10.10.30.0/24"}
	for _, d := range model.TrustedRoutedDestinations() {
		result = append(result, d.Subnet)
	}
	return result
}

func GuestPolicy() string {
	return fmt.Sprintf(`table inet boetticher_tailnet
flush table inet boetticher_tailnet
table inet boetticher_tailnet {
 chain forward {
  type filter hook forward priority -10; policy drop;
  meta nfproto ipv6 counter drop
  iifname "tailscale0" oifname "eth0" ip daddr { %s } counter accept
  iifname "tailscale0" oifname "eth0" ip daddr %s tcp dport 22 counter accept
  iifname "tailscale0" oifname "eth0" ip daddr 10.10.10.20 tcp dport 443 counter accept
  iifname "tailscale0" oifname "eth0" ip daddr 10.10.5.1 tcp dport 53 counter accept
  iifname "tailscale0" oifname "eth0" ip daddr 10.10.5.1 udp dport { 53, 123 } counter accept
  iifname "eth0" oifname "tailscale0" ct state established,related counter accept
 }
 chain input {
  type filter hook input priority -10; policy drop;
  iifname "lo" accept
  meta nfproto ipv6 drop
  iifname "tailscale0" drop
  iifname "eth0" ct state established,related accept
  iifname "eth0" udp sport 67 udp dport 68 accept
  iifname "eth0" ip saddr { %s } drop
  iifname "eth0" udp dport 41641 accept
 }
 chain output {
  type filter hook output priority -10; policy drop;
  oifname "lo" accept
  meta nfproto ipv6 drop
  oifname "eth0" udp sport 68 udp dport 67 accept
  oifname "eth0" ip daddr 10.10.5.1 tcp dport 53 accept
  oifname "eth0" ip daddr 10.10.5.1 udp dport { 53, 123 } accept
  ip daddr { %s } drop
  oifname "eth0" tcp dport { 80, 443 } accept
  oifname "eth0" meta l4proto udp accept
 }
}
`, strings.Join(Destinations(), ", "), model.ProxmoxManagementAddress, NonPublicIPv4, NonPublicIPv4)
}

// RuntimeFiles are installed atomically before enabling forwarding. No file
// contains an enrollment key or a copy of tailscaled's identity.
func RuntimeFiles() map[string]string {
	return map[string]string{
		"/etc/boetticher/tailnet.nft":              GuestPolicy(),
		"/etc/sysctl.d/99-boetticher-tailnet.conf": "net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\nnet.ipv6.conf.default.forwarding=0\n",
		"/usr/local/libexec/boetticher-tailnet-policy": `#!/bin/sh
set -eu
sysctl -q -w net.ipv4.ip_forward=0
nft -f /etc/boetticher/tailnet.nft
nft --stateless list table inet boetticher_tailnet > /run/boetticher-tailnet-policy.nft
sha256sum /run/boetticher-tailnet-policy.nft | cut -d ' ' -f 1 > /run/boetticher-tailnet-policy.sha256
rm -f /run/boetticher-tailnet-policy.nft
sysctl -q -w net.ipv4.ip_forward=1
`,
		"/etc/systemd/system/boetticher-tailnet-policy.service": `[Unit]
Description=Boetticher Tailnet forwarding boundary
After=systemd-sysctl.service
Before=tailscaled.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/boetticher-tailnet-policy
ExecReload=/usr/local/libexec/boetticher-tailnet-policy
ExecStop=/sbin/sysctl -q -w net.ipv4.ip_forward=0
[Install]
WantedBy=multi-user.target
`,
		"/etc/systemd/system/tailscaled.service.d/boetticher.conf": `[Unit]
Requires=boetticher-tailnet-policy.service
After=boetticher-tailnet-policy.service
[Service]
UMask=0077
`,
	}
}
