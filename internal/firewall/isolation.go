package firewall

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
)

// NonPublicIPv4 excludes local, shared, documentation, multicast and reserved
// space from Internet permissions. The observed HOME prefix is added at render
// time, including when an operator uses public addresses on that segment.
var NonPublicIPv4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
}

func renderIsolation(b *strings.Builder, plan Plan, destinationSets []destinationHostSet, dnsUpstreams []string) {
	prefixes := append([]string(nil), NonPublicIPv4...)
	if plan.Upstream != nil {
		prefixes = append(prefixes, upstreamSourceCIDR(*plan.Upstream))
	}
	fmt.Fprintf(b, "  set non_public_v4 { type ipv4_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(prefixes, ", "))
	if len(dnsUpstreams) > 0 {
		fmt.Fprintf(b, "  set upstream_doh_v4 { type ipv4_addr; elements = { %s } }\n", strings.Join(dnsUpstreams, ", "))
	}
	b.WriteString("  chain restricted_input {\n")
	b.WriteString("    iifname { \"sandbox0\", \"transit0\" } meta nfproto ipv6 drop\n")
	b.WriteString("    iifname \"sandbox0\" ip saddr { 0.0.0.0, 10.10.40.0/24 } ip daddr { 10.10.40.1, 255.255.255.255 } udp sport 68 udp dport 67 accept\n")
	b.WriteString("    iifname \"sandbox0\" ip saddr 10.10.40.0/24 ip daddr 10.10.40.1 udp dport { 53, 123 } accept\n")
	b.WriteString("    iifname \"sandbox0\" ip saddr 10.10.40.0/24 ip daddr 10.10.40.1 tcp dport 53 accept\n")
	b.WriteString("    iifname \"sandbox0\" drop\n")
	if len(plan.AirVPNSources) > 0 {
		// DHCP renewal/rebinding uses the selected guest's leased address as its
		// source. Return to the ordinary SERVERS DHCP input allowance before the
		// selected-source default deny, rather than letting a later lease expiry
		// strand the guest behind the host-isolation binding.
		b.WriteString("    iifname \"servers0\" ip saddr @airvpn_sources ip daddr 10.10.20.1 udp sport 68 udp dport 67 return\n")
		b.WriteString("    ip saddr @airvpn_sources drop\n")
	}
	b.WriteString("  }\n  chain restricted_forward {\n")
	b.WriteString("    iifname { \"sandbox0\", \"transit0\" } meta nfproto ipv6 drop\n    oifname { \"sandbox0\", \"transit0\" } meta nfproto ipv6 drop\n")
	b.WriteString("    iifname \"sandbox0\" ip saddr != 10.10.40.0/24 drop\n")
	b.WriteString("    iifname \"sandbox0\" ip daddr @non_public_v4 drop\n    iifname \"sandbox0\" oifname != \"wan0\" drop\n")
	if plan.Upstream == nil {
		b.WriteString("    iifname \"sandbox0\" oifname \"wan0\" drop comment \"boetticher:home-prefix-unverified\"\n")
	}
	b.WriteString("    oifname \"sandbox0\" ip saddr @non_public_v4 drop\n    oifname \"sandbox0\" iifname != \"wan0\" drop\n")
	seen := map[string]bool{}
	for _, r := range plan.Rules {
		if r.Route != "airvpn" || r.SourceMAC == "" || seen[r.SourceCIDR] {
			continue
		}
		seen[r.SourceCIDR] = true
		fmt.Fprintf(b, "    iifname %q ether saddr %s meta nfproto ipv6 drop\n", strings.ToLower(r.From)+"0", r.SourceMAC)
		fmt.Fprintf(b, "    iifname %q ether saddr %s ip saddr != %s drop\n", strings.ToLower(r.From)+"0", r.SourceMAC, r.SourceCIDR)
		fmt.Fprintf(b, "    iifname %q ip saddr %s ether saddr != %s drop\n", strings.ToLower(r.From)+"0", r.SourceCIDR, r.SourceMAC)
	}
	if len(plan.AirVPNSources) > 0 {
		b.WriteString("    ip saddr @airvpn_sources oifname \"wan0\" drop\n")
		b.WriteString("    ip daddr @airvpn_sources iifname \"wan0\" drop\n")
		b.WriteString("    ip daddr @airvpn_sources iifname \"mgmt0\" ip saddr 10.10.99.5 tcp dport { 22, 443 } return\n")
		b.WriteString("    ip saddr @airvpn_sources oifname \"mgmt0\" ip daddr 10.10.99.5 tcp sport { 22, 443 } ct direction reply return\n")
		b.WriteString("    ip daddr @airvpn_sources iifname \"trusted0\" ip saddr 10.10.30.0/24 tcp dport 443 return\n")
		b.WriteString("    ip saddr @airvpn_sources oifname \"trusted0\" ip daddr 10.10.30.0/24 tcp sport 443 ct direction reply return\n")
		b.WriteString("    ip daddr @airvpn_sources iifname \"transit0\" ip saddr 10.10.5.10 tcp dport 443 return\n")
		b.WriteString("    ip saddr @airvpn_sources oifname \"transit0\" ip daddr 10.10.5.10 tcp sport 443 ct direction reply return\n")
		for _, r := range plan.Rules {
			if !containsCIDR(plan.AirVPNSources, r.SourceCIDR) || r.Action != "allow" || r.Route == "airvpn" || r.DestinationCIDR == "" {
				continue
			}
			// Only explicit service destinations cross the private boundary.
			for _, proto := range strings.Split(r.Protocol, "/") {
				if proto != "tcp" && proto != "udp" {
					continue
				}
				fmt.Fprintf(b, "    iifname %q ip saddr %s ip daddr %s %s dport %s return\n", strings.ToLower(r.From)+"0", r.SourceCIDR, r.DestinationCIDR, proto, nftPortSet(r.Ports))
				fmt.Fprintf(b, "    iifname %q ip saddr %s ip daddr %s %s sport %s ct direction reply return\n", strings.ToLower(r.To)+"0", r.DestinationCIDR, r.SourceCIDR, proto, nftPortSet(r.Ports))
			}
		}
		for _, r := range plan.Rules {
			if !containsCIDR(plan.AirVPNSources, r.DestinationCIDR) || r.SourceCIDR == "" || r.Action != "allow" || r.Route == "airvpn" {
				continue
			}
			for _, proto := range strings.Split(r.Protocol, "/") {
				if proto != "tcp" && proto != "udp" {
					continue
				}
				fmt.Fprintf(b, "    iifname %q ip saddr %s ip daddr %s %s dport %s return\n", strings.ToLower(r.From)+"0", r.SourceCIDR, r.DestinationCIDR, proto, nftPortSet(r.Ports))
				fmt.Fprintf(b, "    ip saddr %s ip daddr %s %s sport %s ct direction reply return\n", r.DestinationCIDR, r.SourceCIDR, proto, nftPortSet(r.Ports))
			}
		}
		b.WriteString("    ip saddr @airvpn_sources tcp dport { 53, 853 } drop\n    ip saddr @airvpn_sources udp dport { 53, 853 } drop\n")
		if len(dnsUpstreams) > 0 {
			b.WriteString("    ip saddr @airvpn_sources ip daddr @upstream_doh_v4 tcp dport 443 drop\n    ip saddr @airvpn_sources ip daddr @upstream_doh_v4 udp dport 443 drop\n")
			b.WriteString("    ip daddr @airvpn_sources ip saddr @upstream_doh_v4 tcp sport 443 drop\n    ip daddr @airvpn_sources ip saddr @upstream_doh_v4 udp sport 443 drop\n")
		}
		b.WriteString("    ip saddr @airvpn_sources ip daddr @non_public_v4 drop\n    ip saddr @airvpn_sources oifname != \"transit0\" drop\n")
		b.WriteString("    ip daddr @airvpn_sources ip saddr @non_public_v4 drop\n    ip daddr @airvpn_sources iifname != \"transit0\" drop\n")
	}
	// Router payload must never escape unencrypted. Its single handshake
	// exception is resolved and rendered in the ordinary source policy.
	if plan.AirVPN != nil {
		fmt.Fprintf(b, "    iifname \"transit0\" ip saddr %s oifname \"wan0\" udp dport %d ip daddr @%s return\n", model.AirVPNGuestAddress, plan.AirVPN.EndpointPort, destinationHostSetName(destinationSets, plan.AirVPN.EndpointHost))
		fmt.Fprintf(b, "    iifname \"transit0\" ip saddr %s oifname \"wan0\" drop\n", model.AirVPNGuestAddress)
		for _, r := range plan.Rules {
			if r.SourceCIDR != model.AirVPNGuestAddress+"/32" || r.Action != "allow" || r.DestinationCIDR == "" {
				continue
			}
			for _, proto := range strings.Split(r.Protocol, "/") {
				if proto == "tcp" || proto == "udp" {
					fmt.Fprintf(b, "    iifname \"transit0\" ip saddr %s ip daddr %s %s dport %s return\n", model.AirVPNGuestAddress, r.DestinationCIDR, proto, nftPortSet(r.Ports))
				}
			}
		}
		fmt.Fprintf(b, "    iifname \"transit0\" ip saddr %s ip daddr 10.10.99.5 tcp sport 22 ct direction reply return\n", model.AirVPNGuestAddress)
		if len(plan.AirVPNSources) > 0 {
			fmt.Fprintf(b, "    iifname \"transit0\" ip saddr %s ip daddr @airvpn_sources tcp sport 53 ct direction reply return\n", model.AirVPNGuestAddress)
			fmt.Fprintf(b, "    iifname \"transit0\" ip saddr %s ip daddr @airvpn_sources udp sport { 53, 123 } ct direction reply return\n", model.AirVPNGuestAddress)
		}
		fmt.Fprintf(b, "    iifname \"transit0\" ip saddr %s drop\n", model.AirVPNGuestAddress)
	}
	b.WriteString("  }\n")
}

func resolveDNSUpstreamAddresses(lookup func(string) ([]net.IP, error)) ([]string, error) {
	seen := map[string]bool{}
	for _, endpoint := range dns.PublicUpstreams {
		u, err := url.Parse(endpoint)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("invalid configured DNS upstream")
		}
		addresses, err := lookup(u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("resolve DNS bypass guard for %s: %w", u.Hostname(), err)
		}
		found := false
		for _, address := range addresses {
			if address.To4() != nil {
				seen[address.To4().String()] = true
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("DNS bypass guard has no IPv4 address for %s", u.Hostname())
		}
	}
	var result []string
	for address := range seen {
		result = append(result, address)
	}
	sort.Strings(result)
	return result, nil
}

func containsCIDR(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
