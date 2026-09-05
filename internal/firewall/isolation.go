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

func writeIsolationRule(b *strings.Builder, rule, comment string) {
	fmt.Fprintf(b, "    %s comment %q\n", rule, comment)
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
	writeIsolationRule(b, `iifname { "sandbox0", "transit0" } meta nfproto ipv6 drop`, "boetticher:drop:input-restricted-ipv6")
	writeIsolationRule(b, `iifname "sandbox0" ip saddr { 0.0.0.0, 10.10.40.0/24 } ip daddr { 10.10.40.1, 255.255.255.255 } udp sport 68 udp dport 67 accept`, "boetticher:allow:input-sandbox-dhcp")
	writeIsolationRule(b, `iifname "sandbox0" ip saddr 10.10.40.0/24 ip daddr 10.10.40.1 udp dport { 53, 123 } accept`, "boetticher:allow:input-sandbox-dns-ntp-udp")
	writeIsolationRule(b, `iifname "sandbox0" ip saddr 10.10.40.0/24 ip daddr 10.10.40.1 tcp dport 53 accept`, "boetticher:allow:input-sandbox-dns-tcp")
	writeIsolationRule(b, `iifname "sandbox0" drop`, "boetticher:drop:input-sandbox-default")
	if len(plan.AirVPNSources) > 0 {
		// DHCP renewal/rebinding uses the selected guest's leased address as its
		// source. Return to the ordinary SERVERS DHCP input allowance before the
		// selected-source default deny, rather than letting a later lease expiry
		// strand the guest behind the host-isolation binding.
		writeIsolationRule(b, `iifname "servers0" ip saddr @airvpn_sources ip daddr 10.10.20.1 udp sport 68 udp dport 67 return`, "boetticher:return:input-airvpn-dhcp-renewal")
		writeIsolationRule(b, `ip saddr @airvpn_sources drop`, "boetticher:drop:input-airvpn-source")
	}
	b.WriteString("  }\n  chain restricted_forward {\n")
	writeIsolationRule(b, `iifname { "sandbox0", "transit0" } meta nfproto ipv6 drop`, "boetticher:drop:forward-restricted-input-ipv6")
	writeIsolationRule(b, `oifname { "sandbox0", "transit0" } meta nfproto ipv6 drop`, "boetticher:drop:forward-restricted-output-ipv6")
	writeIsolationRule(b, `iifname "sandbox0" ip saddr != 10.10.40.0/24 drop`, "boetticher:drop:forward-sandbox-source-spoof")
	writeIsolationRule(b, `iifname "sandbox0" ip daddr @non_public_v4 drop`, "boetticher:drop:forward-sandbox-non-public")
	writeIsolationRule(b, `iifname "sandbox0" oifname != "wan0" drop`, "boetticher:drop:forward-sandbox-non-wan")
	if plan.Upstream == nil {
		b.WriteString("    iifname \"sandbox0\" oifname \"wan0\" drop comment \"boetticher:home-prefix-unverified\"\n")
	}
	writeIsolationRule(b, `oifname "sandbox0" ip saddr @non_public_v4 drop`, "boetticher:drop:forward-sandbox-return-non-public")
	writeIsolationRule(b, `oifname "sandbox0" iifname != "wan0" drop`, "boetticher:drop:forward-sandbox-return-non-wan")
	seen := map[string]bool{}
	for _, r := range plan.Rules {
		if r.Route != "airvpn" || r.SourceMAC == "" || seen[r.SourceCIDR] {
			continue
		}
		seen[r.SourceCIDR] = true
		token := safeRuleToken(r.SourceCIDR)
		writeIsolationRule(b, fmt.Sprintf(`iifname %q ether saddr %s meta nfproto ipv6 drop`, strings.ToLower(r.From)+"0", r.SourceMAC), "boetticher:drop:forward-airvpn-source-ipv6-"+token)
		writeIsolationRule(b, fmt.Sprintf(`iifname %q ether saddr %s ip saddr != %s drop`, strings.ToLower(r.From)+"0", r.SourceMAC, r.SourceCIDR), "boetticher:drop:forward-airvpn-source-ip-"+token)
		writeIsolationRule(b, fmt.Sprintf(`iifname %q ip saddr %s ether saddr != %s drop`, strings.ToLower(r.From)+"0", r.SourceCIDR, r.SourceMAC), "boetticher:drop:forward-airvpn-source-mac-"+token)
	}
	if len(plan.AirVPNSources) > 0 {
		writeIsolationRule(b, `ip saddr @airvpn_sources oifname "wan0" drop`, "boetticher:drop:forward-airvpn-direct-wan")
		writeIsolationRule(b, `ip daddr @airvpn_sources iifname "wan0" drop`, "boetticher:drop:forward-airvpn-inbound-wan")
		writeIsolationRule(b, `ip daddr @airvpn_sources iifname "mgmt0" ip saddr 10.10.99.5 tcp dport { 22, 443 } return`, "boetticher:return:forward-airvpn-mgmt-request")
		writeIsolationRule(b, `ip saddr @airvpn_sources oifname "mgmt0" ip daddr 10.10.99.5 tcp sport { 22, 443 } ct direction reply return`, "boetticher:return:forward-airvpn-mgmt-reply")
		writeIsolationRule(b, `ip daddr @airvpn_sources iifname "trusted0" ip saddr 10.10.30.0/24 tcp dport 443 return`, "boetticher:return:forward-airvpn-trusted-request")
		writeIsolationRule(b, `ip saddr @airvpn_sources oifname "trusted0" ip daddr 10.10.30.0/24 tcp sport 443 ct direction reply return`, "boetticher:return:forward-airvpn-trusted-reply")
		writeIsolationRule(b, `ip daddr @airvpn_sources iifname "transit0" ip saddr 10.10.5.10 tcp dport 443 return`, "boetticher:return:forward-airvpn-transit-request")
		writeIsolationRule(b, `ip saddr @airvpn_sources oifname "transit0" ip daddr 10.10.5.10 tcp sport 443 ct direction reply return`, "boetticher:return:forward-airvpn-transit-reply")
		for _, r := range plan.Rules {
			if !containsCIDR(plan.AirVPNSources, r.SourceCIDR) || r.Action != "allow" || r.Route == "airvpn" || r.DestinationCIDR == "" {
				continue
			}
			// Only explicit service destinations cross the private boundary.
			for _, proto := range strings.Split(r.Protocol, "/") {
				if proto != "tcp" && proto != "udp" {
					continue
				}
				token := safeRuleToken(r.Name) + "-" + proto
				writeIsolationRule(b, fmt.Sprintf(`iifname %q ip saddr %s ip daddr %s %s dport %s return`, strings.ToLower(r.From)+"0", r.SourceCIDR, r.DestinationCIDR, proto, nftPortSet(r.Ports)), "boetticher:return:forward-airvpn-service-"+token)
				writeIsolationRule(b, fmt.Sprintf(`iifname %q ip saddr %s ip daddr %s %s sport %s ct direction reply return`, strings.ToLower(r.To)+"0", r.DestinationCIDR, r.SourceCIDR, proto, nftPortSet(r.Ports)), "boetticher:return:forward-airvpn-service-reply-"+token)
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
				token := safeRuleToken(r.Name) + "-" + proto
				writeIsolationRule(b, fmt.Sprintf(`iifname %q ip saddr %s ip daddr %s %s dport %s return`, strings.ToLower(r.From)+"0", r.SourceCIDR, r.DestinationCIDR, proto, nftPortSet(r.Ports)), "boetticher:return:forward-airvpn-destination-"+token)
				writeIsolationRule(b, fmt.Sprintf(`ip saddr %s ip daddr %s %s sport %s ct direction reply return`, r.DestinationCIDR, r.SourceCIDR, proto, nftPortSet(r.Ports)), "boetticher:return:forward-airvpn-destination-reply-"+token)
			}
		}
		writeIsolationRule(b, `ip saddr @airvpn_sources tcp dport { 53, 853 } drop`, "boetticher:drop:forward-airvpn-dns-tcp")
		writeIsolationRule(b, `ip saddr @airvpn_sources udp dport { 53, 853 } drop`, "boetticher:drop:forward-airvpn-dns-udp")
		if len(dnsUpstreams) > 0 {
			writeIsolationRule(b, `ip saddr @airvpn_sources ip daddr @upstream_doh_v4 tcp dport 443 drop`, "boetticher:drop:forward-airvpn-doh-tcp")
			writeIsolationRule(b, `ip saddr @airvpn_sources ip daddr @upstream_doh_v4 udp dport 443 drop`, "boetticher:drop:forward-airvpn-doh-udp")
			writeIsolationRule(b, `ip daddr @airvpn_sources ip saddr @upstream_doh_v4 tcp sport 443 drop`, "boetticher:drop:forward-airvpn-doh-reply-tcp")
			writeIsolationRule(b, `ip daddr @airvpn_sources ip saddr @upstream_doh_v4 udp sport 443 drop`, "boetticher:drop:forward-airvpn-doh-reply-udp")
		}
		writeIsolationRule(b, `ip saddr @airvpn_sources ip daddr @non_public_v4 drop`, "boetticher:drop:forward-airvpn-non-public")
		writeIsolationRule(b, `ip saddr @airvpn_sources oifname != "transit0" drop`, "boetticher:drop:forward-airvpn-non-transit")
		writeIsolationRule(b, `ip daddr @airvpn_sources ip saddr @non_public_v4 drop`, "boetticher:drop:forward-airvpn-return-non-public")
		writeIsolationRule(b, `ip daddr @airvpn_sources iifname != "transit0" drop`, "boetticher:drop:forward-airvpn-return-non-transit")
	}
	// Router payload must never escape unencrypted. Its single handshake
	// exception is resolved and rendered in the ordinary source policy.
	if plan.AirVPN != nil {
		writeIsolationRule(b, fmt.Sprintf(`iifname "transit0" ip saddr %s oifname "wan0" udp dport %d ip daddr @%s return`, model.AirVPNGuestAddress, plan.AirVPN.EndpointPort, destinationHostSetName(destinationSets, plan.AirVPN.EndpointHost)), "boetticher:return:forward-airvpn-handshake")
		writeIsolationRule(b, fmt.Sprintf(`iifname "transit0" ip saddr %s oifname "wan0" drop`, model.AirVPNGuestAddress), "boetticher:drop:forward-airvpn-router-wan")
		for _, r := range plan.Rules {
			if r.SourceCIDR != model.AirVPNGuestAddress+"/32" || r.Action != "allow" || r.DestinationCIDR == "" {
				continue
			}
			for _, proto := range strings.Split(r.Protocol, "/") {
				if proto == "tcp" || proto == "udp" {
					writeIsolationRule(b, fmt.Sprintf(`iifname "transit0" ip saddr %s ip daddr %s %s dport %s return`, model.AirVPNGuestAddress, r.DestinationCIDR, proto, nftPortSet(r.Ports)), "boetticher:return:forward-airvpn-router-service-"+safeRuleToken(r.Name)+"-"+proto)
				}
			}
		}
		writeIsolationRule(b, fmt.Sprintf(`iifname "transit0" ip saddr %s ip daddr 10.10.99.5 tcp sport 22 ct direction reply return`, model.AirVPNGuestAddress), "boetticher:return:forward-airvpn-router-ssh-reply")
		if len(plan.AirVPNSources) > 0 {
			writeIsolationRule(b, fmt.Sprintf(`iifname "transit0" ip saddr %s ip daddr @airvpn_sources tcp sport 53 ct direction reply return`, model.AirVPNGuestAddress), "boetticher:return:forward-airvpn-router-dns-tcp-reply")
			writeIsolationRule(b, fmt.Sprintf(`iifname "transit0" ip saddr %s ip daddr @airvpn_sources udp sport { 53, 123 } ct direction reply return`, model.AirVPNGuestAddress), "boetticher:return:forward-airvpn-router-dns-ntp-udp-reply")
		}
		writeIsolationRule(b, fmt.Sprintf(`iifname "transit0" ip saddr %s drop`, model.AirVPNGuestAddress), "boetticher:drop:forward-airvpn-router-default")
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
