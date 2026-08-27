package firewall

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	FilterTable = "boetticher_filter"
	NATTable    = "boetticher_nat"
	DDNSPort    = "53001"
)

type Interface struct {
	Role    string `json:"role"`
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	Bridge  string `json:"bridge"`
	VLAN    int    `json:"vlan,omitempty"`
	Address string `json:"address"`
	Method  string `json:"method"`
}

type PolicyRule struct {
	Sequence    int      `json:"sequence"`
	Name        string   `json:"name"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	Action      string   `json:"action"`
	Protocol    string   `json:"protocol"`
	Ports       []string `json:"ports,omitempty"`
	Counter     string   `json:"counter"`
	LogPrefix   string   `json:"log_prefix,omitempty"`
	NAT         bool     `json:"nat,omitempty"`
	Description string   `json:"description"`
}

type DHCPSubnet struct {
	ID                   int      `json:"id"`
	Zone                 string   `json:"zone"`
	Network              string   `json:"network"`
	Pool                 string   `json:"pool,omitempty"`
	Gateway              string   `json:"gateway"`
	DNS                  []string `json:"dns"`
	NTP                  []string `json:"ntp"`
	ForwardZone          string   `json:"forward_zone"`
	ReverseZone          string   `json:"reverse_zone"`
	TSIGKeyName          string   `json:"tsig_key_name"`
	TSIGAlgorithm        string   `json:"tsig_algorithm"`
	UpdateOnRenew        bool     `json:"update_on_renew"`
	ConflictResolution   string   `json:"conflict_resolution"`
	RegistrationOptional bool     `json:"registration_optional"`
}

type Plan struct {
	ModelRevision string       `json:"model_revision"`
	Mode          string       `json:"mode"`
	Engine        string       `json:"engine"`
	IPv4Only      bool         `json:"ipv4_only"`
	Forwarding    bool         `json:"forwarding_after_policy"`
	Interfaces    []Interface  `json:"interfaces"`
	Rules         []PolicyRule `json:"rules"`
	DHCP          []DHCPSubnet `json:"dhcp_subnets"`
	DDNS          dns.DDNSPlan `json:"ddns"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	dnsPlan, err := dns.PlanFromSite(s)
	if err != nil {
		return Plan{}, err
	}
	engine := "nftables + Kea"
	if s.Gateway.Mode == model.GatewayModeExternal {
		engine = "operator-managed external firewall"
	}
	plan := Plan{
		ModelRevision: revision,
		Mode:          s.Gateway.Mode,
		Engine:        engine,
		IPv4Only:      true,
		Forwarding:    s.Gateway.Mode == model.GatewayModeManaged,
		Rules:         policyRules(s),
		DHCP:          dhcpSubnets(s),
		DDNS:          dnsPlan.DDNS,
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		plan.Interfaces = gatewayInterfaces(s)
	}
	return plan, nil
}

func gatewayInterfaces(s model.Site) []Interface {
	interfaces := []Interface{{Role: "WAN", Name: "wan0", MAC: "02:00:00:00:01:01", Bridge: "vmbr0", Address: "dhcp", Method: "dhcp"}}
	for _, zone := range s.Normalize().Network.Zones {
		interfaces = append(interfaces, Interface{
			Role: zone.Name, Name: strings.ToLower(zone.Name) + "0", MAC: fmt.Sprintf("02:00:00:00:01:%02x", len(interfaces)+1), Bridge: "vmbr1", VLAN: zone.VLAN,
			Address: zone.Gateway + "/24", Method: "static",
		})
	}
	return interfaces
}

func dhcpSubnets(s model.Site) []DHCPSubnet {
	zones := append([]model.Zone(nil), s.Network.Zones...)
	sort.Slice(zones, func(i, j int) bool { return zones[i].VLAN < zones[j].VLAN })
	result := make([]DHCPSubnet, 0, len(zones))
	for index, zone := range zones {
		forward := strings.ToLower(zone.Name) + "." + s.Network.Domain + "."
		result = append(result, DHCPSubnet{
			ID: index + 1, Zone: zone.Name, Network: zone.Network, Pool: poolForNetwork(zone.Network, zone.AddressMode),
			Gateway: zone.Gateway, DNS: append([]string(nil), zone.DNSAddresses...), NTP: append([]string(nil), zone.NTPAddresses...),
			ForwardZone: forward, ReverseZone: reverseZoneForNetwork(zone.Network), TSIGKeyName: dns.TSIGKeyName(zone.Name, s.Network.Domain),
			TSIGAlgorithm: "hmac-sha256", UpdateOnRenew: true, ConflictResolution: "check-exists-with-dhcid", RegistrationOptional: true,
		})
	}
	return result
}

func poolForNetwork(network, addressMode string) string {
	if addressMode == "reservations-only" {
		return ""
	}
	base, parsed, err := net.ParseCIDR(network)
	if err != nil {
		return ""
	}
	ones, bits := parsed.Mask.Size()
	if bits != 32 || ones != 24 {
		return ""
	}
	prefix := strings.TrimSuffix(base.String(), ".0")
	return prefix + ".100-" + prefix + ".199"
}

func reverseZoneForNetwork(network string) string {
	base, parsed, err := net.ParseCIDR(network)
	if err != nil {
		return ""
	}
	ones, bits := parsed.Mask.Size()
	if bits != 32 || ones != 24 {
		return ""
	}
	octets := strings.Split(base.To4().String(), ".")
	return strings.Join([]string{octets[2], octets[1], octets[0], "in-addr.arpa."}, ".")
}

func policyRules(s model.Site) []PolicyRule {
	networks := map[string]string{}
	for _, zone := range s.Network.Zones {
		networks[zone.Name] = zone.Network
	}
	rules := make([]PolicyRule, 0, 40)
	add := func(name, from, to, action, protocol string, ports []string, log bool, nat bool) {
		prefix := ""
		if log {
			prefix = "boetticher " + name
		}
		rules = append(rules, PolicyRule{
			Sequence: len(rules) + 1, Name: name, From: from, To: to, Action: action, Protocol: protocol,
			Ports: append([]string(nil), ports...), Counter: "boetticher_" + strings.ToLower(strings.ReplaceAll(name, " ", "_")), LogPrefix: prefix, NAT: nat,
			Description: "boetticher " + name,
		})
	}
	// These are gateway-local services. Forwarding rules below deliberately
	// place internal denies before any Internet egress rule.
	for _, zone := range []string{"TRUSTED", "SERVERS", "SANDBOX", "MGMT"} {
		add(strings.ToLower(zone)+" DHCP to gateway", zone, "gateway", "allow", "udp", []string{"67"}, false, false)
	}
	add("SANDBOX DNS to gateway", "SANDBOX", "gateway", "allow", "tcp/udp", []string{"53"}, false, false)
	add("SANDBOX NTP to gateway", "SANDBOX", "gateway", "allow", "udp", []string{"123"}, false, false)
	add("MGMT SSH to gateway", "MGMT", "gateway", "allow", "tcp", []string{"22"}, false, false)

	add("SANDBOX to TRUSTED deny", "SANDBOX", "TRUSTED", "deny", "any", nil, true, false)
	add("SANDBOX to SERVERS deny", "SANDBOX", "SERVERS", "deny", "any", nil, true, false)
	add("SANDBOX to MGMT deny", "SANDBOX", "MGMT", "deny", "any", nil, true, false)
	add("TRUSTED DNS to SERVERS", "TRUSTED", "SERVERS", "allow", "tcp/udp", []string{"53"}, false, false)
	add("TRUSTED NTP to SERVERS", "TRUSTED", "SERVERS", "allow", "udp", []string{"123"}, false, false)
	add("TRUSTED HTTPS to SERVERS", "TRUSTED", "SERVERS", "allow", "tcp", []string{"443"}, false, false)
	add("TRUSTED administration to MGMT", "TRUSTED", "MGMT", "allow", "tcp", []string{"22", "443", "8006"}, false, false)
	add("SERVERS DNS to SERVERS", "SERVERS", "SERVERS", "allow", "tcp/udp", []string{"53"}, false, false)
	add("SERVERS NTP to SERVERS", "SERVERS", "SERVERS", "allow", "udp", []string{"123"}, false, false)
	add("SERVERS monitoring to MGMT", "SERVERS", "MGMT", "allow", "tcp", []string{"10051"}, false, false)
	add("MGMT administration to SERVERS", "MGMT", "SERVERS", "allow", "tcp", []string{"22", "53", "80", "443"}, false, false)
	add("MGMT diagnostics to TRUSTED", "MGMT", "TRUSTED", "allow", "icmp", nil, false, false)
	add("SANDBOX Internet egress", "SANDBOX", "WAN", "allow", "any", nil, false, true)
	add("TRUSTED Internet egress", "TRUSTED", "WAN", "allow", "any", nil, false, true)
	add("SERVERS update egress", "SERVERS", "WAN", "allow", "tcp/udp", []string{"53", "80", "443", "853"}, false, true)
	add("MGMT update egress", "MGMT", "WAN", "allow", "tcp", []string{"443"}, false, true)
	return rules
}

func RenderNFT(plan Plan) (string, error) {
	if plan.Mode != model.GatewayModeManaged {
		return "", errors.New("nftables is only rendered for managed gateway mode")
	}
	if len(plan.Interfaces) != 5 {
		return "", errors.New("managed gateway requires WAN plus four zone interfaces")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by boetticher. Model revision: %s\n", plan.ModelRevision)
	b.WriteString("destroy table inet " + FilterTable + "\n")
	b.WriteString("destroy table ip " + NATTable + "\n\n")
	b.WriteString("table inet " + FilterTable + " {\n")
	for _, zone := range []string{"TRUSTED", "SERVERS", "SANDBOX", "MGMT"} {
		fmt.Fprintf(&b, "  set %s_net { type ipv4_addr; flags interval; elements = { %s } }\n", strings.ToLower(zone), networkFor(plan, zone))
	}
	b.WriteString("  chain input {\n    type filter hook input priority filter; policy drop;\n    iifname \"lo\" accept comment \"boetticher:input-loopback\"\n    ct state established,related accept comment \"boetticher:input-established\"\n    iifname \"wan0\" udp sport 67 udp dport 68 accept comment \"boetticher:input-wan-dhcp\"\n    iifname { \"trusted0\", \"servers0\", \"sandbox0\", \"mgmt0\" } udp dport 67 counter accept comment \"boetticher:input-zone-dhcp\"\n    iifname \"sandbox0\" udp dport 53 counter accept comment \"boetticher:input-sandbox-dns-udp\"\n    iifname \"sandbox0\" tcp dport 53 counter accept comment \"boetticher:input-sandbox-dns-tcp\"\n    iifname \"sandbox0\" udp dport 123 counter accept comment \"boetticher:input-sandbox-ntp\"\n    iifname \"mgmt0\" tcp dport 22 counter accept comment \"boetticher:input-mgmt-ssh\"\n  }\n")
	b.WriteString("  chain forward {\n    type filter hook forward priority filter; policy drop;\n    ct state established,related accept comment \"boetticher:forward-established\"\n")
	for _, deny := range []struct{ zone, set, label string }{{"sandbox0", "trusted_net", "SANDBOX-TRUSTED-DROP"}, {"sandbox0", "servers_net", "SANDBOX-SERVERS-DROP"}, {"sandbox0", "mgmt_net", "SANDBOX-MGMT-DROP"}} {
		fmt.Fprintf(&b, "    iifname \"%s\" ip daddr @%s counter log prefix \"boetticher %s \" drop comment \"boetticher:forward-%s\"\n", deny.zone, deny.set, deny.label, strings.ToLower(strings.ReplaceAll(deny.label, "-", "-")))
	}
	// The state rule above is deliberately the first forward rule after the
	// chain declaration. It keeps return traffic working without weakening the
	// ordered SANDBOX deny rules below.
	b.WriteString("    iifname \"trusted0\" ip daddr @servers_net tcp dport { 53, 443 } counter accept comment \"boetticher:forward-trusted-servers-tcp\"\n")
	b.WriteString("    iifname \"trusted0\" ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-trusted-servers-udp\"\n")
	b.WriteString("    iifname \"trusted0\" ip daddr @mgmt_net tcp dport { 22, 443, 8006 } counter accept comment \"boetticher:forward-trusted-mgmt\"\n")
	b.WriteString("    iifname \"servers0\" ip daddr @servers_net tcp dport 53 counter accept comment \"boetticher:forward-servers-dns-tcp\"\n")
	b.WriteString("    iifname \"servers0\" ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-servers-dns-udp\"\n")
	b.WriteString("    iifname \"servers0\" ip daddr @mgmt_net tcp dport 10051 counter accept comment \"boetticher:forward-servers-monitoring\"\n")
	b.WriteString("    iifname \"mgmt0\" ip daddr @servers_net tcp dport { 22, 53, 80, 443 } counter accept comment \"boetticher:forward-mgmt-servers-tcp\"\n")
	b.WriteString("    iifname \"mgmt0\" ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-mgmt-servers-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" ip daddr @trusted_net ip protocol icmp counter accept comment \"boetticher:forward-mgmt-trusted-icmp\"\n")
	b.WriteString("    iifname \"sandbox0\" oifname \"wan0\" ip saddr @sandbox_net counter accept comment \"boetticher:forward-sandbox-internet\"\n")
	b.WriteString("    iifname \"trusted0\" oifname \"wan0\" ip saddr @trusted_net counter accept comment \"boetticher:forward-trusted-internet\"\n")
	b.WriteString("    iifname \"servers0\" oifname \"wan0\" ip saddr @servers_net tcp dport { 53, 80, 443, 853 } counter accept comment \"boetticher:forward-servers-internet-tcp\"\n")
	b.WriteString("    iifname \"servers0\" oifname \"wan0\" ip saddr @servers_net udp dport { 53, 853 } counter accept comment \"boetticher:forward-servers-internet-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" oifname \"wan0\" ip saddr @mgmt_net tcp dport 443 counter accept comment \"boetticher:forward-mgmt-internet\"\n")
	b.WriteString("  }\n  chain output { type filter hook output priority filter; policy accept; }\n}\n\n")
	b.WriteString("table ip " + NATTable + " {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"wan0\" ip saddr " + networkFor(plan, "TRUSTED") + " masquerade comment \"boetticher:nat-trusted\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "SERVERS") + " masquerade comment \"boetticher:nat-servers\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "SANDBOX") + " masquerade comment \"boetticher:nat-sandbox\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "MGMT") + " masquerade comment \"boetticher:nat-mgmt\"\n  }\n}\n")
	return b.String(), nil
}

func networkFor(plan Plan, zone string) string {
	for _, subnet := range plan.DHCP {
		if subnet.Zone == zone {
			return subnet.Network
		}
	}
	return "0.0.0.0/32"
}

func ValidateNFT(ruleset string) error {
	if !strings.Contains(ruleset, "table inet "+FilterTable) || !strings.Contains(ruleset, "table ip "+NATTable) {
		return errors.New("ruleset is missing boetticher-owned filter or NAT table")
	}
	if !strings.Contains(ruleset, "policy drop") || !strings.Contains(ruleset, "ct state established,related accept") {
		return errors.New("ruleset must default-drop and allow established traffic")
	}
	if strings.Contains(ruleset, "ethX.") {
		return errors.New("ruleset contains an unstable interface identity")
	}
	return nil
}
