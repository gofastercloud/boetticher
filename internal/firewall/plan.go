package firewall

import (
	"errors"
	"fmt"
	"net"
	"net/url"
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
	Sequence        int      `json:"sequence"`
	Name            string   `json:"name"`
	From            string   `json:"from"`
	To              string   `json:"to"`
	Action          string   `json:"action"`
	Protocol        string   `json:"protocol"`
	Ports           []string `json:"ports,omitempty"`
	Counter         string   `json:"counter"`
	LogPrefix       string   `json:"log_prefix,omitempty"`
	NAT             bool     `json:"nat,omitempty"`
	Description     string   `json:"description"`
	SourceCIDR      string   `json:"source_cidr,omitempty"`
	DestinationCIDR string   `json:"destination_cidr,omitempty"`
	DestinationHost string   `json:"destination_host,omitempty"`
}

type DHCPSubnet struct {
	ID                   int               `json:"id"`
	Zone                 string            `json:"zone"`
	Network              string            `json:"network"`
	Pool                 string            `json:"pool,omitempty"`
	Gateway              string            `json:"gateway"`
	DNS                  []string          `json:"dns"`
	NTP                  []string          `json:"ntp"`
	ForwardZone          string            `json:"forward_zone"`
	ReverseZone          string            `json:"reverse_zone"`
	TSIGKeyName          string            `json:"tsig_key_name"`
	TSIGAlgorithm        string            `json:"tsig_algorithm"`
	UpdateOnRenew        bool              `json:"update_on_renew"`
	ConflictResolution   string            `json:"conflict_resolution"`
	RegistrationOptional bool              `json:"registration_optional"`
	Reservations         []DHCPReservation `json:"reservations,omitempty"`
}

type DHCPReservation struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	MAC      string `json:"mac"`
}

type Plan struct {
	ModelRevision   string       `json:"model_revision"`
	Mode            string       `json:"mode"`
	Engine          string       `json:"engine"`
	IPv4Only        bool         `json:"ipv4_only"`
	Forwarding      bool         `json:"forwarding_after_policy"`
	TailnetExitNode bool         `json:"tailnet_exit_node,omitempty"`
	Interfaces      []Interface  `json:"interfaces"`
	Rules           []PolicyRule `json:"rules"`
	ModuleSources   []string     `json:"module_source_cidrs,omitempty"`
	DHCP            []DHCPSubnet `json:"dhcp_subnets"`
	DDNS            dns.DDNSPlan `json:"ddns"`
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
		ModelRevision:   revision,
		Mode:            s.Gateway.Mode,
		Engine:          engine,
		IPv4Only:        true,
		Forwarding:      s.Gateway.Mode == model.GatewayModeManaged,
		TailnetExitNode: tailnetExitNodeEnabled(s),
		Rules:           policyRules(s),
		ModuleSources:   moduleSourceCIDRs(s),
		DHCP:            dhcpSubnets(s),
		DDNS:            dnsPlan.DDNS,
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		plan.Interfaces = gatewayInterfaces(s)
	}
	return plan, nil
}

func moduleSourceCIDRs(s model.Site) []string {
	seen := map[string]bool{}
	// A module guest is isolated from broad zone policy only when its own
	// declaration supplies source-specific intents. Core-owned module guests
	// without such an intent continue to receive the established platform
	// baseline (for example DNS update egress).
	for _, declaration := range s.Declarations {
		for _, intent := range declaration.NetworkIntents {
			component, ok := componentReference(s, intent.Source)
			if !ok || component.Module != declaration.Module {
				continue
			}
			if address := net.ParseIP(component.Address).To4(); address != nil {
				seen[address.String()+"/32"] = true
			}
		}
	}
	result := make([]string, 0, len(seen))
	for cidr := range seen {
		result = append(result, cidr)
	}
	sort.Strings(result)
	return result
}

func gatewayInterfaces(s model.Site) []Interface {
	interfaces := []Interface{{Role: "WAN", Name: "wan0", MAC: "02:00:00:00:01:01", Bridge: "vmbr0", Address: "dhcp", Method: "dhcp"}}
	// Keep the established interface/MAC identities stable. TRANSIT and INFRA
	// are permanent platform interfaces appended after the existing identities,
	// not module-created vNICs whose presence changes them.
	for _, zoneType := range []model.ZoneType{model.ZoneTypeTrusted, model.ZoneTypeServers, model.ZoneTypeSandbox, model.ZoneTypeManagement, model.ZoneTypeTransit, model.ZoneTypeInfrastructure} {
		zone, err := s.ZoneForType(zoneType)
		if err != nil {
			continue
		}
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
	for _, zone := range zones {
		if zone.Type != model.ZoneTypeTrusted && zone.Type != model.ZoneTypeSandbox && zone.Type != model.ZoneTypeServers {
			continue
		}
		reservations := []DHCPReservation(nil)
		if zone.Type == model.ZoneTypeServers {
			reservations = make([]DHCPReservation, 0, len(s.DHCPReservations))
			for _, reservation := range s.Normalize().DHCPReservations {
				reservations = append(reservations, DHCPReservation{Hostname: reservation.Hostname, Address: reservation.Address, MAC: reservation.MAC})
			}
		}
		forward := strings.ToLower(zone.Name) + "." + s.Network.Domain + "."
		result = append(result, DHCPSubnet{
			ID: len(result) + 1, Zone: zone.Name, Network: zone.Network, Pool: poolForNetwork(zone.Network, zone.AddressMode),
			Gateway: zone.Gateway, DNS: append([]string(nil), zone.DNSAddresses...), NTP: append([]string(nil), zone.NTPAddresses...),
			ForwardZone: forward, ReverseZone: reverseZoneForNetwork(zone.Network), TSIGKeyName: dns.TSIGKeyName(zone.Name, s.Network.Domain),
			TSIGAlgorithm: "hmac-sha256", UpdateOnRenew: true, ConflictResolution: "check-exists-with-dhcid", RegistrationOptional: true, Reservations: reservations,
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
	for _, zone := range []string{"TRUSTED", "SERVERS", "SANDBOX"} {
		add(strings.ToLower(zone)+" DHCP to gateway", zone, "gateway", "allow", "udp", []string{"67"}, false, false)
	}
	add("SANDBOX DNS to gateway", "SANDBOX", "gateway", "allow", "tcp/udp", []string{"53"}, false, false)
	add("SANDBOX NTP to gateway", "SANDBOX", "gateway", "allow", "udp", []string{"123"}, false, false)
	add("MGMT SSH to gateway", "MGMT", "gateway", "allow", "tcp", []string{"22"}, false, false)

	add("SANDBOX to TRUSTED deny", "SANDBOX", "TRUSTED", "deny", "any", nil, true, false)
	add("SANDBOX to SERVERS deny", "SANDBOX", "SERVERS", "deny", "any", nil, true, false)
	add("SANDBOX to INFRA deny", "SANDBOX", "INFRA", "deny", "any", nil, true, false)
	add("SANDBOX to MGMT deny", "SANDBOX", "MGMT", "deny", "any", nil, true, false)
	add("TRUSTED DNS to INFRA", "TRUSTED", "INFRA", "allow", "tcp/udp", []string{"53"}, false, false)
	add("TRUSTED NTP to INFRA", "TRUSTED", "INFRA", "allow", "udp", []string{"123"}, false, false)
	add("TRUSTED HTTPS to INFRA", "TRUSTED", "INFRA", "allow", "tcp", []string{"443"}, false, false)
	add("TRUSTED HTTPS to SERVERS", "TRUSTED", "SERVERS", "allow", "tcp", []string{"443"}, false, false)
	add("TRUSTED administration to MGMT", "TRUSTED", "MGMT", "allow", "tcp", []string{"22", "443", "8006"}, false, false)
	add("SERVERS DNS to INFRA", "SERVERS", "INFRA", "allow", "tcp/udp", []string{"53"}, false, false)
	add("SERVERS NTP to INFRA", "SERVERS", "INFRA", "allow", "udp", []string{"123"}, false, false)
	add("MGMT administration to SERVERS", "MGMT", "SERVERS", "allow", "tcp", []string{"22", "53", "80", "443"}, false, false)
	add("MGMT administration to INFRA", "MGMT", "INFRA", "allow", "tcp", []string{"22", "53", "80", "443"}, false, false)
	add("MGMT diagnostics to TRUSTED", "MGMT", "TRUSTED", "allow", "icmp", nil, false, false)
	add("SANDBOX Internet egress", "SANDBOX", "WAN", "allow", "any", nil, false, true)
	add("TRUSTED Internet egress", "TRUSTED", "WAN", "allow", "any", nil, false, true)
	add("SERVERS update egress", "SERVERS", "WAN", "allow", "tcp/udp", []string{"53", "80", "443", "853"}, false, true)
	add("INFRA update egress", "INFRA", "WAN", "allow", "tcp/udp", []string{"53", "80", "123", "853"}, false, true)
	add("MGMT update egress", "MGMT", "WAN", "allow", "tcp", []string{"443"}, false, true)
	for _, destination := range []string{"INFRA", "TRUSTED", "SERVERS", "SANDBOX", "MGMT", "Proxmox API", "SSH", "Internet"} {
		add("TRANSIT to "+destination+" deny", "TRANSIT", destination, "deny", "any", nil, true, false)
	}
	add("any to TRANSIT deny", "any", "TRANSIT", "deny", "any", nil, true, false)
	if tailnetExitNodeEnabled(s) {
		rules = append(rules, PolicyRule{
			Sequence: len(rules) + 1, Name: "tailnet-router Internet exit egress", From: "TRANSIT", To: "WAN", Action: "allow", Protocol: "any",
			Counter: "boetticher_tailnet_router_internet_exit_egress", NAT: true,
			Description: "tailnet-router opt-in Internet exit-node egress", SourceCIDR: "10.10.5.10/32", DestinationCIDR: "0.0.0.0/0",
		})
	}
	for _, declaration := range s.Declarations {
		for _, intent := range declaration.NetworkIntents {
			rule := policyRuleForIntent(s, declaration.Module, intent)
			if rule.Name != "" {
				rule.Sequence = len(rules) + 1
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

func tailnetExitNodeEnabled(s model.Site) bool {
	for _, declaration := range s.Declarations {
		if declaration.Module == "tailnet-router" {
			return declaration.ExitNode
		}
	}
	return false
}

func policyRuleForIntent(s model.Site, module string, intent model.NetworkIntent) PolicyRule {
	source, sourceOK := componentReference(s, intent.Source)
	if !sourceOK || (intent.Endpoint == "" && intent.Destination == "") {
		return PolicyRule{}
	}
	rule := PolicyRule{
		Name: "module " + module + " " + intent.Purpose,
		From: source.Zone, To: "WAN", Action: "allow", Protocol: intent.Protocol,
		Ports: append([]string(nil), intent.Ports...), Counter: "boetticher_module_" + safeRuleToken(module),
		Description: "module " + module + ": " + intent.Purpose,
		SourceCIDR:  source.Address + "/32",
	}
	if destination, ok := componentReference(s, intent.Destination); ok {
		rule.To = destination.Zone
		rule.DestinationCIDR = destination.Address + "/32"
	} else if intent.Endpoint != "" {
		parsed, err := url.Parse(intent.Endpoint)
		if err != nil || parsed.Hostname() == "" {
			return PolicyRule{}
		}
		rule.DestinationHost = parsed.Hostname()
	} else {
		return PolicyRule{}
	}
	if rule.To == "" || rule.From == "" {
		return PolicyRule{}
	}
	return rule
}

func componentReference(s model.Site, reference string) (model.Component, bool) {
	reference = strings.TrimSuffix(strings.ToLower(reference), ".")
	domain := strings.TrimSuffix(strings.ToLower(s.Network.Domain), ".")
	for _, component := range s.PlatformComponents() {
		identities := []string{component.Name, component.Hostname}
		identities = append(identities, component.DNSAliases...)
		for _, identity := range identities {
			identity = strings.TrimSuffix(strings.ToLower(identity), ".")
			if identity == reference || (domain != "" && identity+"."+domain == reference) {
				return component, true
			}
		}
	}
	return model.Component{}, false
}

func safeRuleToken(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(value)
}

func nftPortSet(ports []string) string {
	if len(ports) == 1 {
		return ports[0]
	}
	return "{ " + strings.Join(ports, ", ") + " }"
}

func RenderNFT(plan Plan) (string, error) {
	if plan.Mode != model.GatewayModeManaged {
		return "", errors.New("nftables is only rendered for managed gateway mode")
	}
	if len(plan.Interfaces) != 7 {
		return "", errors.New("managed gateway requires WAN plus six zone interfaces")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by boetticher. Model revision: %s\n", plan.ModelRevision)
	b.WriteString("destroy table inet " + FilterTable + "\n")
	b.WriteString("destroy table ip " + NATTable + "\n\n")
	b.WriteString("table inet " + FilterTable + " {\n")
	for _, zone := range []string{"INFRA", "TRUSTED", "SERVERS", "SANDBOX", "MGMT", "TRANSIT"} {
		fmt.Fprintf(&b, "  set %s_net { type ipv4_addr; flags interval; elements = { %s } }\n", strings.ToLower(zone), networkFor(plan, zone))
	}
	if sources := moduleGuestSources(plan); len(sources) > 0 {
		fmt.Fprintf(&b, "  set module_guest_sources { type ipv4_addr; elements = { %s } }\n", strings.Join(sources, ", "))
	}
	b.WriteString("  chain input {\n    type filter hook input priority filter; policy drop;\n    iifname \"lo\" accept comment \"boetticher:input-loopback\"\n    ct state established,related accept comment \"boetticher:input-established\"\n    iifname \"wan0\" udp sport 67 udp dport 68 accept comment \"boetticher:input-wan-dhcp\"\n    iifname { \"infra0\", \"trusted0\", \"servers0\", \"sandbox0\", \"mgmt0\" } ip protocol icmp icmp type echo-request counter accept comment \"boetticher:input-diagnostic-icmp\"\n    iifname { \"trusted0\", \"servers0\", \"sandbox0\" } udp dport 67 counter accept comment \"boetticher:input-zone-dhcp\"\n    iifname \"sandbox0\" udp dport 53 counter accept comment \"boetticher:input-sandbox-dns-udp\"\n    iifname \"sandbox0\" tcp dport 53 counter accept comment \"boetticher:input-sandbox-dns-tcp\"\n    iifname \"sandbox0\" udp dport 123 counter accept comment \"boetticher:input-sandbox-ntp\"\n    iifname \"mgmt0\" tcp dport 22 counter accept comment \"boetticher:input-mgmt-ssh\"\n  }\n")
	b.WriteString("  chain forward {\n    type filter hook forward priority filter; policy drop;\n    ct state established,related accept comment \"boetticher:forward-established\"\n")
	for _, rule := range plan.Rules {
		if rule.Action != "allow" || rule.SourceCIDR == "" || (rule.DestinationCIDR == "" && rule.DestinationHost == "") || rule.From == "" || rule.To == "" {
			continue
		}
		sourceIface := strings.ToLower(rule.From) + "0"
		destinationIface := strings.ToLower(rule.To) + "0"
		if rule.To == "WAN" {
			destinationIface = "wan0"
		}
		if sourceIface == "any0" || destinationIface == "gateway0" {
			continue
		}
		destination := rule.DestinationCIDR
		if destination == "" {
			destination = rule.DestinationHost
		}
		ports := ""
		if len(rule.Ports) > 0 {
			ports = " dport " + nftPortSet(rule.Ports)
		}
		protocols := []string{rule.Protocol}
		if rule.Protocol == "tcp/udp" {
			protocols = []string{"tcp", "udp"}
		}
		for _, protocol := range protocols {
			protocolText := ""
			switch protocol {
			case "tcp", "udp":
				protocolText = " " + protocol + ports
			case "icmp":
				protocolText = " ip protocol icmp"
			}
			fmt.Fprintf(&b, "    iifname \"%s\" oifname \"%s\" ip saddr %s ip daddr %s%s counter accept comment \"boetticher:module-%s\"\n", sourceIface, destinationIface, rule.SourceCIDR, destination, protocolText, safeRuleToken(rule.Name))
		}
	}
	for _, rule := range plan.Rules {
		if rule.Action == "allow" && rule.To == "WAN" && rule.SourceCIDR != "" && rule.DestinationCIDR != "0.0.0.0/0" {
			fmt.Fprintf(&b, "    iifname \"%s\" oifname \"wan0\" ip saddr %s counter drop comment \"boetticher:module-%s-arbitrary-egress-drop\"\n", strings.ToLower(rule.From)+"0", rule.SourceCIDR, safeRuleToken(rule.Name))
		}
	}
	for _, deny := range []struct{ zone, set, label string }{{"sandbox0", "trusted_net", "SANDBOX-TRUSTED-DROP"}, {"sandbox0", "servers_net", "SANDBOX-SERVERS-DROP"}, {"sandbox0", "infra_net", "SANDBOX-INFRA-DROP"}, {"sandbox0", "mgmt_net", "SANDBOX-MGMT-DROP"}} {
		fmt.Fprintf(&b, "    iifname \"%s\" ip daddr @%s counter log prefix \"boetticher %s \" drop comment \"boetticher:forward-%s\"\n", deny.zone, deny.set, deny.label, strings.ToLower(strings.ReplaceAll(deny.label, "-", "-")))
	}
	for _, deny := range []struct{ set, label string }{{"infra_net", "TRANSIT-INFRA-DROP"}, {"trusted_net", "TRANSIT-TRUSTED-DROP"}, {"servers_net", "TRANSIT-SERVERS-DROP"}, {"sandbox_net", "TRANSIT-SANDBOX-DROP"}, {"mgmt_net", "TRANSIT-MGMT-DROP"}} {
		fmt.Fprintf(&b, "    iifname \"transit0\" ip daddr @%s counter log prefix \"boetticher %s \" drop comment \"boetticher:forward-%s\"\n", deny.set, deny.label, strings.ToLower(deny.label))
	}
	b.WriteString("    iifname \"transit0\" tcp dport { 22, 8006 } counter log prefix \"boetticher TRANSIT-ADMIN-DROP \" drop comment \"boetticher:forward-transit-admin-drop\"\n")
	b.WriteString("    iifname \"transit0\" oifname \"wan0\" counter log prefix \"boetticher TRANSIT-INTERNET-DROP \" drop comment \"boetticher:forward-transit-internet-drop\"\n")
	b.WriteString("    ip daddr @transit_net counter log prefix \"boetticher TO-TRANSIT-DROP \" drop comment \"boetticher:forward-to-transit-drop\"\n")
	// The state rule above is deliberately the first forward rule after the
	// chain declaration. It keeps return traffic working without weakening the
	// ordered SANDBOX deny rules below.
	moduleSourceCondition := moduleSourceCondition(plan)
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @servers_net tcp dport { 53, 443 } counter accept comment \"boetticher:forward-trusted-servers-tcp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-trusted-servers-udp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @infra_net tcp dport { 53, 443 } counter accept comment \"boetticher:forward-trusted-infra-tcp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @infra_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-trusted-infra-udp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @mgmt_net tcp dport { 22, 443, 8006 } counter accept comment \"boetticher:forward-trusted-mgmt\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @infra_net tcp dport 53 counter accept comment \"boetticher:forward-servers-infra-tcp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @infra_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-servers-infra-udp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @servers_net tcp dport 53 counter accept comment \"boetticher:forward-servers-dns-tcp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-servers-dns-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @infra_net tcp dport { 22, 53, 80, 443 } counter accept comment \"boetticher:forward-mgmt-infra-tcp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @infra_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-mgmt-infra-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @servers_net tcp dport { 22, 53, 80, 443 } counter accept comment \"boetticher:forward-mgmt-servers-tcp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:forward-mgmt-servers-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @trusted_net ip protocol icmp counter accept comment \"boetticher:forward-mgmt-trusted-icmp\"\n")
	b.WriteString("    iifname \"sandbox0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @sandbox_net counter accept comment \"boetticher:forward-sandbox-internet\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @trusted_net counter accept comment \"boetticher:forward-trusted-internet\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @servers_net tcp dport { 53, 80, 443, 853 } counter accept comment \"boetticher:forward-servers-internet-tcp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @servers_net udp dport { 53, 853 } counter accept comment \"boetticher:forward-servers-internet-udp\"\n")
	b.WriteString("    iifname \"infra0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @infra_net tcp dport { 53, 80, 443, 853 } counter accept comment \"boetticher:forward-infra-internet-tcp\"\n")
	b.WriteString("    iifname \"infra0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @infra_net udp dport { 53, 123, 853 } counter accept comment \"boetticher:forward-infra-internet-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @mgmt_net tcp dport 443 counter accept comment \"boetticher:forward-mgmt-internet\"\n")
	b.WriteString("  }\n  chain output { type filter hook output priority filter; policy accept; }\n}\n\n")
	b.WriteString("table ip " + NATTable + " {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"wan0\" ip saddr " + networkFor(plan, "TRUSTED") + " masquerade comment \"boetticher:nat-trusted\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "SERVERS") + " masquerade comment \"boetticher:nat-servers\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "INFRA") + " masquerade comment \"boetticher:nat-infra\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "SANDBOX") + " masquerade comment \"boetticher:nat-sandbox\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "MGMT") + " masquerade comment \"boetticher:nat-mgmt\"\n")
	if plan.TailnetExitNode {
		// The gateway NAT is required for the exit node's TRANSIT address to
		// leave the site through the upstream router.
		b.WriteString("    oifname \"wan0\" ip saddr 10.10.5.10/32 masquerade comment \"boetticher:nat-tailnet-exit\"\n")
	}
	b.WriteString("  }\n}\n")
	return b.String(), nil
}

func moduleGuestSources(plan Plan) []string {
	seen := map[string]bool{}
	for _, cidr := range plan.ModuleSources {
		address := strings.TrimSuffix(cidr, "/32")
		if net.ParseIP(address) != nil {
			seen[address] = true
		}
	}
	result := make([]string, 0, len(seen))
	for address := range seen {
		result = append(result, address)
	}
	sort.Strings(result)
	return result
}

func moduleSourceCondition(plan Plan) string {
	if len(moduleGuestSources(plan)) == 0 {
		return ""
	}
	return "ip saddr != @module_guest_sources "
}

func networkFor(plan Plan, zone string) string {
	for _, subnet := range plan.DHCP {
		if subnet.Zone == zone {
			return subnet.Network
		}
	}
	for _, iface := range plan.Interfaces {
		if iface.Role != zone {
			continue
		}
		_, network, err := net.ParseCIDR(iface.Address)
		if err == nil {
			return network.String()
		}
	}
	if zone == "TRANSIT" {
		return model.TransitNetwork
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
