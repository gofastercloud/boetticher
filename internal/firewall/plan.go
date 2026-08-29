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
	UserRuleID      string   `json:"user_rule_id,omitempty"`
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

type UpstreamObservation struct {
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
	Address   string `json:"address"`
	Gateway   string `json:"gateway"`
}

type PublishedService struct {
	Service          string `json:"service"`
	Protocol         string `json:"protocol"`
	Port             int    `json:"port"`
	Destination      string `json:"destination"`
	DestinationCIDR  string `json:"destination_cidr"`
	DestinationIface string `json:"destination_interface"`
}

type Plan struct {
	ModelRevision string               `json:"model_revision"`
	Mode          string               `json:"mode"`
	Engine        string               `json:"engine"`
	IPv4Only      bool                 `json:"ipv4_only"`
	Forwarding    bool                 `json:"forwarding_after_policy"`
	Interfaces    []Interface          `json:"interfaces"`
	Rules         []PolicyRule         `json:"rules"`
	ModuleSources []string             `json:"module_source_cidrs,omitempty"`
	DHCP          []DHCPSubnet         `json:"dhcp_subnets"`
	DDNS          dns.DDNSPlan         `json:"ddns"`
	Publications  []PublishedService   `json:"publications,omitempty"`
	Upstream      *UpstreamObservation `json:"upstream,omitempty"`
	Telemetry     TelemetryPlan        `json:"telemetry"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	s = s.Normalize()
	for _, userRule := range s.UserFirewallRules {
		if _, _, ok := userSelector(s, userRule.Source); !ok {
			return Plan{}, fmt.Errorf("HOLD: user firewall rule %s source %q cannot be rendered", userRule.ID, userRule.Source)
		}
		if _, _, ok := userSelector(s, userRule.Destination); !ok {
			return Plan{}, fmt.Errorf("HOLD: user firewall rule %s destination %q cannot be rendered", userRule.ID, userRule.Destination)
		}
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
	rules := policyRules(s)
	userRuleCount := 0
	for _, rule := range rules {
		if rule.UserRuleID != "" {
			userRuleCount++
		}
	}
	if userRuleCount != len(s.UserFirewallRules) {
		return Plan{}, fmt.Errorf("HOLD: %d persisted user firewall rule(s) cannot be rendered", len(s.UserFirewallRules)-userRuleCount)
	}
	plan := Plan{
		ModelRevision: revision,
		Mode:          s.Gateway.Mode,
		Engine:        engine,
		IPv4Only:      true,
		Forwarding:    s.Gateway.Mode == model.GatewayModeManaged,
		Telemetry:     DefaultTelemetryPlan(s.Gateway.Mode == model.GatewayModeManaged),
		Rules:         rules,
		ModuleSources: moduleSourceCIDRs(s),
		DHCP:          dhcpSubnets(s),
		DDNS:          dnsPlan.DDNS,
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		plan.Interfaces = gatewayInterfaces(s)
	}
	plan.Publications = publishedServices(s)
	return plan, nil
}

func PlanFromSiteWithUpstream(s model.Site, upstream UpstreamObservation) (Plan, error) {
	plan, err := PlanFromSite(s)
	if err != nil {
		return Plan{}, err
	}
	if err := ValidateUpstreamObservation(plan, upstream); err != nil {
		return Plan{}, err
	}
	plan.Upstream = &upstream
	return plan, nil
}

func publishedServices(s model.Site) []PublishedService {
	services := make([]PublishedService, 0, len(s.Gateway.Publish)*2)
	for _, publication := range s.Gateway.Publish {
		if publication.Service != "dns" {
			continue
		}
		for _, protocol := range []string{"tcp", "udp"} {
			services = append(services, PublishedService{
				Service: publication.Service, Protocol: protocol, Port: 53,
				Destination: "lab-dns-01", DestinationCIDR: "10.10.10.10/32", DestinationIface: "infra0",
			})
		}
	}
	return services
}

func ValidateUpstreamObservation(plan Plan, upstream UpstreamObservation) error {
	if upstream.Interface != "wan0" {
		return fmt.Errorf("upstream observation must identify wan0")
	}
	if len(plan.Interfaces) == 0 || plan.Interfaces[0].Name != "wan0" {
		return errors.New("managed gateway plan is missing wan0")
	}
	if !strings.EqualFold(upstream.MAC, plan.Interfaces[0].MAC) {
		return fmt.Errorf("upstream observation MAC %q does not match configured wan0 MAC", upstream.MAC)
	}
	if err := model.ValidateGatewayUpstreamMAC(upstream.MAC); err != nil {
		return err
	}
	address := net.ParseIP(strings.TrimSpace(strings.Split(upstream.Address, "/")[0])).To4()
	_, network, err := net.ParseCIDR(upstream.Address)
	if err != nil || address == nil || network == nil || network.IP.To4() == nil {
		return fmt.Errorf("upstream observation address %q is not an IPv4 CIDR", upstream.Address)
	}
	if address.String() != strings.Split(upstream.Address, "/")[0] {
		return fmt.Errorf("upstream observation address %q is not canonical IPv4", upstream.Address)
	}
	gateway := net.ParseIP(strings.TrimSpace(upstream.Gateway)).To4()
	if gateway == nil || !network.Contains(gateway) || gateway.Equal(address) {
		return fmt.Errorf("upstream observation gateway %q is not a distinct address on %s", upstream.Gateway, network.String())
	}
	for _, iface := range plan.Interfaces {
		if iface.Name == "wan0" {
			continue
		}
		_, internal, parseErr := net.ParseCIDR(iface.Address)
		if parseErr == nil && (internal.Contains(address) || network.Contains(internal.IP)) {
			return fmt.Errorf("upstream network %s overlaps internal interface %s", network.String(), iface.Name)
		}
	}
	return nil
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
	interfaces := []Interface{{Role: "WAN", Name: "wan0", MAC: s.Gateway.Upstream.MAC, Bridge: "vmbr0", Address: "dhcp", Method: "dhcp"}}
	// Keep the established interface/MAC identities stable. TRANSIT and INFRA
	// are permanent platform interfaces appended after the existing identities,
	// not module-created vNICs whose presence changes them.
	for _, zoneType := range []model.ZoneType{model.ZoneTypeTrusted, model.ZoneTypeServers, model.ZoneTypeSandbox, model.ZoneTypeManagement, model.ZoneTypeTransit, model.ZoneTypeInfrastructure} {
		zone, err := s.ZoneForType(zoneType)
		if err != nil {
			continue
		}
		interfaces = append(interfaces, Interface{
			Role: zone.Name, Name: strings.ToLower(zone.Name) + "0", MAC: model.GatewayInterfaceMAC(len(interfaces) + 1), Bridge: "vmbr1", VLAN: zone.VLAN,
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
	// The Proxmox host is the controlled SSH jump point for the isolated
	// TRANSIT appliance. Keep this management path narrower than the ordinary
	// MGMT rules: only the host's fixed management address may reach the
	// module's SSH port, and only while the module is declared.
	if tailnet, ok := componentReference(s, "lab-tailnet-01"); ok {
		rules = append(rules, PolicyRule{
			Sequence:        len(rules) + 1,
			Name:            "MGMT administration to tailnet-router",
			From:            "MGMT",
			To:              "TRANSIT",
			Action:          "allow",
			Protocol:        "tcp",
			Ports:           []string{"22"},
			Counter:         "boetticher_mgmt_administration_to_tailnet_router",
			Description:     "boetticher MGMT administration to tailnet-router",
			SourceCIDR:      model.ProxmoxManagementAddress + "/32",
			DestinationCIDR: tailnet.Address + "/32",
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
	userRules := append([]model.UserFirewallRule(nil), s.UserFirewallRules...)
	sort.Slice(userRules, func(i, j int) bool { return userRules[i].ID < userRules[j].ID })
	for _, user := range userRules {
		sourceZone, sourceCIDR, sourceOK := userSelector(s, user.Source)
		destinationZone, destinationCIDR, destinationOK := userSelector(s, user.Destination)
		if !sourceOK || !destinationOK {
			continue
		}
		rules = append(rules, PolicyRule{Sequence: len(rules) + 1, Name: "user-rule-" + user.ID, From: sourceZone, To: destinationZone, Action: "allow", Protocol: strings.ToLower(user.Protocol), Ports: append([]string(nil), user.Ports...), Counter: "boetticher_user_" + safeRuleToken(user.ID), Description: "user firewall rule " + user.ID, SourceCIDR: sourceCIDR, DestinationCIDR: destinationCIDR, UserRuleID: user.ID})
	}
	return rules
}

func userSelector(s model.Site, selector string) (string, string, bool) {
	selector = strings.ToUpper(strings.TrimSpace(selector))
	for _, zone := range s.Network.Zones {
		if selector == zone.Name {
			if zone.Type == model.ZoneTypeServers || zone.Type == model.ZoneTypeTrusted || zone.Type == model.ZoneTypeSandbox {
				return zone.Name, zone.Network, true
			}
			return "", "", false
		}
	}
	_, network, err := net.ParseCIDR(selector)
	if err != nil || network.IP.To4() == nil {
		return "", "", false
	}
	for _, zone := range s.Network.Zones {
		if zone.Type != model.ZoneTypeServers && zone.Type != model.ZoneTypeTrusted && zone.Type != model.ZoneTypeSandbox {
			continue
		}
		_, zoneNetwork, e := net.ParseCIDR(zone.Network)
		if e == nil && zoneNetwork.Contains(network.IP) {
			return zone.Name, network.String(), true
		}
	}
	return "", "", false
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
		rule.Name += " " + intent.Destination
	} else if intent.Endpoint != "" {
		parsed, err := url.Parse(intent.Endpoint)
		if err != nil || parsed.Hostname() == "" {
			return PolicyRule{}
		}
		rule.DestinationHost = parsed.Hostname()
		rule.Name += " " + intent.Destination
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
	var token strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			token.WriteRune(character)
		} else {
			token.WriteByte('_')
		}
	}
	result := token.String()
	if result == "" {
		return "rule"
	}
	if result[0] == '-' {
		result = "rule_" + result
	}
	if len(result) > 128 {
		result = result[:128]
	}
	return result
}

func nftPortSet(ports []string) string {
	if len(ports) == 1 {
		return ports[0]
	}
	return "{ " + strings.Join(ports, ", ") + " }"
}

// RenderSafeNFT emits the base policy while an optional publication remains
// inactive until a current upstream DHCP observation is available. This is
// used for projections and the first convergence pass; it never opens a
// broader forwarding path as a substitute for the observed lease.
func RenderSafeNFT(plan Plan) (string, error) {
	plan.Publications = nil
	plan.Upstream = nil
	return RenderNFT(plan)
}

func RenderNFT(plan Plan) (string, error) {
	return renderNFTWithResolver(plan, net.LookupIP)
}

type destinationHostSet struct {
	host      string
	setName   string
	addresses []string
}

func renderNFTWithResolver(plan Plan, lookup func(string) ([]net.IP, error)) (string, error) {
	if plan.Mode != model.GatewayModeManaged {
		return "", errors.New("nftables is only rendered for managed gateway mode")
	}
	if len(plan.Interfaces) != 7 {
		return "", errors.New("managed gateway requires WAN plus six zone interfaces")
	}
	if err := plan.Telemetry.Validate(); err != nil {
		return "", err
	}
	if !plan.Telemetry.Enabled {
		return "", errors.New("managed firewall telemetry is disabled")
	}
	if len(plan.Publications) > 0 {
		if plan.Upstream == nil {
			return "", errors.New("HOLD: published services require a current upstream DHCP observation")
		}
		if err := ValidateUpstreamObservation(plan, *plan.Upstream); err != nil {
			return "", fmt.Errorf("HOLD: validate upstream DHCP observation: %w", err)
		}
	}
	destinationSets, err := resolveDestinationHostSets(plan.Rules, lookup)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by boetticher. Model revision: %s\n", plan.ModelRevision)
	b.WriteString("destroy table inet " + FilterTable + "\n")
	b.WriteString("destroy table ip " + NATTable + "\n\n")
	b.WriteString("table inet " + FilterTable + " {\n")
	for _, zone := range []string{"INFRA", "TRUSTED", "SERVERS", "SANDBOX", "MGMT", "TRANSIT"} {
		fmt.Fprintf(&b, "  set %s_net { type ipv4_addr; flags interval; elements = { %s } }\n", strings.ToLower(zone), networkFor(plan, zone))
	}
	for _, destinationSet := range destinationSets {
		fmt.Fprintf(&b, "  set %s { type ipv4_addr; elements = { %s } }\n", destinationSet.setName, strings.Join(destinationSet.addresses, ", "))
	}
	if sources := moduleGuestSources(plan); len(sources) > 0 {
		fmt.Fprintf(&b, "  set module_guest_sources { type ipv4_addr; elements = { %s } }\n", strings.Join(sources, ", "))
	}
	telemetrySource := strings.TrimSuffix(plan.Telemetry.AllowedSources[0], "/32")
	b.WriteString("  chain input {\n    type filter hook input priority filter; policy drop;\n    iifname \"lo\" accept comment \"boetticher:input-loopback\"\n    ct state established,related accept comment \"boetticher:input-established\"\n    iifname \"wan0\" udp sport 67 udp dport 68 accept comment \"boetticher:input-wan-dhcp\"\n    iifname { \"infra0\", \"trusted0\", \"servers0\", \"sandbox0\", \"mgmt0\" } ip protocol icmp icmp type echo-request counter accept comment \"boetticher:allow:input-diagnostic-icmp\"\n    iifname { \"trusted0\", \"servers0\", \"sandbox0\" } udp dport 67 counter accept comment \"boetticher:allow:input-zone-dhcp\"\n    iifname \"sandbox0\" udp dport 53 counter accept comment \"boetticher:allow:input-sandbox-dns-udp\"\n    iifname \"sandbox0\" tcp dport 53 counter accept comment \"boetticher:allow:input-sandbox-dns-tcp\"\n    iifname \"sandbox0\" udp dport 123 counter accept comment \"boetticher:allow:input-sandbox-ntp\"\n    iifname \"mgmt0\" tcp dport 22 counter accept comment \"boetticher:allow:input-mgmt-ssh\"\n    iifname \"infra0\" ip saddr " + telemetrySource + " tcp dport 9765 counter accept comment \"boetticher:allow:input-firewall-telemetry\"\n  }\n")
	b.WriteString("  chain forward {\n    type filter hook forward priority filter; policy drop;\n    ct state established,related accept comment \"boetticher:forward-established\"\n")
	if plan.Upstream != nil {
		for _, publication := range plan.Publications {
			fmt.Fprintf(&b, "    iifname \"wan0\" oifname \"%s\" ip saddr %s ip daddr %s %s dport %d counter accept comment \"boetticher:publish-%s-%s\"\n", publication.DestinationIface, upstreamSourceCIDR(*plan.Upstream), publication.DestinationCIDR, publication.Protocol, publication.Port, safeRuleToken(publication.Service), publication.Protocol)
		}
	}
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
			destination = "@" + destinationHostSetName(destinationSets, rule.DestinationHost)
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
			comment := "boetticher:allow:module-" + safeRuleToken(rule.Name) + "-" + protocol
			if rule.UserRuleID != "" {
				comment = "boetticher:user-rule:" + rule.UserRuleID + ":" + protocol
			}
			fmt.Fprintf(&b, "    iifname \"%s\" oifname \"%s\" ip saddr %s ip daddr %s%s counter accept comment \"%s\"\n", sourceIface, destinationIface, rule.SourceCIDR, destination, protocolText, comment)
		}
	}
	for _, rule := range plan.Rules {
		if rule.Action == "allow" && rule.To == "WAN" && rule.SourceCIDR != "" {
			fmt.Fprintf(&b, "    iifname \"%s\" oifname \"wan0\" ip saddr %s counter drop comment \"boetticher:drop:module-%s-arbitrary-egress\"\n", strings.ToLower(rule.From)+"0", rule.SourceCIDR, safeRuleToken(rule.Name))
		}
	}
	for _, deny := range []struct{ zone, set, label string }{{"sandbox0", "trusted_net", "SANDBOX-TRUSTED-DROP"}, {"sandbox0", "servers_net", "SANDBOX-SERVERS-DROP"}, {"sandbox0", "infra_net", "SANDBOX-INFRA-DROP"}, {"sandbox0", "mgmt_net", "SANDBOX-MGMT-DROP"}} {
		fmt.Fprintf(&b, "    iifname \"%s\" ip daddr @%s counter log prefix \"boetticher %s \" drop comment \"boetticher:drop:forward-%s\"\n", deny.zone, deny.set, deny.label, strings.ToLower(deny.label))
	}
	for _, deny := range []struct{ set, label string }{{"infra_net", "TRANSIT-INFRA-DROP"}, {"trusted_net", "TRANSIT-TRUSTED-DROP"}, {"servers_net", "TRANSIT-SERVERS-DROP"}, {"sandbox_net", "TRANSIT-SANDBOX-DROP"}, {"mgmt_net", "TRANSIT-MGMT-DROP"}} {
		fmt.Fprintf(&b, "    iifname \"transit0\" ip daddr @%s counter log prefix \"boetticher %s \" drop comment \"boetticher:drop:forward-%s\"\n", deny.set, deny.label, strings.ToLower(deny.label))
	}
	b.WriteString("    iifname \"transit0\" tcp dport { 22, 8006 } counter log prefix \"boetticher TRANSIT-ADMIN-DROP \" drop comment \"boetticher:drop:forward-transit-admin\"\n")
	b.WriteString("    iifname \"transit0\" oifname \"wan0\" counter log prefix \"boetticher TRANSIT-INTERNET-DROP \" drop comment \"boetticher:drop:forward-transit-internet\"\n")
	b.WriteString("    ip daddr @transit_net counter log prefix \"boetticher TO-TRANSIT-DROP \" drop comment \"boetticher:drop:forward-to-transit\"\n")
	// The state rule above is deliberately the first forward rule after the
	// chain declaration. It keeps return traffic working without weakening the
	// ordered SANDBOX deny rules below.
	moduleSourceCondition := moduleSourceCondition(plan)
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @servers_net tcp dport { 53, 443 } counter accept comment \"boetticher:allow:forward-trusted-servers-tcp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:allow:forward-trusted-servers-udp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @infra_net tcp dport { 53, 443 } counter accept comment \"boetticher:allow:forward-trusted-infra-tcp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @infra_net udp dport { 53, 123 } counter accept comment \"boetticher:allow:forward-trusted-infra-udp\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "ip daddr @mgmt_net tcp dport { 22, 443, 8006 } counter accept comment \"boetticher:allow:forward-trusted-mgmt\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @infra_net tcp dport 53 counter accept comment \"boetticher:allow:forward-servers-infra-tcp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @infra_net udp dport { 53, 123 } counter accept comment \"boetticher:allow:forward-servers-infra-udp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @servers_net tcp dport 53 counter accept comment \"boetticher:allow:forward-servers-dns-tcp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:allow:forward-servers-dns-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @infra_net tcp dport { 22, 53, 80, 443 } counter accept comment \"boetticher:allow:forward-mgmt-infra-tcp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @infra_net udp dport { 53, 123 } counter accept comment \"boetticher:allow:forward-mgmt-infra-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @servers_net tcp dport { 22, 53, 80, 443 } counter accept comment \"boetticher:allow:forward-mgmt-servers-tcp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @servers_net udp dport { 53, 123 } counter accept comment \"boetticher:allow:forward-mgmt-servers-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "ip daddr @trusted_net ip protocol icmp counter accept comment \"boetticher:allow:forward-mgmt-trusted-icmp\"\n")
	b.WriteString("    iifname \"sandbox0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @sandbox_net counter accept comment \"boetticher:allow:forward-sandbox-internet\"\n")
	b.WriteString("    iifname \"trusted0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @trusted_net counter accept comment \"boetticher:allow:forward-trusted-internet\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @servers_net tcp dport { 53, 80, 443, 853 } counter accept comment \"boetticher:allow:forward-servers-internet-tcp\"\n")
	b.WriteString("    iifname \"servers0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @servers_net udp dport { 53, 853 } counter accept comment \"boetticher:allow:forward-servers-internet-udp\"\n")
	b.WriteString("    iifname \"infra0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @infra_net tcp dport { 53, 80, 443, 853 } counter accept comment \"boetticher:allow:forward-infra-internet-tcp\"\n")
	b.WriteString("    iifname \"infra0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @infra_net udp dport { 53, 123, 853 } counter accept comment \"boetticher:allow:forward-infra-internet-udp\"\n")
	b.WriteString("    iifname \"mgmt0\" " + moduleSourceCondition + "oifname \"wan0\" ip saddr @mgmt_net tcp dport 443 counter accept comment \"boetticher:allow:forward-mgmt-internet\"\n")
	b.WriteString("  }\n  chain output { type filter hook output priority filter; policy accept; }\n}\n\n")
	b.WriteString("table ip " + NATTable + " {\n")
	if plan.Upstream != nil {
		b.WriteString("  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
		for _, publication := range plan.Publications {
			fmt.Fprintf(&b, "    iifname \"wan0\" ip saddr %s ip daddr %s %s dport %d dnat to %s:%d comment \"boetticher:publish-%s-%s-dnat\"\n", upstreamSourceCIDR(*plan.Upstream), upstreamAddress(*plan.Upstream), publication.Protocol, publication.Port, strings.TrimSuffix(publication.DestinationCIDR, "/32"), publication.Port, safeRuleToken(publication.Service), publication.Protocol)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"wan0\" ip saddr " + networkFor(plan, "TRUSTED") + " masquerade comment \"boetticher:nat-trusted\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "SERVERS") + " masquerade comment \"boetticher:nat-servers\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "INFRA") + " masquerade comment \"boetticher:nat-infra\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "SANDBOX") + " masquerade comment \"boetticher:nat-sandbox\"\n    oifname \"wan0\" ip saddr " + networkFor(plan, "MGMT") + " masquerade comment \"boetticher:nat-mgmt\"\n  }\n}\n")
	return b.String(), nil
}

func resolveDestinationHostSets(rules []PolicyRule, lookup func(string) ([]net.IP, error)) ([]destinationHostSet, error) {
	if lookup == nil {
		return nil, errors.New("HOLD: endpoint address resolver is unavailable")
	}
	hosts := map[string]struct{}{}
	for _, rule := range rules {
		if rule.Action == "allow" && rule.SourceCIDR != "" && rule.DestinationCIDR == "" && rule.DestinationHost != "" {
			hosts[rule.DestinationHost] = struct{}{}
		}
	}
	orderedHosts := make([]string, 0, len(hosts))
	for host := range hosts {
		orderedHosts = append(orderedHosts, host)
	}
	sort.Strings(orderedHosts)
	result := make([]destinationHostSet, 0, len(orderedHosts))
	for index, host := range orderedHosts {
		ips, err := lookup(host)
		if err != nil {
			return nil, fmt.Errorf("HOLD: resolve endpoint %s: %w", host, err)
		}
		seen := map[string]struct{}{}
		addresses := make([]string, 0, len(ips))
		for _, ip := range ips {
			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			address := ipv4.String()
			if _, ok := seen[address]; ok {
				continue
			}
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("HOLD: resolve endpoint %s: no IPv4 addresses", host)
		}
		sort.Strings(addresses)
		result = append(result, destinationHostSet{host: host, setName: fmt.Sprintf("boetticher_endpoint_%d", index), addresses: addresses})
	}
	return result, nil
}

func destinationHostSetName(sets []destinationHostSet, host string) string {
	for _, destinationSet := range sets {
		if destinationSet.host == host {
			return destinationSet.setName
		}
	}
	return "boetticher_endpoint_unresolved"
}

func upstreamAddress(upstream UpstreamObservation) string {
	return strings.Split(upstream.Address, "/")[0]
}

func upstreamSourceCIDR(upstream UpstreamObservation) string {
	_, network, err := net.ParseCIDR(upstream.Address)
	if err != nil || network == nil {
		return "0.0.0.0/32"
	}
	return network.String()
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
