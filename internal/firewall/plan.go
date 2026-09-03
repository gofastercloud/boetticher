package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
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

type InterfaceConfigurationDigest struct {
	Link    string `json:"link"`
	Network string `json:"network"`
}

// GatewayInterfaceConfigurationDigests returns the checksums of the two
// systemd-networkd files rendered for each managed gateway interface. The
// Ansible role uses these values for one cheap live drift probe before it
// invokes the slower template modules.
func GatewayInterfaceConfigurationDigests(plan Plan) map[string]InterfaceConfigurationDigest {
	result := make(map[string]InterfaceConfigurationDigest, len(plan.Interfaces))
	for _, iface := range plan.Interfaces {
		link := fmt.Sprintf("[Match]\nMACAddress=%s\n\n[Link]\nName=%s\n", iface.MAC, iface.Name)
		network := fmt.Sprintf("[Match]\nName=%s\n\n[Network]\n", iface.Name)
		if iface.Method == "dhcp" {
			network += "DHCP=ipv4\n"
		} else {
			network += fmt.Sprintf("Address=%s\n", iface.Address)
		}
		network += "IPv6AcceptRA=no\nLinkLocalAddressing=no\n"
		result[iface.Name] = InterfaceConfigurationDigest{Link: sha256Hex(link), Network: sha256Hex(network)}
	}
	return result
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// RulesetDigest returns the stable content digest used by the convergence
// role to avoid transferring and validating an unchanged nftables artifact.
// The live ruleset is still applied on every convergence so this digest is a
// transfer optimization, not a substitute for runtime activation.
func RulesetDigest(ruleset string) string {
	return sha256Hex(ruleset)
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
	Route           string   `json:"route,omitempty"`
	Description     string   `json:"description"`
	SourceCIDR      string   `json:"source_cidr,omitempty"`
	DestinationCIDR string   `json:"destination_cidr,omitempty"`
	DestinationHost string   `json:"destination_host,omitempty"`
	SourceMAC       string   `json:"source_mac,omitempty"`
	UserRuleID      string   `json:"user_rule_id,omitempty"`
}

// AirVPNProfile is the non-secret portion of the retained provider profile.
// The private key and the normalized WireGuard configuration never enter a
// firewall plan.
type AirVPNProfile struct {
	EndpointHost      string   `json:"endpoint_host"`
	EndpointPort      int      `json:"endpoint_port"`
	TunnelAddress     string   `json:"tunnel_address"`
	EndpointAddresses []string `json:"endpoint_addresses,omitempty"`
	SHA256            string   `json:"sha256"`
}

type PolicyRoute struct {
	SourceCIDR       string             `json:"source_cidr"`
	Table            int                `json:"table"`
	Priority         int                `json:"priority"`
	DefaultGateway   string             `json:"default_gateway"`
	DefaultInterface string             `json:"default_interface"`
	InternalRoutes   []PolicyRouteEntry `json:"internal_routes"`
}

type PolicyRouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface"`
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
	AirVPNSources []string             `json:"airvpn_source_cidrs,omitempty"`
	PolicyRoutes  []PolicyRoute        `json:"policy_routes,omitempty"`
	AirVPN        *AirVPNProfile       `json:"airvpn,omitempty"`
	DHCP          []DHCPSubnet         `json:"dhcp_subnets"`
	DDNS          dns.DDNSPlan         `json:"ddns"`
	Publications  []PublishedService   `json:"publications,omitempty"`
	Upstream      *UpstreamObservation `json:"upstream,omitempty"`
	Telemetry     TelemetryPlan        `json:"telemetry"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	return planFromSite(s, nil)
}

func PlanFromSiteWithAirVPN(s model.Site, profile AirVPNProfile) (Plan, error) {
	return planFromSite(s, &profile)
}

// BindAirVPNEndpoint resolves the provider endpoint into the runtime-only
// metadata consumed by gateway and guest firewall renderers.
func BindAirVPNEndpoint(plan Plan, lookup func(string) ([]net.IP, error)) (Plan, error) {
	if plan.AirVPN == nil {
		return plan, nil
	}
	if lookup == nil {
		return Plan{}, errors.New("HOLD: AirVPN endpoint resolver is unavailable")
	}
	ips, err := lookup(plan.AirVPN.EndpointHost)
	if err != nil {
		return Plan{}, fmt.Errorf("HOLD: resolve AirVPN provider endpoint: %w", err)
	}
	seen := map[string]bool{}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil && !seen[ipv4.String()] {
			seen[ipv4.String()] = true
			addresses = append(addresses, ipv4.String())
		}
	}
	if len(addresses) == 0 {
		return Plan{}, errors.New("HOLD: AirVPN provider endpoint has no IPv4 address")
	}
	sort.Strings(addresses)
	plan.AirVPN.EndpointAddresses = addresses
	return plan, nil
}

func PlanFromSiteWithUpstreamAndAirVPN(s model.Site, upstream UpstreamObservation, profile AirVPNProfile) (Plan, error) {
	plan, err := planFromSite(s, &profile)
	if err != nil {
		return Plan{}, err
	}
	if err := ValidateUpstreamObservation(plan, upstream); err != nil {
		return Plan{}, err
	}
	plan.Upstream = &upstream
	return plan, nil
}

func planFromSite(s model.Site, airvpnProfile *AirVPNProfile) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	s = s.Normalize()
	for _, userRule := range s.UserFirewallRules {
		if _, _, ok := userSelector(s, userRule.Source); !ok {
			return Plan{}, fmt.Errorf("HOLD: user firewall rule %s source %q cannot be rendered", userRule.ID, userRule.Source)
		}
		if _, _, ok := userRuleDestinationSelector(s, userRule); !ok {
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
	if airvpnProfile != nil {
		if err := validateAirVPNProfile(*airvpnProfile); err != nil {
			return Plan{}, err
		}
		rules = append(rules, PolicyRule{
			Sequence:        len(rules) + 1,
			Name:            "AirVPN provider WireGuard handshake",
			From:            "TRANSIT",
			To:              "WAN",
			Action:          "allow",
			Protocol:        "udp",
			Ports:           []string{strconv.Itoa(airvpnProfile.EndpointPort)},
			Counter:         "boetticher_airvpn_provider_handshake",
			NAT:             true,
			Route:           "direct",
			Description:     "boetticher AirVPN provider WireGuard handshake only",
			SourceCIDR:      model.AirVPNGuestAddress + "/32",
			DestinationHost: airvpnProfile.EndpointHost,
		})
	}
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
		AirVPNSources: airVPNSources(s),
		PolicyRoutes:  policyRoutes(s),
		DHCP:          dhcpSubnets(s),
		DDNS:          dnsPlan.DDNS,
	}
	if airvpnProfile != nil {
		plan.AirVPN = airvpnProfile
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

func validateAirVPNProfile(profile AirVPNProfile) error {
	if !validAirVPNEndpointHost(profile.EndpointHost) || profile.EndpointPort != 1637 {
		return errors.New("HOLD: AirVPN firewall metadata has an invalid provider endpoint")
	}
	if address := net.ParseIP(profile.TunnelAddress); address == nil || address.To4() == nil {
		return errors.New("HOLD: AirVPN firewall metadata has an invalid tunnel address")
	}
	if len(profile.SHA256) != 64 {
		return errors.New("HOLD: AirVPN firewall metadata is missing the profile digest")
	}
	for _, character := range profile.SHA256 {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F') {
			return errors.New("HOLD: AirVPN firewall metadata has an invalid profile digest")
		}
	}
	return nil
}

func validAirVPNEndpointHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\") {
		return false
	}
	if address := net.ParseIP(host); address != nil {
		return address.To4() != nil
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
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
	for _, cidr := range airVPNSources(s) {
		seen[cidr] = true
	}
	result := make([]string, 0, len(seen))
	for cidr := range seen {
		result = append(result, cidr)
	}
	sort.Strings(result)
	return result
}

func airVPNSources(s model.Site) []string {
	seen := map[string]bool{}
	for _, component := range s.PlatformComponents() {
		config, ok := s.ModuleConfig[component.Module]
		if !ok || config.Network != model.ModuleNetworkAirVPN {
			continue
		}
		if address := net.ParseIP(component.Address).To4(); address != nil {
			seen[address.String()+"/32"] = true
		}
	}
	result := make([]string, 0, len(seen))
	for cidr := range seen {
		result = append(result, cidr)
	}
	sort.Strings(result)
	return result
}

func policyRoutes(s model.Site) []PolicyRoute {
	sources := airVPNSources(s)
	if len(sources) == 0 {
		return nil
	}
	zones := append([]model.Zone(nil), s.Normalize().Network.Zones...)
	sort.Slice(zones, func(i, j int) bool { return zones[i].VLAN < zones[j].VLAN })
	routes := make([]PolicyRouteEntry, 0, len(zones))
	for _, zone := range zones {
		entry := PolicyRouteEntry{Destination: zone.Network, Interface: strings.ToLower(zone.Name) + "0"}
		if zone.Type != model.ZoneTypeTransit {
			entry.Gateway = zone.Gateway
		}
		routes = append(routes, entry)
	}
	result := make([]PolicyRoute, 0, len(sources))
	for index, source := range sources {
		result = append(result, PolicyRoute{
			SourceCIDR:       source,
			Table:            51820,
			Priority:         10000 + index,
			DefaultGateway:   model.AirVPNGuestAddress,
			DefaultInterface: "transit0",
			InternalRoutes:   append([]PolicyRouteEntry(nil), routes...),
		})
	}
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
	// Pulse is a Core service protected by the endpoint's mTLS boundary. Allow
	// the modeled client zones to reach only the fixed Pulse HTTPS address;
	// source-zone selectors keep this useful for operators without granting
	// access to the rest of INFRA.
	if monitor, ok := componentReference(s, "monitor"); ok && monitor.Module == "monitoring" && monitor.Address != "" {
		for _, source := range []string{"TRANSIT", "SERVERS", "TRUSTED"} {
			for _, zone := range s.Network.Zones {
				if zone.Name != source {
					continue
				}
				rules = append(rules, PolicyRule{
					Sequence:        len(rules) + 1,
					Name:            source + " HTTPS to Pulse",
					From:            source,
					To:              "INFRA",
					Action:          "allow",
					Protocol:        "tcp",
					Ports:           []string{"443"},
					Counter:         "boetticher_" + strings.ToLower(source) + "_https_to_pulse",
					Description:     "boetticher " + source + " HTTPS to Pulse",
					SourceCIDR:      zone.Network,
					DestinationCIDR: monitor.Address + "/32",
				})
			}
		}
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
	// ARR is the one current module whose job includes arbitrary media
	// acquisition. Keep that egress bound to its fixed source, the TRANSIT
	// interface, and the AirVPN route; never turn a SERVERS-zone allowance into
	// a generic Internet escape hatch.
	if arr, ok := componentReference(s, "lab-arr-01"); ok && moduleNetworkMode(s, "arr") == model.ModuleNetworkAirVPN {
		rules = append(rules, PolicyRule{
			Sequence:        len(rules) + 1,
			Name:            "ARR media acquisition through AirVPN",
			From:            arr.Zone,
			To:              "TRANSIT",
			Action:          "allow",
			Protocol:        "any",
			Counter:         "boetticher_arr_airvpn_egress",
			Route:           "airvpn",
			Description:     "boetticher ARR media acquisition through AirVPN only",
			SourceCIDR:      arr.Address + "/32",
			SourceMAC:       arr.MAC,
			DestinationCIDR: "0.0.0.0/0",
		})
	}
	for _, declaration := range s.Declarations {
		for _, intent := range declaration.NetworkIntents {
			for _, rule := range policyRulesForIntent(s, declaration.Module, intent) {
				rule.Sequence = len(rules) + 1
				rules = append(rules, rule)
			}
		}
	}
	userRules := append([]model.UserFirewallRule(nil), s.UserFirewallRules...)
	sort.Slice(userRules, func(i, j int) bool { return userRules[i].ID < userRules[j].ID })
	for _, user := range userRules {
		sourceZone, sourceCIDR, sourceOK := userSelector(s, user.Source)
		destinationZone, destinationCIDR, destinationOK := userRuleDestinationSelector(s, user)
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

func userRuleDestinationSelector(s model.Site, rule model.UserFirewallRule) (string, string, bool) {
	if zone, cidr, ok := userSelector(s, rule.Destination); ok {
		return zone, cidr, true
	}
	if model.IsReservedServersPulseRule(s, rule.Source, rule.Destination, strings.ToLower(rule.Protocol), rule.Ports) {
		return "INFRA", rule.Destination, true
	}
	return "", "", false
}

func policyRuleForIntent(s model.Site, module string, intent model.NetworkIntent) PolicyRule {
	rules := policyRulesForIntent(s, module, intent)
	if len(rules) == 0 {
		return PolicyRule{}
	}
	return rules[0]
}

func policyRulesForIntent(s model.Site, module string, intent model.NetworkIntent) []PolicyRule {
	source, sourceOK := componentReference(s, intent.Source)
	if !sourceOK || (intent.Endpoint == "" && intent.Destination == "") {
		return nil
	}
	// An endpoint URL is external only when the logical destination is not an
	// existing site component. Product-owned checks may carry an HTTPS URL for
	// an internal service; those paths remain direct.
	if intent.Endpoint != "" && len(componentReferences(s, intent.Destination)) == 0 {
		parsed, err := url.Parse(intent.Endpoint)
		if err != nil || parsed.Hostname() == "" {
			return nil
		}
		to, route, nat := "WAN", "direct", true
		if moduleNetworkMode(s, module) == model.ModuleNetworkAirVPN {
			to, route, nat = "TRANSIT", "airvpn", false
		}
		return []PolicyRule{{
			Name: "module " + module + " " + intent.Purpose + " " + intent.Destination,
			From: source.Zone, To: to, Action: "allow", Protocol: intent.Protocol,
			Ports: append([]string(nil), intent.Ports...), Counter: "boetticher_module_" + safeRuleToken(module),
			NAT: nat, Route: route, Description: "module " + module + ": " + intent.Purpose,
			SourceCIDR: source.Address + "/32", DestinationHost: parsed.Hostname(),
		}}
	}
	destinations := componentReferences(s, intent.Destination)
	if len(destinations) == 0 {
		return nil
	}
	destinationLabel := intent.Destination
	rules := make([]PolicyRule, 0, len(destinations))
	for _, destination := range destinations {
		if len(destinations) > 1 {
			destinationLabel = destination.Name
		}
		rules = append(rules, PolicyRule{
			Name: "module " + module + " " + intent.Purpose + " " + destinationLabel,
			From: source.Zone, To: destination.Zone, Action: "allow", Protocol: intent.Protocol,
			Ports: append([]string(nil), intent.Ports...), Counter: "boetticher_module_" + safeRuleToken(module),
			Description: "module " + module + ": " + intent.Purpose,
			SourceCIDR:  source.Address + "/32", DestinationCIDR: destination.Address + "/32",
		})
	}
	return rules
}

func moduleNetworkMode(s model.Site, module string) model.ModuleNetworkMode {
	if config, ok := s.ModuleConfig[module]; ok && config.Network != "" {
		return config.Network
	}
	return model.ModuleNetworkDirect
}

// componentReferences expands logical service aliases that intentionally name
// a redundant platform service. In particular, "dns" means every managed DNS
// endpoint, while dns01 retains its single-component meaning.
func componentReferences(s model.Site, reference string) []model.Component {
	reference = strings.TrimSuffix(strings.ToLower(reference), ".")
	if reference == "dns" {
		var destinations []model.Component
		for _, component := range s.PlatformComponents() {
			if component.Module == "dns" {
				destinations = append(destinations, component)
			}
		}
		return destinations
	}
	if component, ok := componentReference(s, reference); ok {
		return []model.Component{component}
	}
	return nil
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

// RenderNFTWithResolver renders the managed policy using the supplied
// endpoint resolver. Deployment uses this to keep endpoint resolution inside
// an already-authenticated management path when the controller has no DNS
// configuration of its own.
func RenderNFTWithResolver(plan Plan, lookup func(string) ([]net.IP, error)) (string, error) {
	if lookup == nil {
		return "", errors.New("nftables endpoint resolver is required")
	}
	return renderNFTWithResolver(plan, lookup)
}

// RenderSafeNFTWithResolver emits the base policy while an optional
// publication remains inactive until a current upstream DHCP observation is
// available, using the supplied endpoint resolver.
func RenderSafeNFTWithResolver(plan Plan, lookup func(string) ([]net.IP, error)) (string, error) {
	plan.Publications = nil
	plan.Upstream = nil
	return RenderNFTWithResolver(plan, lookup)
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
	if len(plan.PolicyRoutes) > 0 && plan.AirVPN == nil {
		return "", errors.New("HOLD: AirVPN profile metadata is required for selected-source policy routing")
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
	if len(plan.AirVPNSources) > 0 {
		fmt.Fprintf(&b, "  set airvpn_sources { type ipv4_addr; elements = { %s } }\n", strings.Join(plan.AirVPNSources, ", "))
	}
	telemetrySource := strings.TrimSuffix(plan.Telemetry.AllowedSources[0], "/32")
	b.WriteString("  chain input {\n    type filter hook input priority filter; policy drop;\n    iifname \"lo\" accept comment \"boetticher:input-loopback\"\n    ct state established,related accept comment \"boetticher:input-established\"\n    iifname \"wan0\" udp sport 67 udp dport 68 accept comment \"boetticher:input-wan-dhcp\"\n    iifname { \"infra0\", \"trusted0\", \"servers0\", \"sandbox0\", \"mgmt0\" } ip protocol icmp icmp type echo-request counter accept comment \"boetticher:allow:input-diagnostic-icmp\"\n    iifname { \"trusted0\", \"servers0\", \"sandbox0\" } udp dport 67 counter accept comment \"boetticher:allow:input-zone-dhcp\"\n    iifname \"sandbox0\" udp dport 53 counter accept comment \"boetticher:allow:input-sandbox-dns-udp\"\n    iifname \"sandbox0\" tcp dport 53 counter accept comment \"boetticher:allow:input-sandbox-dns-tcp\"\n    iifname \"sandbox0\" udp dport 123 counter accept comment \"boetticher:allow:input-sandbox-ntp\"\n    iifname \"mgmt0\" tcp dport 22 counter accept comment \"boetticher:allow:input-mgmt-ssh\"\n    iifname \"infra0\" ip saddr " + telemetrySource + " tcp dport 9765 counter accept comment \"boetticher:allow:input-firewall-telemetry\"\n  }\n")
	b.WriteString("  chain forward {\n    type filter hook forward priority filter; policy drop;\n    ct state established,related accept comment \"boetticher:forward-established\"\n")
	if len(plan.AirVPNSources) > 0 {
		b.WriteString("    ip saddr @airvpn_sources oifname \"wan0\" counter log prefix \"boetticher AIRVPN-DIRECT-DROP \" drop comment \"boetticher:drop:airvpn-direct-wan\"\n")
	}
	if plan.Upstream != nil {
		for _, publication := range plan.Publications {
			fmt.Fprintf(&b, "    iifname \"wan0\" oifname \"%s\" ip saddr %s ip daddr %s %s dport %d counter accept comment \"boetticher:publish-%s-%s\"\n", publication.DestinationIface, upstreamSourceCIDR(*plan.Upstream), publication.DestinationCIDR, publication.Protocol, publication.Port, safeRuleToken(publication.Service), publication.Protocol)
		}
	}
	for _, rule := range plan.Rules {
		if rule.Action != "allow" || rule.SourceCIDR == "" || rule.From == "" || rule.To == "" {
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
		if rule.DestinationCIDR == "" && rule.DestinationHost == "" {
			continue
		}
		sourceMAC := ""
		if rule.SourceMAC != "" {
			parsedMAC, parseErr := net.ParseMAC(rule.SourceMAC)
			if parseErr != nil || len(parsedMAC) != 6 {
				return "", fmt.Errorf("firewall rule %s has an invalid source MAC", rule.Name)
			}
			sourceMAC = " ether saddr " + parsedMAC.String()
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
			fmt.Fprintf(&b, "    iifname \"%s\"%s oifname \"%s\" ip saddr %s ip daddr %s%s counter accept comment \"%s\"\n", sourceIface, sourceMAC, destinationIface, rule.SourceCIDR, destination, protocolText, comment)
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
	transitNATSources := make(map[string]struct{})
	for _, rule := range plan.Rules {
		if rule.Action == "allow" && rule.From == "TRANSIT" && rule.To == "WAN" && rule.SourceCIDR != "" {
			if plan.AirVPN != nil && rule.SourceCIDR == model.AirVPNGuestAddress+"/32" {
				continue
			}
			transitNATSources[rule.SourceCIDR] = struct{}{}
		}
	}
	transitNATSourceList := make([]string, 0, len(transitNATSources))
	for source := range transitNATSources {
		transitNATSourceList = append(transitNATSourceList, source)
	}
	sort.Strings(transitNATSourceList)
	b.WriteString("table ip " + NATTable + " {\n")
	if len(plan.AirVPNSources) > 0 {
		fmt.Fprintf(&b, "  set airvpn_sources { type ipv4_addr; elements = { %s } }\n", strings.Join(plan.AirVPNSources, ", "))
	}
	airvpnEndpointSet := ""
	if plan.AirVPN != nil {
		for _, destinationSet := range destinationSets {
			if destinationSet.host != plan.AirVPN.EndpointHost {
				continue
			}
			fmt.Fprintf(&b, "  set %s { type ipv4_addr; elements = { %s } }\n", destinationSet.setName, strings.Join(destinationSet.addresses, ", "))
			airvpnEndpointSet = destinationSet.setName
			break
		}
	}
	if plan.Upstream != nil {
		b.WriteString("  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
		for _, publication := range plan.Publications {
			fmt.Fprintf(&b, "    iifname \"wan0\" ip saddr %s ip daddr %s %s dport %d dnat to %s:%d comment \"boetticher:publish-%s-%s-dnat\"\n", upstreamSourceCIDR(*plan.Upstream), upstreamAddress(*plan.Upstream), publication.Protocol, publication.Port, strings.TrimSuffix(publication.DestinationCIDR, "/32"), publication.Port, safeRuleToken(publication.Service), publication.Protocol)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	if airvpnEndpointSet != "" {
		fmt.Fprintf(&b, "    oifname \"wan0\" ip saddr %s ip daddr @%s udp dport %d masquerade comment \"boetticher:nat-airvpn-handshake\"\n", model.AirVPNGuestAddress+"/32", airvpnEndpointSet, plan.AirVPN.EndpointPort)
	}
	for _, source := range transitNATSourceList {
		fmt.Fprintf(&b, "    oifname \"wan0\" ip saddr %s masquerade comment \"boetticher:nat-transit\"\n", source)
	}
	ordinaryNATSourceCondition := ""
	if len(plan.AirVPNSources) > 0 {
		ordinaryNATSourceCondition = "ip saddr != @airvpn_sources "
	}
	b.WriteString("    oifname \"wan0\" " + ordinaryNATSourceCondition + "ip saddr " + networkFor(plan, "TRUSTED") + " masquerade comment \"boetticher:nat-trusted\"\n    oifname \"wan0\" " + ordinaryNATSourceCondition + "ip saddr " + networkFor(plan, "SERVERS") + " masquerade comment \"boetticher:nat-servers\"\n    oifname \"wan0\" " + ordinaryNATSourceCondition + "ip saddr " + networkFor(plan, "INFRA") + " masquerade comment \"boetticher:nat-infra\"\n    oifname \"wan0\" " + ordinaryNATSourceCondition + "ip saddr " + networkFor(plan, "SANDBOX") + " masquerade comment \"boetticher:nat-sandbox\"\n    oifname \"wan0\" " + ordinaryNATSourceCondition + "ip saddr " + networkFor(plan, "MGMT") + " masquerade comment \"boetticher:nat-mgmt\"\n  }\n}\n")
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
			if ipv4.IsPrivate() || ipv4.IsLoopback() || ipv4.IsLinkLocalUnicast() || ipv4.IsUnspecified() || ipv4.IsMulticast() || !ipv4.IsGlobalUnicast() {
				return nil, fmt.Errorf("HOLD: endpoint %s resolved to a non-public IPv4 address", host)
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
