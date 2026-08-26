package opnsense

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	DHCPv4SubnetSearch = "/api/kea/dhcpv4/searchSubnet"
	DHCPv4SubnetAdd    = "/api/kea/dhcpv4/addSubnet"
	DHCPv4SubnetSet    = "/api/kea/dhcpv4/setSubnet"
	DHCPv4Reconfigure  = "/api/kea/service/reconfigure"
	DDNSGet            = "/api/kea/ddns/get"
	DDNSSet            = "/api/kea/ddns/set"
	VLANSearch         = "/api/interfaces/vlan_settings/searchItem"
	VLANAdd            = "/api/interfaces/vlan_settings/addItem"
	VLANReconfigure    = "/api/interfaces/vlan_settings/reconfigure"
	FirewallSearch     = "/api/firewall/filter/searchRule"
	FirewallAdd        = "/api/firewall/filter/addRule"
	FirewallSet        = "/api/firewall/filter/setRule"
	FirewallApply      = "/api/firewall/filter_base/apply"
)

type Plan struct {
	ModelRevision  string         `json:"model_revision"`
	Boundary       string         `json:"boundary"`
	IPv4Only       bool           `json:"ipv4_only"`
	InternalParent string         `json:"internal_parent"`
	AddressAliases []AddressAlias `json:"address_aliases"`
	VLANs          []VLANPlan     `json:"vlans"`
	Zones          []ZonePlan     `json:"zones"`
	FirewallRules  []FirewallRule `json:"firewall_rules"`
	DDNS           dns.DDNSPlan   `json:"ddns"`
}

type VLANPlan struct {
	Name        string `json:"name"`
	VLAN        int    `json:"vlan"`
	Parent      string `json:"parent"`
	Description string `json:"description"`
}

type ZonePlan struct {
	Name            string           `json:"name"`
	VLAN            int              `json:"vlan"`
	Network         string           `json:"network"`
	Gateway         string           `json:"gateway"`
	AddressMode     string           `json:"address_mode"`
	Pool            string           `json:"pool,omitempty"`
	DNSAddresses    []string         `json:"dns_addresses"`
	NTPAddresses    []string         `json:"ntp_addresses"`
	ClasslessRoutes []ClasslessRoute `json:"classless_routes,omitempty"`
}

type ClasslessRoute struct {
	Destination string `json:"destination"`
	Router      string `json:"router"`
}

type AddressAlias struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Values      []string `json:"values"`
	Description string   `json:"description"`
}

type FirewallRule struct {
	Sequence        int    `json:"sequence"`
	Description     string `json:"description"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	Action          string `json:"action"`
	Protocol        string `json:"protocol"`
	DestinationPort string `json:"destination_port,omitempty"`
	IPVersion       string `json:"ip_version"`
}

// PlanFromSite is the canonical, deterministic OPNsense projection. The
// default V1 DHCP contract intentionally uses ordinary gateway options. The
// SANDBOX /32 experiment is represented separately and is not enabled by
// default until cross-client qualification exists.
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
	zones := make([]ZonePlan, 0, len(s.Network.Zones))
	for _, zone := range s.Normalize().Network.Zones {
		plan := ZonePlan{
			Name:         zone.Name,
			VLAN:         zone.VLAN,
			Network:      zone.Network,
			Gateway:      zone.Gateway,
			AddressMode:  zone.AddressMode,
			DNSAddresses: append([]string(nil), zone.DNSAddresses...),
			NTPAddresses: append([]string(nil), zone.NTPAddresses...),
		}
		if zone.AddressMode != "reservations-only" {
			plan.Pool = poolForNetwork(zone.Network)
		}
		zones = append(zones, plan)
	}
	return Plan{
		ModelRevision:  revision,
		Boundary:       "opnsense",
		IPv4Only:       true,
		InternalParent: "vtnet1",
		AddressAliases: addressAliases(s),
		VLANs:          vlanPlans(s),
		Zones:          zones,
		FirewallRules:  firewallRules(s),
		DDNS:           dnsPlan.DDNS,
	}, nil
}

func vlanPlans(s model.Site) []VLANPlan {
	zones := append([]model.Zone(nil), s.Network.Zones...)
	sort.Slice(zones, func(i, j int) bool { return zones[i].VLAN < zones[j].VLAN })
	result := make([]VLANPlan, 0, len(zones))
	for _, zone := range zones {
		result = append(result, VLANPlan{Name: zone.Name, VLAN: zone.VLAN, Parent: "vtnet1", Description: "boetticher " + zone.Name})
	}
	return result
}

// ApplyVLANs uses the documented OPNsense VLAN model API. Interface address
// assignment remains a separately qualified transition because changing it
// can interrupt the only management path during bootstrap.
func (c *Client) ApplyVLANs(ctx context.Context, plan Plan) error {
	for _, desired := range plan.VLANs {
		var search struct {
			Rows []struct {
				UUID string `json:"uuid"`
				If   string `json:"if"`
				Tag  string `json:"tag"`
			} `json:"rows"`
		}
		if err := c.Post(ctx, VLANSearch, map[string]any{
			"current": 1, "rowCount": 100, "sort": map[string]any{}, "searchPhrase": desired.Description,
		}, &search); err != nil {
			return fmt.Errorf("search OPNsense VLAN %s: %w", desired.Name, err)
		}
		payload := map[string]any{"vlan": map[string]any{
			"if": desired.Parent, "tag": desired.VLAN, "descr": desired.Description,
		}}
		if len(search.Rows) == 0 {
			if err := c.Post(ctx, VLANAdd, payload, nil); err != nil {
				return fmt.Errorf("add OPNsense VLAN %s: %w", desired.Name, err)
			}
			continue
		}
		row := search.Rows[0]
		if row.UUID == "" {
			return fmt.Errorf("OPNsense returned a VLAN without a UUID for %s", desired.Name)
		}
		if row.If != "" && row.If != desired.Parent {
			return fmt.Errorf("OPNsense VLAN %s has parent %q, expected %q", desired.Name, row.If, desired.Parent)
		}
		if row.Tag != "" && row.Tag != strconv.Itoa(desired.VLAN) {
			return fmt.Errorf("OPNsense VLAN %s has tag %q, expected %d", desired.Name, row.Tag, desired.VLAN)
		}
	}
	return c.Post(ctx, VLANReconfigure, map[string]any{}, nil)
}

func poolForNetwork(network string) string {
	base, parsed, err := net.ParseCIDR(network)
	if err != nil {
		return ""
	}
	ones, _ := parsed.Mask.Size()
	if ones != 24 {
		return ""
	}
	return base.String()[:strings.LastIndex(base.String(), ".")+1] + "100-" + base.String()[:strings.LastIndex(base.String(), ".")+1] + "199"
}

func addressAliases(s model.Site) []AddressAlias {
	zones := append([]model.Zone(nil), s.Network.Zones...)
	sort.Slice(zones, func(i, j int) bool { return zones[i].VLAN < zones[j].VLAN })
	values := make([]string, 0, len(zones))
	for _, zone := range zones {
		values = append(values, zone.Network)
	}
	return []AddressAlias{
		{Name: "boetticher-internal-v4", Type: "network", Values: values, Description: "boetticher V1 internal IPv4 networks"},
	}
}

func firewallRules(s model.Site) []FirewallRule {
	networks := make(map[string]string, len(s.Network.Zones))
	gateways := make(map[string]string, len(s.Network.Zones))
	for _, zone := range s.Network.Zones {
		networks[zone.Name] = zone.Network
		gateways[zone.Name] = zone.Gateway
	}
	// Rules are named and explicitly sequenced. Internal denies precede broad
	// egress, and every rule is IPv4-only so the V1 policy cannot accidentally
	// become an IPv6 bypass.
	rules := []FirewallRule{}
	add := func(description, source, destination, action, protocol, ports string) {
		rules = append(rules, FirewallRule{Sequence: len(rules) + 1, Description: "boetticher " + description, Source: source, Destination: destination, Action: action, Protocol: protocol, DestinationPort: ports, IPVersion: "inet"})
	}
	for _, zone := range []string{"TRUSTED", "SERVERS", "SANDBOX", "MGMT"} {
		add(strings.ToLower(zone)+" DHCP to OPNsense", networks[zone], gateways[zone], "pass", "udp", "67")
	}
	add("sandbox DNS TCP to OPNsense", networks["SANDBOX"], gateways["SANDBOX"], "pass", "tcp", "53")
	add("sandbox DNS UDP to OPNsense", networks["SANDBOX"], gateways["SANDBOX"], "pass", "udp", "53")
	add("sandbox NTP to OPNsense", networks["SANDBOX"], gateways["SANDBOX"], "pass", "udp", "123")
	add("sandbox deny trusted", networks["SANDBOX"], networks["TRUSTED"], "block", "any", "")
	add("sandbox deny servers", networks["SANDBOX"], networks["SERVERS"], "block", "any", "")
	add("sandbox deny management", networks["SANDBOX"], networks["MGMT"], "block", "any", "")
	add("sandbox internet egress", networks["SANDBOX"], "internet", "pass", "any", "")
	add("OPNsense DDNS to authoritative DNS", "10.10.99.1", "10.10.20.10", "pass", "tcp", dns.AuthoritativePort)

	add("trusted DNS TCP to platform", networks["TRUSTED"], networks["SERVERS"], "pass", "tcp", "53")
	add("trusted DNS UDP to platform", networks["TRUSTED"], networks["SERVERS"], "pass", "udp", "53")
	add("trusted NTP to platform", networks["TRUSTED"], networks["SERVERS"], "pass", "udp", "123")
	add("trusted user services", networks["TRUSTED"], networks["SERVERS"], "pass", "tcp", "443")
	add("trusted administration", networks["TRUSTED"], networks["MGMT"], "pass", "tcp", "22,443,8006")
	add("trusted deny remaining servers", networks["TRUSTED"], networks["SERVERS"], "block", "any", "")
	add("trusted deny remaining management", networks["TRUSTED"], networks["MGMT"], "block", "any", "")
	add("trusted deny sandbox", networks["TRUSTED"], networks["SANDBOX"], "block", "any", "")

	add("servers DNS TCP to platform", networks["SERVERS"], networks["SERVERS"], "pass", "tcp", "53")
	add("servers NTP to platform", networks["SERVERS"], networks["SERVERS"], "pass", "udp", "123")
	add("servers to monitor", networks["SERVERS"], networks["MGMT"], "pass", "tcp", "10051")
	add("servers restricted update egress", networks["SERVERS"], "internet", "pass", "tcp", "80,443")
	add("servers restricted DNS TCP egress", networks["SERVERS"], "internet", "pass", "tcp", "53,853")
	add("servers restricted DNS UDP egress", networks["SERVERS"], "internet", "pass", "udp", "53")
	add("servers deny trusted", networks["SERVERS"], networks["TRUSTED"], "block", "any", "")
	add("servers deny sandbox", networks["SERVERS"], networks["SANDBOX"], "block", "any", "")
	add("servers deny remaining management", networks["SERVERS"], networks["MGMT"], "block", "any", "")

	add("management DNS TCP to platform", networks["MGMT"], networks["SERVERS"], "pass", "tcp", "53")
	add("management DNS UDP to platform", networks["MGMT"], networks["SERVERS"], "pass", "udp", "53")
	add("management NTP to platform", networks["MGMT"], networks["SERVERS"], "pass", "udp", "123")
	add("management administration", networks["MGMT"], networks["SERVERS"], "pass", "tcp", "22,53,80,443")
	add("management diagnostic trusted", networks["MGMT"], networks["TRUSTED"], "pass", "icmp", "")
	add("management restricted egress", networks["MGMT"], "internet", "pass", "tcp", "443")
	add("management deny sandbox", networks["MGMT"], networks["SANDBOX"], "block", "any", "")
	add("management deny remaining trusted", networks["MGMT"], networks["TRUSTED"], "block", "any", "")
	add("management deny remaining servers", networks["MGMT"], networks["SERVERS"], "block", "any", "")
	return rules
}

// KeaSubnetPayload is kept public so offline contract tests and a future
// live fixture can compare the exact JSON sent to OPNsense.
type KeaSubnetPayload struct {
	Subnet4 KeaSubnet `json:"subnet4"`
}

type KeaSubnet struct {
	SubnetID                   int           `json:"subnet_id"`
	Subnet                     string        `json:"subnet"`
	Description                string        `json:"description"`
	Pools                      []KeaPool     `json:"pools,omitempty"`
	OptionData                 KeaOptionData `json:"option_data"`
	DDNSForwardZone            string        `json:"ddns_forward_zone,omitempty"`
	DDNSReverseZone            string        `json:"ddns_reverse_zone,omitempty"`
	DDNSQualifyingSuffix       string        `json:"ddns_qualifying_suffix,omitempty"`
	DDNSDNSServer              string        `json:"ddns_dns_server,omitempty"`
	DDNSDNSPort                string        `json:"ddns_dns_port,omitempty"`
	DDNSDomainKeyName          string        `json:"ddns_domain_key_name,omitempty"`
	DDNSDomainKeySecret        string        `json:"ddns_domain_key_secret,omitempty"`
	DDNSDomainKeyAlgorithm     string        `json:"ddns_domain_key_algorithm,omitempty"`
	DDNSOverrideNoUpdate       bool          `json:"ddns_override_no_update,omitempty"`
	DDNSOverrideClientUpdate   bool          `json:"ddns_override_client_update,omitempty"`
	DDNSUpdateOnRenew          bool          `json:"ddns_update_on_renew,omitempty"`
	DDNSConflictResolutionMode string        `json:"ddns_conflict_resolution_mode,omitempty"`
}

type KeaPool struct {
	Pool string `json:"pool"`
}

type KeaOptionData struct {
	DomainNameServers string `json:"domain_name_servers"`
	Routers           string `json:"routers"`
	NTPServers        string `json:"ntp_servers"`
}

func (p Plan) KeaPayloads() []KeaSubnetPayload {
	return p.keaPayloads("")
}

func (p Plan) KeaPayloadsWithTSIG(secret string) []KeaSubnetPayload {
	return p.keaPayloads(secret)
}

// DDNSPayload is the global Kea D2 configuration. The per-subnet forward,
// reverse, and TSIG settings are carried separately in KeaPayloads; D2 must
// still be enabled globally before those subnet settings can take effect.
func (p Plan) DDNSPayload() map[string]any {
	return map[string]any{"ddns": map[string]any{
		"general": map[string]any{
			"enabled":       "1",
			"manual_config": "0",
			"server_ip":     "127.0.0.1",
			"server_port":   "53001",
		},
	}}
}

func (p Plan) keaPayloads(tsigSecret string) []KeaSubnetPayload {
	result := make([]KeaSubnetPayload, 0, len(p.Zones))
	for index, zone := range p.Zones {
		payload := KeaSubnetPayload{Subnet4: KeaSubnet{
			SubnetID:    index + 1,
			Subnet:      zone.Network,
			Description: "boetticher " + zone.Name,
			OptionData: KeaOptionData{
				DomainNameServers: strings.Join(zone.DNSAddresses, ","),
				Routers:           zone.Gateway,
				NTPServers:        strings.Join(zone.NTPAddresses, ","),
			},
		}}
		if p.DDNS.Enabled {
			forwardZone := strings.ToLower(zone.Name) + "." + "lab.home.arpa."
			reverseZone := reverseZoneForNetwork(zone.Network)
			payload.Subnet4.DDNSForwardZone = forwardZone
			payload.Subnet4.DDNSReverseZone = reverseZone
			payload.Subnet4.DDNSQualifyingSuffix = forwardZone
			payload.Subnet4.DDNSDNSServer = "10.10.20.10"
			payload.Subnet4.DDNSDNSPort = dns.AuthoritativePort
			payload.Subnet4.DDNSDomainKeyName = dns.TSIGKeyName(zone.Name, model.DefaultDomain)
			payload.Subnet4.DDNSDomainKeySecret = tsigSecret
			payload.Subnet4.DDNSDomainKeyAlgorithm = "hmac-sha256"
			payload.Subnet4.DDNSUpdateOnRenew = true
			payload.Subnet4.DDNSConflictResolutionMode = "check-exists-with-dhcid"
		}
		if zone.Pool != "" {
			payload.Subnet4.Pools = []KeaPool{{Pool: zone.Pool}}
		}
		result = append(result, payload)
	}
	return result
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

// ApplyKea performs the documented OPNsense Kea CRUD sequence. Existing
// UUID discovery is intentionally delegated to the API response; no delete
// or broad replacement is performed. A live fixture must qualify the exact
// search-row and nested model shape before release qualification.
func (c *Client) ApplyKea(ctx context.Context, plan Plan) error {
	return c.applyKea(ctx, plan, "")
}

func (c *Client) ApplyKeaWithTSIG(ctx context.Context, plan Plan, tsigSecret string) error {
	return c.applyKea(ctx, plan, tsigSecret)
}

// ApplyDDNS enables the OPNsense-managed Kea D2 agent. It intentionally does
// not accept a secret: TSIG material belongs only in the per-subnet runtime
// payload and is never part of the global generated configuration.
func (c *Client) ApplyDDNS(ctx context.Context, plan Plan) error {
	if !plan.DDNS.Enabled {
		return nil
	}
	if err := c.Post(ctx, DDNSSet, plan.DDNSPayload(), nil); err != nil {
		return fmt.Errorf("configure Kea DDNS agent: %w", err)
	}
	return nil
}

func (c *Client) applyKea(ctx context.Context, plan Plan, tsigSecret string) error {
	if plan.DDNS.Enabled && tsigSecret == "" {
		return errors.New("DDNS TSIG secret is required for Kea convergence")
	}
	for _, payload := range plan.keaPayloads(tsigSecret) {
		var search struct {
			Rows []struct {
				UUID   string `json:"uuid"`
				Subnet string `json:"subnet"`
			} `json:"rows"`
		}
		if err := c.Post(ctx, DHCPv4SubnetSearch, map[string]any{
			"current": 1, "rowCount": 100, "sort": map[string]any{}, "searchPhrase": payload.Subnet4.Subnet,
		}, &search); err != nil {
			return fmt.Errorf("search Kea subnet %s: %w", payload.Subnet4.Subnet, err)
		}
		if len(search.Rows) == 0 {
			if err := c.Post(ctx, DHCPv4SubnetAdd, payload, nil); err != nil {
				return fmt.Errorf("add Kea subnet %s: %w", payload.Subnet4.Subnet, err)
			}
			continue
		}
		uuid := search.Rows[0].UUID
		if uuid == "" {
			return fmt.Errorf("OPNsense returned a Kea subnet without a UUID for %s", payload.Subnet4.Subnet)
		}
		if err := c.Post(ctx, DHCPv4SubnetSet+"/"+urlPathEscape(uuid), payload, nil); err != nil {
			return fmt.Errorf("update Kea subnet %s: %w", payload.Subnet4.Subnet, err)
		}
	}
	if err := c.Post(ctx, DHCPv4Reconfigure, map[string]any{}, nil); err != nil {
		return fmt.Errorf("reconfigure Kea: %w", err)
	}
	return nil
}

func urlPathEscape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "%", "%25"), "/", "%2F")
}

func (p Plan) FirewallPayloads() []map[string]any {
	result := make([]map[string]any, 0, len(p.FirewallRules))
	for _, rule := range p.FirewallRules {
		value := map[string]any{
			"sequence":        rule.Sequence,
			"description":     rule.Description,
			"source_net":      rule.Source,
			"destination_net": rule.Destination,
			"action":          rule.Action,
			"protocol":        rule.Protocol,
			"ipprotocol":      rule.IPVersion,
		}
		if rule.DestinationPort != "" {
			value["destination_port"] = rule.DestinationPort
		}
		result = append(result, map[string]any{"rule": value})
	}
	return result
}

func (c *Client) ApplyFirewall(ctx context.Context, plan Plan) error {
	for _, desired := range plan.FirewallRules {
		var search struct {
			Rows []struct {
				UUID        string `json:"uuid"`
				Description string `json:"description"`
			} `json:"rows"`
		}
		if err := c.Post(ctx, FirewallSearch, map[string]any{
			"current": 1, "rowCount": 100, "sort": map[string]any{}, "searchPhrase": desired.Description,
		}, &search); err != nil {
			return fmt.Errorf("search firewall rule %s: %w", desired.Description, err)
		}
		value := map[string]any{
			"sequence":        desired.Sequence,
			"description":     desired.Description,
			"source_net":      desired.Source,
			"destination_net": desired.Destination,
			"action":          desired.Action,
			"protocol":        desired.Protocol,
			"ipprotocol":      desired.IPVersion,
		}
		if desired.DestinationPort != "" {
			value["destination_port"] = desired.DestinationPort
		}
		payload := map[string]any{"rule": value}
		if len(search.Rows) == 0 {
			if err := c.Post(ctx, FirewallAdd, payload, nil); err != nil {
				return fmt.Errorf("add firewall rule %s: %w", desired.Description, err)
			}
			continue
		}
		if search.Rows[0].UUID == "" {
			return fmt.Errorf("OPNsense returned a firewall rule without a UUID for %s", desired.Description)
		}
		if err := c.Post(ctx, FirewallSet+"/"+urlPathEscape(search.Rows[0].UUID), payload, nil); err != nil {
			return fmt.Errorf("update firewall rule %s: %w", desired.Description, err)
		}
	}
	if err := c.Post(ctx, FirewallApply, map[string]any{}, nil); err != nil {
		return fmt.Errorf("apply firewall rules: %w", err)
	}
	return nil
}

func StableRuleDescriptions(plan Plan) []string {
	result := make([]string, 0, len(plan.FirewallRules))
	for _, rule := range plan.FirewallRules {
		result = append(result, rule.Description)
	}
	sort.Strings(result)
	return result
}

func NetworkID(zone model.Zone) string {
	return zone.Name + "-vlan" + strconv.Itoa(zone.VLAN)
}
