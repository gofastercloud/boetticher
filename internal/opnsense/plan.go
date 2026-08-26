package opnsense

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/dave/labinabox/internal/model"
)

const (
	DHCPv4SubnetSearch = "/api/kea/dhcpv4/search_subnet"
	DHCPv4SubnetAdd    = "/api/kea/dhcpv4/add_subnet"
	DHCPv4SubnetSet    = "/api/kea/dhcpv4/set_subnet"
	DHCPv4Reconfigure  = "/api/kea/service/reconfigure"
	FirewallSearch     = "/api/firewall/filter/search_rule"
	FirewallAdd        = "/api/firewall/filter/add_rule"
	FirewallSet        = "/api/firewall/filter/set_rule"
	FirewallApply      = "/api/firewall/filter_base/apply"
)

type Plan struct {
	ModelRevision string         `json:"model_revision"`
	Boundary      string         `json:"boundary"`
	IPv4Only      bool           `json:"ipv4_only"`
	Zones         []ZonePlan     `json:"zones"`
	FirewallRules []FirewallRule `json:"firewall_rules"`
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

type FirewallRule struct {
	Description string `json:"description"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
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
		ModelRevision: revision,
		Boundary:      "opnsense",
		IPv4Only:      true,
		Zones:         zones,
		FirewallRules: firewallRules(s),
	}, nil
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

func firewallRules(s model.Site) []FirewallRule {
	// Rules are named and ordered so the convergence layer can identify its
	// own records without deleting rules owned by the operator or OPNsense.
	return []FirewallRule{
		{Description: "labinabox sandbox deny trusted", Source: "SANDBOX", Destination: "TRUSTED", Action: "block", Protocol: "any"},
		{Description: "labinabox sandbox deny servers", Source: "SANDBOX", Destination: "SERVERS", Action: "block", Protocol: "any"},
		{Description: "labinabox sandbox deny management", Source: "SANDBOX", Destination: "MGMT", Action: "block", Protocol: "any"},
		{Description: "labinabox trusted to services", Source: "TRUSTED", Destination: "SERVERS", Action: "pass", Protocol: "tcp"},
		{Description: "labinabox trusted to management services", Source: "TRUSTED", Destination: "MGMT", Action: "pass", Protocol: "tcp"},
		{Description: "labinabox services to monitor", Source: "SERVERS", Destination: "MGMT", Action: "pass", Protocol: "tcp"},
		{Description: "labinabox management to services", Source: "MGMT", Destination: "SERVERS", Action: "pass", Protocol: "tcp"},
	}
}

// KeaSubnetPayload is kept public so offline contract tests and a future
// live fixture can compare the exact JSON sent to OPNsense.
type KeaSubnetPayload struct {
	Subnet4 KeaSubnet `json:"subnet4"`
}

type KeaSubnet struct {
	SubnetID    int           `json:"subnet_id"`
	Subnet      string        `json:"subnet"`
	Description string        `json:"description"`
	Pools       []KeaPool     `json:"pools,omitempty"`
	OptionData  KeaOptionData `json:"option_data"`
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
	result := make([]KeaSubnetPayload, 0, len(p.Zones))
	for index, zone := range p.Zones {
		payload := KeaSubnetPayload{Subnet4: KeaSubnet{
			SubnetID:    index + 1,
			Subnet:      zone.Network,
			Description: "Lab-in-a-Box " + zone.Name,
			OptionData: KeaOptionData{
				DomainNameServers: strings.Join(zone.DNSAddresses, ","),
				Routers:           zone.Gateway,
				NTPServers:        strings.Join(zone.NTPAddresses, ","),
			},
		}}
		if zone.Pool != "" {
			payload.Subnet4.Pools = []KeaPool{{Pool: zone.Pool}}
		}
		result = append(result, payload)
	}
	return result
}

// ApplyKea performs the documented OPNsense Kea CRUD sequence. Existing
// UUID discovery is intentionally delegated to the API response; no delete
// or broad replacement is performed. A live fixture must qualify the exact
// search-row and nested model shape before release qualification.
func (c *Client) ApplyKea(ctx context.Context, plan Plan) error {
	for _, payload := range plan.KeaPayloads() {
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
		result = append(result, map[string]any{"rule": map[string]any{
			"description":     rule.Description,
			"source_net":      rule.Source,
			"destination_net": rule.Destination,
			"action":          rule.Action,
			"protocol":        rule.Protocol,
		}})
	}
	return result
}

// Firewall rules are surfaced as a model projection. Applying them requires
// resolving OPNsense interface/alias UUIDs and qualifying the rule schema on
// the exact supported patch, so ApplyFirewall currently refuses to mutate.
// This is a deliberate safety gate rather than an assertion of success.
func (c *Client) ApplyFirewall(_ context.Context, _ Plan) error {
	return fmt.Errorf("OPNsense firewall convergence requires qualified interface/alias UUID mapping; no mutation performed")
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
