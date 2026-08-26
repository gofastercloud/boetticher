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
	DHCPv4SubnetSearch = "/api/kea/dhcpv4/searchSubnet"
	DHCPv4SubnetAdd    = "/api/kea/dhcpv4/addSubnet"
	DHCPv4SubnetSet    = "/api/kea/dhcpv4/setSubnet"
	DHCPv4Reconfigure  = "/api/kea/service/reconfigure"
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
	VLANs          []VLANPlan     `json:"vlans"`
	Zones          []ZonePlan     `json:"zones"`
	FirewallRules  []FirewallRule `json:"firewall_rules"`
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

type FirewallRule struct {
	Description     string `json:"description"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	Action          string `json:"action"`
	Protocol        string `json:"protocol"`
	DestinationPort string `json:"destination_port,omitempty"`
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
		ModelRevision:  revision,
		Boundary:       "opnsense",
		IPv4Only:       true,
		InternalParent: "vtnet1",
		VLANs:          vlanPlans(s),
		Zones:          zones,
		FirewallRules:  firewallRules(s),
	}, nil
}

func vlanPlans(s model.Site) []VLANPlan {
	zones := append([]model.Zone(nil), s.Network.Zones...)
	sort.Slice(zones, func(i, j int) bool { return zones[i].VLAN < zones[j].VLAN })
	result := make([]VLANPlan, 0, len(zones))
	for _, zone := range zones {
		result = append(result, VLANPlan{Name: zone.Name, VLAN: zone.VLAN, Parent: "vtnet1", Description: "Lab-in-a-Box " + zone.Name})
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

func firewallRules(s model.Site) []FirewallRule {
	networks := make(map[string]string, len(s.Network.Zones))
	for _, zone := range s.Network.Zones {
		networks[zone.Name] = zone.Network
	}
	// Rules are named and ordered so the convergence layer can identify its
	// own records without deleting rules owned by the operator or OPNsense.
	return []FirewallRule{
		{Description: "labinabox sandbox deny trusted", Source: networks["SANDBOX"], Destination: networks["TRUSTED"], Action: "block", Protocol: "any"},
		{Description: "labinabox sandbox deny servers", Source: networks["SANDBOX"], Destination: networks["SERVERS"], Action: "block", Protocol: "any"},
		{Description: "labinabox sandbox deny management", Source: networks["SANDBOX"], Destination: networks["MGMT"], Action: "block", Protocol: "any"},
		{Description: "labinabox trusted to server DNS HTTPS", Source: networks["TRUSTED"], Destination: networks["SERVERS"], Action: "pass", Protocol: "tcp", DestinationPort: "53,443"},
		{Description: "labinabox trusted to server DNS NTP", Source: networks["TRUSTED"], Destination: networks["SERVERS"], Action: "pass", Protocol: "udp", DestinationPort: "53,123"},
		{Description: "labinabox trusted to management HTTPS", Source: networks["TRUSTED"], Destination: networks["MGMT"], Action: "pass", Protocol: "tcp", DestinationPort: "443,8006"},
		{Description: "labinabox services to monitor", Source: networks["SERVERS"], Destination: networks["MGMT"], Action: "pass", Protocol: "tcp", DestinationPort: "10051"},
		{Description: "labinabox management to services", Source: networks["MGMT"], Destination: networks["SERVERS"], Action: "pass", Protocol: "tcp", DestinationPort: "22,53,443"},
		{Description: "labinabox management to server DNS NTP", Source: networks["MGMT"], Destination: networks["SERVERS"], Action: "pass", Protocol: "udp", DestinationPort: "53,123"},
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
		value := map[string]any{
			"description":     rule.Description,
			"source_net":      rule.Source,
			"destination_net": rule.Destination,
			"action":          rule.Action,
			"protocol":        rule.Protocol,
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
			"description":     desired.Description,
			"source_net":      desired.Source,
			"destination_net": desired.Destination,
			"action":          desired.Action,
			"protocol":        desired.Protocol,
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
