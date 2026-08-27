package firewall

import (
	"fmt"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

// RenderExternalContract is the generic, vendor-neutral contract for an
// operator-managed gateway. It deliberately contains intent and fixed values,
// not appliance syntax or credentials.
func RenderExternalContract(s model.Site, plan Plan) (string, error) {
	if s.Gateway.Mode != model.GatewayModeExternal {
		return "", fmt.Errorf("external gateway contract requires external mode")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# boetticher external firewall contract\n\nModel revision: `%s`\n\n", plan.ModelRevision)
	b.WriteString("This contract is generated from the boetticher v0.3 site model. It is desired network intent only: enforcement is NOT ACTIVE in boetticher external-gateway mode. The external gateway is operator-managed; boetticher does not configure, authenticate to, back up, or inspect its internal rule set.\n\n")
	b.WriteString("## TRANSIT architecture\n\nTRANSIT is a fixed Core network primitive, not a module-owned network. The operator must provide the gateway interface and routing for the contract below.\n\n| Name | Semantic type | VLAN | CIDR | Gateway |\n| --- | --- | ---: | --- | --- |\n")
	for _, zone := range s.Normalize().Network.Zones {
		if zone.Type == model.ZoneTypeTransit {
			fmt.Fprintf(&b, "| %s | `%s` | %d | `%s` | `%s` |\n", zone.Name, zone.Type, zone.VLAN, zone.Network, zone.Gateway)
		}
	}
	b.WriteString("\n## VLANs and gateways\n\n| VLAN | Zone | Semantic type | Network | Gateway |\n| ---: | --- | --- | --- | --- |\n")
	for _, zone := range s.Normalize().Network.Zones {
		fmt.Fprintf(&b, "| %d | %s | `%s` | `%s` | `%s` |\n", zone.VLAN, zone.Name, zone.Type, zone.Network, zone.Gateway)
	}
	b.WriteString("\n## Required routes\n\n")
	b.WriteString("The operator must route each fixed site CIDR through its listed gateway and provide the TRANSIT gateway as the routed edge for any enabled module advertisements. Do not infer routes from VMID range or module enablement.\n\n")
	for _, zone := range s.Normalize().Network.Zones {
		fmt.Fprintf(&b, "- `%s` via `%s` on VLAN %d (`%s`, semantic type `%s`).\n", zone.Network, zone.Gateway, zone.VLAN, zone.Name, zone.Type)
	}
	b.WriteString("- Module-advertised routes: none in the Core-only contract. Any later module route is listed explicitly in its composed contract.\n")
	b.WriteString("- Return routing: responses to fixed site CIDRs and any module-advertised route must return through the corresponding external-gateway route and the TRANSIT gateway; asymmetric return paths are not accepted.\n\n")
	b.WriteString("\n## Required behavior\n\n")
	b.WriteString("- Route the five fixed IPv4 networks and provide upstream Internet/NAT as appropriate to the site.\n")
	b.WriteString("- Keep the inter-zone policy in this document: SANDBOX cannot reach TRUSTED, SERVERS, or MGMT; ordinary platform administration is explicit; Internet egress follows the generated policy.\n")
	b.WriteString("- Provide DHCP with the generated gateway, DNS, and NTP values for each zone.\n")
	b.WriteString("- Keep SANDBOX DNS/NTP isolated from the broad internal namespace.\n")
	b.WriteString("- If dynamic DHCP names are wanted, send authenticated RFC2136 updates to the generated PowerDNS target using the generated zone and TSIG contract. DHCP failure must not prevent a lease.\n\n")
	b.WriteString("## DHCP options\n\n")
	for _, subnet := range plan.DHCP {
		fmt.Fprintf(&b, "### %s\n\n- Network: `%s`\n- Gateway: `%s`\n- DNS: `%s`\n- NTP: `%s`\n- Dynamic name zone: `%s`\n- Reverse zone: `%s`\n", subnet.Zone, subnet.Network, subnet.Gateway, strings.Join(subnet.DNS, ", "), strings.Join(subnet.NTP, ", "), subnet.ForwardZone, subnet.ReverseZone)
		if subnet.Pool == "" {
			b.WriteString("- Allocation: reservations only\n\n")
		} else {
			fmt.Fprintf(&b, "- Pool: `%s`\n\n", subnet.Pool)
		}
	}
	b.WriteString("## Required allows\n\n")
	for _, rule := range plan.Rules {
		if rule.Action != "allow" {
			continue
		}
		ports := ""
		if len(rule.Ports) > 0 {
			ports = " (" + strings.Join(rule.Ports, ", ") + ")"
		}
		fmt.Fprintf(&b, "- **%s:** `%s` -> `%s` `%s` %s%s\n", rule.Action, rule.From, rule.To, rule.Protocol, ports, "")
	}
	b.WriteString("\n## Required denies\n\n")
	for _, rule := range plan.Rules {
		if rule.Action != "deny" {
			continue
		}
		ports := ""
		if len(rule.Ports) > 0 {
			ports = " (" + strings.Join(rule.Ports, ", ") + ")"
		}
		fmt.Fprintf(&b, "- **%s:** `%s` -> `%s` `%s`%s\n", rule.Action, rule.From, rule.To, rule.Protocol, ports)
	}
	b.WriteString("\n## Source address expectations\n\n")
	for _, rule := range plan.Rules {
		if rule.From == "gateway" || rule.From == "any" || rule.From == "WAN" || rule.From == "Internet" {
			continue
		}
		if zone, err := s.ZoneForType(zoneTypeForName(rule.From)); err == nil {
			fmt.Fprintf(&b, "- `%s` rules use source `%s` (`%s`).\n", rule.Name, zone.Network, zone.Name)
		}
	}
	b.WriteString("\nBoetticher desired intent is separate from operator implementation responsibility. Generated text does not prove that the external firewall, route approval, ACL, NAT, or deny rules are configured or effective.\n")
	return b.String(), nil
}

func zoneTypeForName(name string) model.ZoneType {
	for _, zone := range []model.ZoneType{model.ZoneTypeTrusted, model.ZoneTypeServers, model.ZoneTypeSandbox, model.ZoneTypeManagement, model.ZoneTypeTransit} {
		if strings.EqualFold(string(zone), name) {
			return zone
		}
	}
	return ""
}
