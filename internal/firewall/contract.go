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
	b.WriteString("This contract is generated from the boetticher v0.4 site model. It is desired network intent only: enforcement is NOT ACTIVE in boetticher external-gateway mode. The external gateway is operator-managed; boetticher does not configure, authenticate to, back up, or inspect its internal rule set.\n\n")
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
	b.WriteString("The operator must route each fixed site CIDR through its listed gateway and provide the TRANSIT gateway as the routed edge for any enabled module advertisements. Do not infer routes from VMID range or module enablement. Proxmox management is `10.10.99.5` on MGMT; the external gateway owns `.1` in every listed subnet.\n\n")
	for _, zone := range s.Normalize().Network.Zones {
		fmt.Fprintf(&b, "- `%s` via `%s` on VLAN %d (`%s`, semantic type `%s`).\n", zone.Network, zone.Gateway, zone.VLAN, zone.Name, zone.Type)
	}
	advertised := false
	for _, declaration := range s.Declarations {
		for _, route := range declaration.AdvertisedRoutes {
			if !advertised {
				b.WriteString("- Module-advertised routes:\n")
				advertised = true
			}
			fmt.Fprintf(&b, "  - `%s` for module `%s`.\n", route, declaration.Module)
		}
	}
	if !advertised {
		b.WriteString("- Module-advertised routes: none in the Core-only contract. Any later module route is listed explicitly in its composed contract.\n")
	}
	b.WriteString("- Return routing: responses to fixed site CIDRs and any module-advertised route must return through the corresponding external-gateway route and the TRANSIT gateway; asymmetric return paths are not accepted.\n\n")
	for _, declaration := range s.Declarations {
		for _, route := range declaration.ReturnRouting {
			fmt.Fprintf(&b, "- Module `%s` return-routing requirement: %s\n", declaration.Module, route)
		}
	}
	if len(s.Declarations) > 0 {
		b.WriteString("\n## Composed module contracts\n\n")
	}
	for _, declaration := range s.Declarations {
		switch declaration.Module {
		case "tailnet-router":
			b.WriteString("### tailnet-router\n\n- Address: `10.10.5.10` on TRANSIT (`10.10.5.0/24`, gateway `10.10.5.1`).\n- Advertised route: `10.10.0.0/16`; Tailscale route approval is an operator action.\n- Subnet-route SNAT: enabled.\n- Tailscale runtime: `accept-dns=false`.\n- Permitted internal destinations: LiteLLM HTTPS, portal HTTPS, and monitoring HTTPS only, plus DNS/NTP and required Tailscale control/DERP egress.\n- Explicit deny expectations: TRUSTED, SANDBOX, MGMT, Proxmox API, SSH, arbitrary SERVERS workloads, and Internet exit-node behavior remain denied.\n- Required return routing: Tailnet traffic for `10.10.0.0/16` returns through the TRANSIT gateway.\n\n")
		case "litellm":
			b.WriteString("### litellm\n\n- Address: `10.10.20.60` in SERVERS.\n- Frontend: HTTPS on `443` with required client certificate; no plaintext listener.\n- Backend: loopback-only `127.0.0.1:4000`.\n- Outbound: only the configured upstream HTTPS endpoint(s), plus DNS/NTP as required; unknown Internet destinations remain denied.\n\n")
		}
	}
	b.WriteString("\n## Required behavior\n\n")
	b.WriteString("- Route the six fixed IPv4 networks and provide upstream Internet/NAT as appropriate to the site.\n")
	b.WriteString("- Keep the inter-zone policy in this document: SANDBOX cannot reach TRUSTED, SERVERS, INFRA, or MGMT; ordinary platform administration is explicit; Internet egress follows the generated policy.\n")
	b.WriteString("- Provide dynamic DHCP pools and DDNS for TRUSTED and SANDBOX with the generated gateway, DNS, and NTP values. Provide reservation-only DHCP and DDNS for SERVERS. TRANSIT, INFRA, and MGMT use static assignments only.\n")
	b.WriteString("- Keep SANDBOX DNS/NTP isolated from the broad internal namespace.\n")
	b.WriteString("- If dynamic DHCP names are wanted, send authenticated RFC2136 updates to the generated PowerDNS target using the generated zone and TSIG contract. DHCP failure must not prevent a lease.\n\n")
	b.WriteString("## DHCP options\n\n")
	for _, subnet := range plan.DHCP {
		fmt.Fprintf(&b, "### %s\n\n- Network: `%s`\n- Gateway: `%s`\n- DNS: `%s`\n- NTP: `%s`\n- Dynamic name zone: `%s`\n- Reverse zone: `%s`\n", subnet.Zone, subnet.Network, subnet.Gateway, strings.Join(subnet.DNS, ", "), strings.Join(subnet.NTP, ", "), subnet.ForwardZone, subnet.ReverseZone)
		if subnet.Pool == "" {
			b.WriteString("- Allocation: reservations only\n")
			for _, reservation := range subnet.Reservations {
				fmt.Fprintf(&b, "- Reservation: `%s` `%s` `%s`\n", reservation.Hostname, reservation.Address, reservation.MAC)
			}
			b.WriteString("\n")
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
		extra := ""
		if rule.SourceCIDR != "" {
			extra += " source=" + rule.SourceCIDR
		}
		if rule.DestinationCIDR != "" {
			extra += " destination=" + rule.DestinationCIDR
		}
		if rule.DestinationHost != "" {
			extra += " endpoint=" + rule.DestinationHost
		}
		fmt.Fprintf(&b, "- **%s:** `%s` -> `%s` `%s` %s%s%s\n", rule.Action, rule.From, rule.To, rule.Protocol, ports, extra, "")
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
	for _, zone := range []model.ZoneType{model.ZoneTypeTransit, model.ZoneTypeInfrastructure, model.ZoneTypeServers, model.ZoneTypeTrusted, model.ZoneTypeSandbox, model.ZoneTypeManagement} {
		if strings.EqualFold(string(zone), name) {
			return zone
		}
	}
	return ""
}
