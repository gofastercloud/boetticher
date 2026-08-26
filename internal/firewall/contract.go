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
	b.WriteString("This contract is generated from the boetticher v0.2 site model. The external gateway is operator-managed; boetticher does not configure, authenticate to, back up, or inspect its internal rule set.\n\n")
	b.WriteString("## VLANs and gateways\n\n| VLAN | Zone | Network | Gateway |\n| ---: | --- | --- | --- |\n")
	for _, zone := range s.Normalize().Network.Zones {
		fmt.Fprintf(&b, "| %d | %s | `%s` | `%s` |\n", zone.VLAN, zone.Name, zone.Network, zone.Gateway)
	}
	b.WriteString("\n## Required behavior\n\n")
	b.WriteString("- Route the four fixed IPv4 networks and provide upstream Internet/NAT as appropriate to the site.\n")
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
	b.WriteString("## Policy intent\n\n")
	for _, rule := range plan.Rules {
		ports := ""
		if len(rule.Ports) > 0 {
			ports = " (" + strings.Join(rule.Ports, ", ") + ")"
		}
		fmt.Fprintf(&b, "- **%s:** `%s` -> `%s` `%s` %s%s\n", rule.Action, rule.From, rule.To, rule.Protocol, ports, "")
	}
	return b.String(), nil
}
