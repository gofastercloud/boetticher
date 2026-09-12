package firewallmodule

import (
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/tailnet"
	"strings"
)

func tailnetFirewallSections(home string) []Section {
	rule := func(id string, values map[string]string) Section {
		options := map[string]string{"name": "Boetticher Tailnet " + id, "src": "transit", "src_ip": tailnet.GuestAddress + "/32", "src_mac": tailnet.GuestMAC, "family": "ipv4", "target": "ACCEPT"}
		for k, v := range values {
			options[k] = v
		}
		return Section{Name: "boetticher_tailnet_" + id, Type: "rule", Options: options, Lists: map[string][]string{}}
	}
	result := []Section{
		rule("deny_home", map[string]string{"dest": "home_wan", "dest_ip": home, "target": "DROP", "proto": "all"}),
		rule("deny_nonpublic", map[string]string{"dest": "home_wan", "target": "DROP", "proto": "all"}),
	}
	result[1].Lists["dest_ip"] = strings.Split(tailnet.NonPublicIPv4, ", ")
	result = append(result,
		rule("transport_tcp", map[string]string{"dest": "home_wan", "proto": "tcp", "dest_port": "80 443"}),
		rule("transport_udp", map[string]string{"dest": "home_wan", "proto": "udp"}),
		rule("dns", map[string]string{"dest_ip": tailnet.Gateway, "proto": "tcp udp", "dest_port": "53"}),
		rule("ntp", map[string]string{"dest_ip": tailnet.Gateway, "proto": "udp", "dest_port": "123"}),
		rule("trusted", map[string]string{"dest": "trusted", "proto": "all"}),
		rule("proxmox_ssh", map[string]string{"dest": "mgmt", "dest_ip": model.ProxmoxManagementAddress + "/32", "proto": "tcp", "dest_port": "22"}),
	)
	for _, d := range model.TrustedRoutedDestinations() {
		result = append(result, rule(strings.ToLower(d.Zone), map[string]string{"dest": strings.ToLower(d.Zone), "proto": "all"}))
	}
	return result
}

// FirewallScope filters to this owner's exact named sections. In particular,
// the independent 4C safety ipsets and unrecognised provider objects survive.
func FirewallScope(current map[string]openwrt.UCISection, desired []Section) map[string]openwrt.UCISection {
	owned := map[string]bool{}
	for _, s := range desired {
		owned[s.Name] = true
	}
	for _, s := range tailnetFirewallSections("192.168.4.0/22") {
		owned[s.Name] = true
	}
	reference := model.NewSite("scope", "controller-local", model.GatewayModeManaged)
	for _, s := range serviceFirewallSections(reference, true, true, true) {
		owned[s.Name] = true
	}
	for _, name := range []string{
		observabilityControllerExporterRule, observabilityHostExporterRule,
		observabilityControllerPortalRule,
		mediaMonitoringRule,
		observabilityControllerIngressRule, observabilityHostIngressRule,
		observabilityRuntimeIngressRule, observabilityTrustedIngressRule,
		observabilityTailnetIngressRule,
	} {
		owned[name] = true
	}
	result := map[string]openwrt.UCISection{}
	for name, s := range current {
		if managedVPNFirewallSection(name, s) {
			owned[name] = true
		}
		if strings.HasPrefix(name, "boetticher_system_") && managedRuleIdentity(name, s.Options) {
			owned[name] = true
		}
		if owned[name] {
			result[name] = s
		}
	}
	return result
}

func managedVPNFirewallSection(name string, section openwrt.UCISection) bool {
	if name == "boetticher_zone_vpn" {
		return section.Type == "zone" && section.Options["name"] == "vpn" && section.Options["family"] == "ipv4" && section.Options["masq"] == "1"
	}
	if strings.HasPrefix(name, "boetticher_forward_") && strings.HasSuffix(name, "_vpn") {
		return section.Type == "forwarding" && section.Options["dest"] == "vpn" && section.Options["family"] == "ipv4"
	}
	if strings.HasPrefix(name, "boetticher_vpn_forward_") {
		return section.Type == "redirect" && strings.HasPrefix(section.Options["name"], "Boetticher VPN ") && section.Options["src"] == "vpn" && section.Options["target"] == "DNAT" && section.Options["family"] == "ipv4" && section.Options["reflection"] == "0" && len(section.Lists["proto"]) > 0
	}
	return false
}

func DiffFirewall(current map[string]openwrt.UCISection, desired []Section) ([]Mutation, error) {
	return DiffOwned(FirewallScope(current, desired), desired)
}
