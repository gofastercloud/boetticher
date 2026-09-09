package firewallmodule

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
)

// vpnSections projects one provider profile into ordinary OpenWrt UCI
// sections. route_allowed_ips stays disabled so the provider cannot install a
// main-table default; explicit source rules select table 51820 instead.
func vpnSections(site model.Site, modules clientservices.Modules, profile VPNProfile) ([]Section, []Section) {
	clients := make([]string, 0, len(modules.VPN.Clients))
	for _, name := range modules.VPN.Clients {
		if reservation, ok := clientservices.ResolveReservation(modules, name); ok {
			clients = append(clients, reservation.Address)
		}
	}
	network := []Section{
		{Name: "airvpn", Type: "interface", Options: map[string]string{
			"proto": "wireguard", "private_key": profile.PrivateKey, "fwmark": "51820", "mtu": strconv.Itoa(profile.MTU), "force_link": "1", "ipv6": "0", "delegate": "0",
		}, Lists: map[string][]string{"addresses": {profile.Address}}},
		{Name: "boetticher_vpn_peer", Type: "wireguard_airvpn", Options: map[string]string{
			"public_key": profile.PeerPublicKey, "preshared_key": profile.PresharedKey, "endpoint_host": profile.EndpointHost,
			"endpoint_port": strconv.Itoa(profile.EndpointPort), "persistent_keepalive": strconv.Itoa(profile.PersistentKeepalive), "route_allowed_ips": "0",
		}, Lists: map[string][]string{"allowed_ips": {"0.0.0.0/0"}}},
		{Name: "boetticher_vpn_default", Type: "route", Options: map[string]string{
			"interface": "airvpn", "target": "0.0.0.0", "netmask": "0.0.0.0", "table": "51820",
		}, Lists: map[string][]string{}},
	}
	for index, zone := range site.Network.Zones {
		_ = index
		name := strings.ToLower(zone.Name)
		network = append(network, Section{Name: "boetticher_vpn_lab_" + name, Type: "route", Options: map[string]string{
			"interface": "boetticher_iface_" + name, "target": strings.Split(zone.Network, "/")[0], "netmask": "255.255.255.0", "table": "51820",
		}, Lists: map[string][]string{}})
	}
	for index, address := range clients {
		network = append(network,
			Section{Name: fmt.Sprintf("boetticher_vpn_rule_%d", index), Type: "rule", Options: map[string]string{
				"src": address + "/32", "lookup": "51820", "priority": strconv.Itoa(10000 + index),
			}, Lists: map[string][]string{}},
			Section{Name: fmt.Sprintf("boetticher_vpn_block_%d", index), Type: "rule", Options: map[string]string{
				"src": address + "/32", "action": "unreachable", "priority": strconv.Itoa(10100 + index),
			}, Lists: map[string][]string{}},
		)
	}

	firewall := []Section{
		{Name: "boetticher_zone_vpn", Type: "zone", Options: map[string]string{"name": "vpn", "input": "DROP", "output": "ACCEPT", "forward": "DROP", "family": "ipv4", "masq": "1"}, Lists: map[string][]string{"network": {"airvpn"}}},
	}
	for _, zone := range site.Network.Zones {
		name := strings.ToLower(zone.Name)
		if zone.Type == model.ZoneTypeTransit || zone.Type == model.ZoneTypeManagement {
			continue
		}
		firewall = append(firewall, Section{Name: "boetticher_forward_" + name + "_vpn", Type: "forwarding", Options: map[string]string{"src": name, "dest": "vpn", "family": "ipv4"}, Lists: map[string][]string{}})
	}
	for _, forward := range modules.VPN.Forwards {
		reservation, ok := clientservices.ResolveReservation(modules, forward.Reservation)
		if !ok {
			continue
		}
		zoneName := ""
		for _, zone := range site.Network.Zones {
			if strings.EqualFold(zone.Name, reservation.Zone) {
				zoneName = strings.ToLower(zone.Name)
			}
		}
		if zoneName == "" {
			continue
		}
		firewall = append(firewall, Section{Name: nativeVPNForwardSectionName(forward.Name), Type: "redirect", Options: map[string]string{
			"name": "Boetticher VPN " + forward.Name, "src": "vpn", "dest": zoneName, "dest_ip": reservation.Address,
			"src_dport": strconv.Itoa(forward.Port), "dest_port": strconv.Itoa(forward.Port), "target": "DNAT", "family": "ipv4", "reflection": "0",
		}, Lists: map[string][]string{"proto": append([]string(nil), forward.Protocols...)}})
	}
	return network, firewall
}

func nativeVPNForwardSectionName(name string) string {
	return "boetticher_vpn_forward_" + nativeRecordSuffix(name)
}
