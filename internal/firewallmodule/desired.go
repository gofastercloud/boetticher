// Package firewallmodule contains the concrete Phase 4A firewall capability.
// OpenWrt is intentionally an implementation detail of this package.
package firewallmodule

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	ProviderName  = "lab-firewall-01"
	ProviderVMID  = 280 // 200-209 is reserved by the existing tailnet module.
	ProviderDisk  = "scsi0"
	ProviderNIC0  = "virtio,bridge=vmbr0,firewall=1,macaddr=02:00:00:04:00:01"
	ProviderNIC1  = "virtio,bridge=vmbr1,firewall=1,macaddr=02:00:00:04:00:02"
	ProviderImage = "openwrt-25.12.5-x86-64-generic-ext4-combined.img"
)

var zoneOrder = []model.ZoneType{
	model.ZoneTypeTransit,
	model.ZoneTypeInfrastructure,
	model.ZoneTypeServers,
	model.ZoneTypeTrusted,
	model.ZoneTypeSandbox,
	model.ZoneTypeManagement,
}

type Zone struct {
	Name    string
	Type    model.ZoneType
	VLAN    int
	Subnet  string
	Gateway string
}

// Section is the provider-neutral representation of one named UCI section.
// It stays internal to this concrete capability and is never exposed in CLI
// output.
type Section struct {
	Name    string
	Type    string
	Options map[string]string
	Lists   map[string][]string
}

type DesiredState struct {
	ManagementAddress string
	ManagementNetwork string
	ManagementNetmask string
	ManagementGateway string
	ControllerAddress string
	Zones             []Zone
	Network           []Section
	Firewall          []Section
}

func DesiredFromSite(site model.Site) (DesiredState, error) {
	return DesiredFromSiteWithServices(site, clientservices.Modules{})
}

func DesiredFromSiteWithServices(site model.Site, services clientservices.Modules, policies ...*CompositionPolicy) (DesiredState, error) {
	management := site.Gateway.ManagementAddress
	if management == "" {
		management = model.GatewayManagementAddress
	}
	managementNetwork := site.Gateway.ManagementNetwork
	if managementNetwork == "" {
		managementNetwork = model.GatewayManagementNetwork
	}
	managementGateway := site.Gateway.ManagementGateway
	if managementGateway == "" {
		managementGateway = model.GatewayManagementGateway
	}
	controllerAddress := site.Gateway.ControllerAddress
	if controllerAddress == "" {
		controllerAddress = model.GatewayControllerAddress
	}
	managementPrefix, err := netip.ParsePrefix(managementNetwork)
	if err != nil || !managementPrefix.Addr().Is4() || managementPrefix.String() != managementNetwork {
		return DesiredState{}, errors.New("gateway.management_network must be a canonical IPv4 CIDR")
	}
	managementNetmask, err := prefixNetmask(managementPrefix)
	if err != nil {
		return DesiredState{}, err
	}
	managementIP, err := netip.ParseAddr(management)
	if err != nil || !managementIP.Is4() || managementIP.String() != management {
		return DesiredState{}, errors.New("gateway.management_address must be a canonical IPv4 address")
	}
	managementGatewayIP, gatewayErr := netip.ParseAddr(managementGateway)
	controllerIP, controllerErr := netip.ParseAddr(controllerAddress)
	if !managementIP.IsPrivate() || !managementPrefix.Contains(managementIP) {
		return DesiredState{}, errors.New("gateway.management_address must be a HOME private IPv4 address")
	}
	first := managementPrefix.Masked().Addr()
	last := first.As4()
	hostBits := 32 - managementPrefix.Bits()
	lastInt := binary.BigEndian.Uint32(last[:])
	if hostBits > 0 {
		lastInt |= uint32(1<<hostBits) - 1
	}
	binary.BigEndian.PutUint32(last[:], lastInt)
	// The supported /22 HOME binding has fixed reserved endpoints. Keep the
	// generic network/broadcast checks here so alternate valid prefixes remain
	// safe as well; callers supply the fixed HOME contract.
	if managementIP == first || managementIP == netip.AddrFrom4(last) || managementIP == netip.MustParseAddr(model.GatewayManagementGateway) || managementIP == netip.MustParseAddr(model.GatewayControllerAddress) || managementIP == netip.MustParseAddr("192.168.4.5") {
		return DesiredState{}, errors.New("gateway.management_address must be a usable HOME address without reserved bindings")
	}
	if gatewayErr != nil || !managementGatewayIP.Is4() || !managementPrefix.Contains(managementGatewayIP) || managementGatewayIP == managementIP {
		return DesiredState{}, errors.New("gateway.management_gateway must be a distinct IPv4 address in management_network")
	}
	if controllerErr != nil || !controllerIP.Is4() || !managementPrefix.Contains(controllerIP) {
		return DesiredState{}, errors.New("gateway.controller_address must be an IPv4 address in management_network")
	}

	byType := make(map[model.ZoneType]model.Zone, len(site.Network.Zones))
	seenVLAN := map[int]string{}
	seenSubnet := map[string]string{}
	for _, zone := range site.Network.Zones {
		if _, exists := byType[zone.Type]; exists {
			return DesiredState{}, fmt.Errorf("duplicate network zone type %q", zone.Type)
		}
		prefix, err := netip.ParsePrefix(zone.Network)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 || prefix.String() != zone.Network {
			return DesiredState{}, fmt.Errorf("zone %s has malformed IPv4 subnet %q", zone.Name, zone.Network)
		}
		gateway, err := netip.ParseAddr(zone.Gateway)
		if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
			return DesiredState{}, fmt.Errorf("zone %s gateway %q is outside subnet %q", zone.Name, zone.Gateway, zone.Network)
		}
		if previous, exists := seenVLAN[zone.VLAN]; exists {
			return DesiredState{}, fmt.Errorf("zones %s and %s share VLAN %d", previous, zone.Name, zone.VLAN)
		}
		if previous, exists := seenSubnet[zone.Network]; exists {
			return DesiredState{}, fmt.Errorf("zones %s and %s share subnet %s", previous, zone.Name, zone.Network)
		}
		seenVLAN[zone.VLAN], seenSubnet[zone.Network] = zone.Name, zone.Name
		byType[zone.Type] = zone
	}
	zones := make([]Zone, 0, len(zoneOrder))
	for _, typ := range zoneOrder {
		zone, ok := byType[typ]
		if !ok {
			return DesiredState{}, fmt.Errorf("required network zone %q is missing", typ)
		}
		zones = append(zones, Zone{Name: zone.Name, Type: zone.Type, VLAN: zone.VLAN, Subnet: zone.Network, Gateway: zone.Gateway})
	}
	state := DesiredState{ManagementAddress: management, ManagementNetwork: managementNetwork, ManagementNetmask: managementNetmask, ManagementGateway: managementGateway, ControllerAddress: controllerAddress, Zones: zones}
	state.Network = networkSections(zones, management, managementNetmask, managementGateway)
	state.Firewall = firewallSections(zones, managementNetwork, controllerAddress)
	if len(policies) > 0 && policies[0] != nil {
		p := policies[0]
		if (p.ControllerLABAddress == "") != (p.ControllerLABMAC == "") {
			return DesiredState{}, errors.New("controller LAB address and MAC must be supplied together")
		}
		mgmt, servers := zones[5], zones[2]
		state.Firewall = append(state.Firewall, Section{Name: "boetticher_allow_trusted_proxmox_https", Type: "rule", Options: map[string]string{"name": "Boetticher TRUSTED Proxmox HTTPS", "src": "mgmt", "src_ip": model.ProxmoxManagementAddress + "/32", "dest_ip": mgmt.Gateway + "/32", "proto": "tcp", "dest_port": "443", "target": "ACCEPT"}})
		if p.ControllerLABAddress != "" {
			ip := net.ParseIP(p.ControllerLABAddress)
			mac, macErr := net.ParseMAC(p.ControllerLABMAC)
			if ip == nil || ip.To4() == nil || macErr != nil || len(mac) != 6 {
				return DesiredState{}, errors.New("controller LAB binding is invalid")
			}
			if !netip.MustParsePrefix(servers.Subnet).Contains(netip.MustParseAddr(ip.To4().String())) {
				return DesiredState{}, errors.New("controller LAB address must be in SERVERS")
			}
			ok := false
			if services.DHCP != nil {
				for _, reservation := range services.DHCP.Reservations {
					if reservation.Zone == "SERVERS" && reservation.Address == ip.To4().String() && strings.EqualFold(reservation.MAC, p.ControllerLABMAC) {
						ok = true
						break
					}
				}
			}
			if !ok {
				return DesiredState{}, errors.New("controller LAB binding does not match a SERVERS reservation")
			}
			state.Firewall = append(state.Firewall, Section{Name: "boetticher_allow_controller_lab_ssh", Type: "rule", Options: map[string]string{"name": "Boetticher Controller LAB SSH", "src": "servers", "src_ip": ip.To4().String() + "/32", "src_mac": strings.ToLower(p.ControllerLABMAC), "dest": "mgmt", "dest_ip": model.ProxmoxManagementAddress + "/32", "proto": "tcp", "dest_port": "22", "target": "ACCEPT"}})
		}
	}
	serviceState, err := ServiceStateFromModules(site, services)
	if err != nil {
		return DesiredState{}, err
	}
	state.Firewall = append(state.Firewall, serviceState.Firewall...)
	if services.Tailnet != nil && services.Tailnet.Enabled {
		state.Firewall = append(state.Firewall, tailnetFirewallSections(managementNetwork)...)
	}
	return state, nil
}

// DesiredFromSiteWithServicesAndVPN extends the shared projection with the
// retained, validated provider profile required to preserve active VPN policy.
func DesiredFromSiteWithServicesAndVPN(site model.Site, services clientservices.Modules, profile VPNProfile, policies ...*CompositionPolicy) (DesiredState, error) {
	state, err := DesiredFromSiteWithServices(site, services, policies...)
	if err != nil {
		return DesiredState{}, err
	}
	if services.VPN == nil || !clientservices.Enabled(services.VPN.Enabled) {
		return state, nil
	}
	network, firewall := vpnSections(site, services, profile)
	state.Network = append(state.Network, network...)
	state.Firewall = append(state.Firewall, firewall...)
	return state, nil
}

func prefixNetmask(prefix netip.Prefix) (string, error) {
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return "", errors.New("gateway.management_network must be an IPv4 prefix")
	}
	mask := net.CIDRMask(bits, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]), nil
}

func networkSections(zones []Zone, managementAddress, managementNetmask, managementGateway string) []Section {
	sections := []Section{
		{Name: "boetticher_home", Type: "interface", Options: map[string]string{"device": "eth0", "proto": "static", "ipaddr": managementAddress, "netmask": managementNetmask, "gateway": managementGateway, "delegate": "0", "ipv6": "0"}, Lists: map[string][]string{}},
		{Name: "boetticher_lab_trunk", Type: "device", Options: map[string]string{"name": "br-lab", "type": "bridge", "ipv6": "0"}, Lists: map[string][]string{"ports": {"eth1"}}},
	}
	for _, zone := range zones {
		name := strings.ToLower(zone.Name)
		sections = append(sections,
			Section{Name: "boetticher_vlan_" + name, Type: "bridge-vlan", Options: map[string]string{"device": "br-lab", "vlan": strconv.Itoa(zone.VLAN)}, Lists: map[string][]string{"ports": {"eth1:t"}}},
			Section{Name: "boetticher_iface_" + name, Type: "interface", Options: map[string]string{"device": "br-lab." + strconv.Itoa(zone.VLAN), "proto": "static", "ipaddr": zone.Gateway, "netmask": "255.255.255.0", "delegate": "0", "ipv6": "0"}, Lists: map[string][]string{}},
		)
	}
	return sections
}

func firewallSections(zones []Zone, managementNetwork, controllerAddress string) []Section {
	sections := make([]Section, 0, len(zones)*2+17)
	sections = append(sections, Section{Name: "boetticher_home_wan", Type: "zone", Options: map[string]string{"name": "home_wan", "input": "DROP", "output": "ACCEPT", "forward": "DROP", "family": "ipv4", "masq": "1", "mtu_fix": "1"}, Lists: map[string][]string{"network": {"boetticher_home"}}})
	for _, zone := range zones {
		name := strings.ToLower(zone.Name)
		options := map[string]string{"name": name, "input": "DROP", "output": "ACCEPT", "forward": "DROP", "family": "ipv4"}
		sections = append(sections, Section{Name: "boetticher_zone_" + name, Type: "zone", Options: options, Lists: map[string][]string{"network": {"boetticher_iface_" + name}}})
		sections = append(sections, Section{Name: "boetticher_allow_" + name + "_ping", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " gateway ping", "src": name, "proto": "icmp", "icmp_type": "echo-request", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
	}
	for _, zone := range zones {
		name := strings.ToLower(zone.Name)
		if zone.Type != model.ZoneTypeTransit {
			sections = append(sections, Section{Name: "boetticher_deny_" + name + "_home_management", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " deny HOME management", "src": name, "dest": "home_wan", "dest_ip": managementNetwork, "family": "ipv4", "target": "DROP"}, Lists: map[string][]string{}})
			sections = append(sections, Section{Name: "boetticher_forward_" + name + "_home_wan", Type: "forwarding", Options: map[string]string{"src": name, "dest": "home_wan", "family": "ipv4"}, Lists: map[string][]string{}})
		}
		if zone.Type == model.ZoneTypeTrusted {
			sections = append(sections, Section{Name: "boetticher_allow_trusted_proxmox_ssh", Type: "rule", Options: map[string]string{"name": "Boetticher TRUSTED Proxmox SSH", "src": name, "dest": "mgmt", "dest_ip": model.ProxmoxManagementAddress + "/32", "proto": "tcp", "dest_port": "22", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
			for _, target := range model.TrustedRoutedDestinations() {
				destination := strings.ToLower(target.Zone)
				sections = append(sections, Section{Name: "boetticher_forward_trusted_" + destination, Type: "forwarding", Options: map[string]string{"src": name, "dest": destination, "family": "ipv4"}, Lists: map[string][]string{}})
			}
		}
		if zone.Type == model.ZoneTypeManagement {
			for _, target := range zones {
				if target.Type == zone.Type {
					continue
				}
				targetName := strings.ToLower(target.Name)
				sections = append(sections, Section{Name: "boetticher_forward_mgmt_" + targetName, Type: "forwarding", Options: map[string]string{"src": name, "dest": targetName, "family": "ipv4"}, Lists: map[string][]string{}})
			}
		}
	}
	// HOME management is the only provider administrative ingress. LAB zones
	// retain their default DROP input stance.
	sections = append(sections, Section{Name: "boetticher_allow_home_api", Type: "rule", Options: map[string]string{"name": "Boetticher Controller management API", "src": "home_wan", "src_ip": controllerAddress + "/32", "proto": "tcp", "dest_port": "443", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
	return sections
}

func sortedSectionNames(sections []Section) []string {
	names := make([]string, 0, len(sections))
	for _, section := range sections {
		names = append(names, section.Name)
	}
	sort.Strings(names)
	return names
}
