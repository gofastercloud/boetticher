// Package firewallmodule contains the concrete Phase 4A firewall capability.
// OpenWrt is intentionally an implementation detail of this package.
package firewallmodule

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

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
	Zones             []Zone
	Network           []Section
	Firewall          []Section
}

func DesiredFromSite(site model.Site) (DesiredState, error) {
	management := site.Gateway.ManagementAddress
	if management == "" {
		management = model.GatewayManagementAddress
	}
	managementIP, err := netip.ParseAddr(management)
	if err != nil || !managementIP.Is4() || managementIP.String() != management {
		return DesiredState{}, errors.New("gateway.management_address must be a canonical IPv4 address")
	}
	if managementIP.IsPrivate() == false {
		return DesiredState{}, errors.New("gateway.management_address must be a HOME private IPv4 address")
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
	state := DesiredState{ManagementAddress: management, Zones: zones}
	state.Network = networkSections(zones)
	state.Firewall = firewallSections(zones)
	return state, nil
}

func networkSections(zones []Zone) []Section {
	sections := []Section{{Name: "boetticher_lab_trunk", Type: "device", Options: map[string]string{"name": "br-lab", "type": "bridge"}, Lists: map[string][]string{"ports": {"eth1"}}}}
	for _, zone := range zones {
		name := strings.ToLower(zone.Name)
		sections = append(sections,
			Section{Name: "boetticher_vlan_" + name, Type: "bridge-vlan", Options: map[string]string{"device": "br-lab", "vlan": strconv.Itoa(zone.VLAN)}, Lists: map[string][]string{"ports": {"eth1:t"}}},
			Section{Name: "boetticher_iface_" + name, Type: "interface", Options: map[string]string{"device": "br-lab." + strconv.Itoa(zone.VLAN), "proto": "static", "ipaddr": zone.Gateway, "netmask": "255.255.255.0", "delegate": "0"}, Lists: map[string][]string{}},
		)
	}
	return sections
}

func firewallSections(zones []Zone) []Section {
	sections := make([]Section, 0, len(zones)*2+16)
	for _, zone := range zones {
		name := strings.ToLower(zone.Name)
		options := map[string]string{"name": name, "input": "DROP", "output": "ACCEPT", "forward": "DROP", "family": "ipv4"}
		if zone.Type != model.ZoneTypeTransit {
			options["masq"] = "1"
			options["mtu_fix"] = "1"
		}
		sections = append(sections, Section{Name: "boetticher_zone_" + name, Type: "zone", Options: options, Lists: map[string][]string{"network": {"boetticher_iface_" + name}}})
		sections = append(sections, Section{Name: "boetticher_allow_" + name + "_ping", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " gateway ping", "src": name, "proto": "icmp", "icmp_type": "echo-request", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
	}
	for _, zone := range zones {
		name := strings.ToLower(zone.Name)
		if zone.Type != model.ZoneTypeTransit {
			sections = append(sections, Section{Name: "boetticher_forward_" + name + "_wan", Type: "forwarding", Options: map[string]string{"src": name, "dest": "wan", "family": "ipv4"}, Lists: map[string][]string{}})
		}
		if zone.Type == model.ZoneTypeTrusted {
			sections = append(sections, Section{Name: "boetticher_forward_trusted_servers", Type: "forwarding", Options: map[string]string{"src": name, "dest": "servers", "family": "ipv4"}, Lists: map[string][]string{}})
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
	sections = append(sections, Section{Name: "boetticher_allow_home_api", Type: "rule", Options: map[string]string{"name": "Boetticher HOME management API", "src": "lan", "proto": "tcp", "dest_port": "443", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
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
