package firewall

import (
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

type HostIsolationGuest struct {
	VMID       int                 `json:"vmid"`
	Name       string              `json:"name"`
	Module     string              `json:"module"`
	VLAN       int                 `json:"vlan"`
	Address    string              `json:"address"`
	MAC        string              `json:"mac"`
	GatewayMAC string              `json:"gateway_mac"`
	Gateway    string              `json:"gateway"`
	Peers      []HostIsolationPeer `json:"peers"`
	Services   []HostIsolationPeer `json:"services"`
	HTTPS      bool                `json:"https"`
}

type HostIsolationPeer struct {
	VMID     int      `json:"vmid"`
	Address  string   `json:"address"`
	MAC      string   `json:"mac"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
	Incoming bool     `json:"incoming"`
}

type HostIsolation struct {
	Bridge      string               `json:"bridge"`
	GatewayVMID int                  `json:"gateway_vmid"`
	GatewayMAC  string               `json:"gateway_mac"`
	Trunk       model.PhysicalNIC    `json:"trunk"`
	Selected    []HostIsolationGuest `json:"selected"`
	Anchors     []HostIsolationGuest `json:"anchors"`
}

func HostIsolationForSite(s model.Site) HostIsolation {
	plan := HostIsolation{Bridge: "vmbr1", GatewayVMID: model.ProxmoxVMID, Trunk: s.PhysicalNetwork.Trunk, Selected: []HostIsolationGuest{}, Anchors: []HostIsolationGuest{}}
	for _, iface := range gatewayInterfaces(s) {
		if iface.Name == "sandbox0" {
			plan.GatewayMAC = iface.MAC
		}
	}
	for _, c := range s.PlatformComponents() {
		if c.ProductOwned && c.Module != "" {
			if c.Module == "firewall" {
				for _, iface := range gatewayInterfaces(s) {
					if iface.Name != "wan0" {
						for _, z := range s.Network.Zones {
							if strings.ToLower(z.Name)+"0" == iface.Name {
								plan.Anchors = append(plan.Anchors, HostIsolationGuest{VMID: c.VMID, Name: c.Name, Module: c.Module, MAC: iface.MAC, VLAN: z.VLAN})
							}
						}
					}
				}
			} else {
				for _, z := range s.Network.Zones {
					if z.Name == c.Zone {
						plan.Anchors = append(plan.Anchors, HostIsolationGuest{VMID: c.VMID, Name: c.Name, Module: c.Module, MAC: componentSourceMAC(s, c), VLAN: z.VLAN})
					}
				}
			}
		}
		if !c.ProductOwned || s.ModuleConfig[c.Module].Network != model.ModuleNetworkAirVPN {
			continue
		}
		guest := HostIsolationGuest{VMID: c.VMID, Name: c.Name, Module: c.Module, Address: c.Address, MAC: componentSourceMAC(s, c), HTTPS: c.URL != "", Peers: []HostIsolationPeer{}, Services: []HostIsolationPeer{}}
		for _, iface := range gatewayInterfaces(s) {
			if iface.Name == strings.ToLower(c.Zone)+"0" {
				guest.GatewayMAC = iface.MAC
				guest.Gateway = strings.Split(iface.Address, "/")[0]
				for _, zone := range s.Network.Zones {
					if zone.Name == c.Zone {
						guest.VLAN = zone.VLAN
					}
				}
			}
		}
		for _, declaration := range s.Declarations {
			for _, intent := range declaration.NetworkIntents {
				source, ok := componentReference(s, intent.Source)
				if !ok {
					continue
				}
				for _, destination := range componentReferences(s, intent.Destination) {
					peer, incoming := destination, false
					if destination.Name == c.Name {
						peer, incoming = source, true
					} else if source.Name != c.Name {
						continue
					}
					if peer.Name != c.Name {
						service := HostIsolationPeer{VMID: peer.VMID, Address: peer.Address, MAC: componentSourceMAC(s, peer), Protocol: intent.Protocol, Ports: intent.Ports, Incoming: incoming}
						guest.Services = append(guest.Services, service)
						if peer.Zone == c.Zone {
							guest.Peers = append(guest.Peers, service)
						}
					}
				}
			}
		}
		plan.Selected = append(plan.Selected, guest)
	}
	return plan
}
