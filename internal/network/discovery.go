package network

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	ClassUpstream       = "upstream/bootstrap"
	ClassCandidate      = "eligible trunk candidate"
	ClassConfigured     = "configured Lab-in-a-Box trunk"
	ClassIneligible     = "ineligible/in-use"
	ClassAmbiguous      = "ambiguous"
	ModeVirtualOnly     = "virtual-only"
	ModePhysicalTrunk   = "physical-trunk"
	ModeSelectionNeeded = "selection-required"
)

type Interface struct {
	Name             string   `json:"name"`
	PermanentMAC     string   `json:"permanent_mac,omitempty"`
	PCIAddress       string   `json:"pci_address,omitempty"`
	Driver           string   `json:"driver,omitempty"`
	Model            string   `json:"model,omitempty"`
	SpeedMbps        int      `json:"speed_mbps,omitempty"`
	Carrier          bool     `json:"carrier"`
	Addresses        []string `json:"addresses,omitempty"`
	IPv6Addresses    []string `json:"ipv6_addresses,omitempty"`
	PhysicalEthernet bool     `json:"physical_ethernet"`
	DefaultRoute     bool     `json:"default_route"`
	Bridge           string   `json:"bridge,omitempty"`
	Bond             string   `json:"bond,omitempty"`
	ManagementPath   bool     `json:"management_path"`
}

type Evidence struct {
	Interfaces            []Interface `json:"interfaces"`
	DefaultRouteInterface string      `json:"default_route_interface"`
	BootstrapInterface    string      `json:"bootstrap_interface"`
	BootstrapAddress      string      `json:"bootstrap_address"`
	VMbr0Members          []string    `json:"vmbr0_members"`
	ConfiguredTrunk       string      `json:"configured_trunk,omitempty"`
}

type ClassifiedInterface struct {
	Interface
	Classification string `json:"classification"`
	Reason         string `json:"reason"`
}

type Discovery struct {
	Mode             string                `json:"mode"`
	BootstrapAddress string                `json:"bootstrap_address,omitempty"`
	Upstream         Interface             `json:"upstream"`
	Trunk            *Interface            `json:"trunk,omitempty"`
	Candidates       []Interface           `json:"candidates,omitempty"`
	Interfaces       []ClassifiedInterface `json:"interfaces"`
	Status           string                `json:"status"`
	Explanation      string                `json:"explanation"`
}

func Analyze(evidence Evidence, explicitTrunk string) (Discovery, error) {
	if len(evidence.Interfaces) == 0 {
		return Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (no physical interface evidence)")
	}
	byName := make(map[string]Interface, len(evidence.Interfaces))
	for _, iface := range evidence.Interfaces {
		if iface.Name == "" {
			return Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (unnamed interface evidence)")
		}
		byName[iface.Name] = iface
	}
	upstreamName := evidence.BootstrapInterface
	if upstreamName == "" {
		upstreamName = evidence.DefaultRouteInterface
	}
	if upstreamName == "" || evidence.DefaultRouteInterface != upstreamName || evidence.BootstrapInterface != upstreamName || !contains(evidence.VMbr0Members, upstreamName) {
		return Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous")
	}
	upstream, ok := byName[upstreamName]
	if !ok || !upstream.PhysicalEthernet {
		return Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (bootstrap path is not a physical Ethernet device)")
	}
	if upstream.PermanentMAC == "" && upstream.PCIAddress == "" {
		return Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (no stable hardware identity is available)")
	}
	if evidence.BootstrapAddress == "" || !hasAddress(upstream.Addresses, evidence.BootstrapAddress) {
		return Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (bootstrap address is not present on the selected interface)")
	}

	classified := make([]ClassifiedInterface, 0, len(evidence.Interfaces))
	candidates := make([]Interface, 0)
	var configured *Interface
	for _, iface := range evidence.Interfaces {
		classification, reason := classify(iface, upstreamName, evidence.VMbr0Members, evidence.ConfiguredTrunk)
		classified = append(classified, ClassifiedInterface{Interface: iface, Classification: classification, Reason: reason})
		if classification == ClassConfigured {
			copy := iface
			configured = &copy
		}
		if classification == ClassCandidate {
			candidates = append(candidates, iface)
		}
	}
	sort.Slice(classified, func(i, j int) bool { return classified[i].Name < classified[j].Name })
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })

	result := Discovery{BootstrapAddress: evidence.BootstrapAddress, Upstream: upstream, Candidates: candidates, Interfaces: classified, Status: "PASS"}
	switch {
	case explicitTrunk != "":
		selected, found := byName[explicitTrunk]
		if !found {
			return Discovery{}, fmt.Errorf("selected trunk interface %q was not discovered", explicitTrunk)
		}
		if configured != nil && configured.Name == explicitTrunk {
			result.Mode = ModePhysicalTrunk
			result.Trunk = &selected
			result.Explanation = "explicit selection matches the persisted Lab-in-a-Box trunk binding"
			return result, nil
		}
		if !containsInterface(candidates, explicitTrunk) {
			return Discovery{}, fmt.Errorf("selected trunk interface %q is not an eligible unused physical Ethernet interface", explicitTrunk)
		}
		result.Mode = ModePhysicalTrunk
		result.Trunk = &selected
		result.Explanation = "explicit operator selection passed safety checks"
		return result, nil
	case configured != nil:
		result.Mode = ModePhysicalTrunk
		result.Trunk = configured
		result.Explanation = "persisted Lab-in-a-Box trunk binding is present"
		return result, nil
	case len(candidates) == 0:
		result.Mode = ModeVirtualOnly
		result.Explanation = "no eligible unused physical Ethernet interface; vmbr1 remains virtual-only"
		return result, nil
	case len(candidates) == 1:
		result.Mode = ModePhysicalTrunk
		result.Trunk = &candidates[0]
		result.Explanation = "exactly one eligible unused physical Ethernet interface was found"
		return result, nil
	default:
		result.Mode = ModeSelectionNeeded
		result.Status = "HOLD"
		result.Explanation = "more than one eligible trunk interface remains; explicit operator selection is required"
		return result, nil
	}
}

func classify(iface Interface, upstream string, vmbr0Members []string, configuredTrunk string) (string, string) {
	if iface.Name == upstream {
		return ClassUpstream, "current upstream/bootstrap interface"
	}
	if !iface.PhysicalEthernet {
		return ClassIneligible, "not a physical Ethernet interface"
	}
	if iface.ManagementPath || iface.DefaultRoute {
		return ClassIneligible, "has a management or default-route dependency"
	}
	if (iface.Bridge != "" && !(iface.Name == configuredTrunk && iface.Bridge == "vmbr1")) || iface.Bond != "" || contains(vmbr0Members, iface.Name) {
		return ClassIneligible, "already belongs to a bridge or bond"
	}
	if len(iface.Addresses) != 0 {
		return ClassIneligible, "has configured addresses"
	}
	for _, address := range iface.IPv6Addresses {
		parsed := net.ParseIP(strings.TrimSpace(strings.Split(address, "/")[0]))
		if parsed != nil && !parsed.IsLinkLocalUnicast() {
			return ClassIneligible, "has a non-link-local IPv6 address"
		}
	}
	if iface.PermanentMAC == "" && iface.PCIAddress == "" {
		return ClassAmbiguous, "no stable hardware identity is available"
	}
	if iface.Name == configuredTrunk && iface.Bridge == "vmbr1" {
		return ClassConfigured, "persisted Lab-in-a-Box trunk binding"
	}
	return ClassCandidate, "unused physical Ethernet interface with stable hardware identity"
}

func hasAddress(addresses []string, wanted string) bool {
	wanted = strings.TrimSpace(wanted)
	for _, address := range addresses {
		if strings.TrimSpace(strings.Split(address, "/")[0]) == wanted {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsInterface(values []Interface, wanted string) bool {
	for _, value := range values {
		if value.Name == wanted {
			return true
		}
	}
	return false
}
