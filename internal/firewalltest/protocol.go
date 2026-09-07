// Package firewalltest contains the fixed Phase 4A packet-test contract.
//
// The expectation table in this package is deliberately independent from the
// firewall renderer. Runtime addresses and VLANs are supplied by the
// authoritative Host/lab intent; expected outcomes are fixed here.
package firewalltest

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	ProtocolVersion = 1
	HelperVersion   = "boetticher-firewall-test-host/v6"
	HelperPath      = "/usr/local/libexec/boetticher-firewall-test-host"
	HelperCommand   = HelperPath
	LockPath        = "/run/boetticher/firewall-test.lock"
	PublicHost      = "example.com"
	PublicPath      = "/"
	TCPPort         = 41991
	UDPPort         = 41992
	HTTPSPort       = 443
	ProxmoxPort     = 8006
	SSHPort         = 22
)

var ZoneOrder = []string{"TRANSIT", "INFRA", "SERVERS", "TRUSTED", "SANDBOX", "MGMT"}

type Zone struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	VLAN         int    `json:"vlan"`
	Subnet       string `json:"subnet"`
	Gateway      string `json:"gateway"`
	Address      string `json:"address,omitempty"`
	DHCPMode     string `json:"dhcp_mode,omitempty"`
	ClientMAC    string `json:"client_mac,omitempty"`
	ExpectedName string `json:"expected_name,omitempty"`
}

type Request struct {
	Version        int    `json:"version"`
	Action         string `json:"action"`
	Zones          []Zone `json:"zones,omitempty"`
	PublicAddress  string `json:"public_address,omitempty"`
	PublicHost     string `json:"public_host,omitempty"`
	HomeProxmox    string `json:"home_proxmox,omitempty"`
	HomeController string `json:"home_controller,omitempty"`
	ProviderHome   string `json:"provider_home,omitempty"`
	Service        string `json:"service,omitempty"`
	DNSHost        string `json:"dns_host,omitempty"`
}

type Result struct {
	Name     string `json:"name"`
	Group    string `json:"group"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

type Response struct {
	Version        int      `json:"version"`
	OK             bool     `json:"ok"`
	CleanupOK      bool     `json:"cleanup_ok"`
	CleanupFound   bool     `json:"cleanup_found,omitempty"`
	CleanupRemoved bool     `json:"cleanup_removed,omitempty"`
	Results        []Result `json:"results,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type Expectation struct {
	Name     string
	Group    string
	Source   string
	Target   string
	Protocol string
	Expected string
}

// ReferenceExpectations is the fixed Phase 4A contract. It intentionally does
// not inspect firewallmodule.DesiredState or any renderer output.
func ReferenceExpectations() []Expectation {
	result := []Expectation{}
	for _, zone := range ZoneOrder {
		result = append(result, Expectation{Name: "gateway/" + zone, Group: "Gateway access", Source: zone, Target: zone + " gateway", Protocol: "icmp", Expected: "allow"})
	}
	for _, zone := range []string{"INFRA", "SERVERS", "TRUSTED", "SANDBOX", "MGMT"} {
		result = append(result, Expectation{Name: "internet/" + zone, Group: "Ordinary Internet egress", Source: zone, Target: "public HTTPS", Protocol: "https", Expected: "allow"})
	}
	result = append(result, Expectation{Name: "internet/TRANSIT", Group: "Ordinary Internet egress", Source: "TRANSIT", Target: "public HTTPS", Protocol: "https", Expected: "deny"})
	for _, item := range []struct {
		name, source, target, protocol, expected string
	}{
		{"trusted-to-servers-tcp", "TRUSTED", "SERVERS", "tcp", "allow"},
		{"servers-to-trusted-tcp", "SERVERS", "TRUSTED", "tcp", "deny"},
		{"mgmt-to-infra-tcp", "MGMT", "INFRA", "tcp", "allow"},
		{"infra-to-trusted-tcp", "INFRA", "TRUSTED", "tcp", "deny"},
		{"sandbox-to-servers-tcp", "SANDBOX", "SERVERS", "tcp", "deny"},
		{"sandbox-to-trusted-tcp", "SANDBOX", "TRUSTED", "tcp", "deny"},
		{"sandbox-to-infra-tcp", "SANDBOX", "INFRA", "tcp", "deny"},
		{"trusted-to-servers-udp", "TRUSTED", "SERVERS", "udp", "allow"},
		{"sandbox-to-servers-udp", "SANDBOX", "SERVERS", "udp", "deny"},
	} {
		result = append(result, Expectation{Name: "inter-zone/" + item.name, Group: "Directional inter-zone policy", Source: item.source, Target: item.target, Protocol: item.protocol, Expected: item.expected})
	}
	for _, zone := range []string{"INFRA", "SERVERS", "TRUSTED", "SANDBOX", "MGMT"} {
		result = append(result, Expectation{Name: "home/proxmox-" + strings.ToLower(zone), Group: "HOME protection", Source: zone, Target: "Proxmox HOME", Protocol: "tcp", Expected: "deny"})
	}
	result = append(result, Expectation{Name: "home/sandbox-controller-ssh", Group: "HOME protection", Source: "SANDBOX", Target: "Controller HOME", Protocol: "tcp", Expected: "deny"})
	result = append(result, Expectation{Name: "admin/controller-provider-home", Group: "Appliance administration", Source: "Controller", Target: "firewall HOME", Protocol: "https", Expected: "allow"})
	for _, zone := range ZoneOrder {
		result = append(result,
			Expectation{Name: "admin/" + strings.ToLower(zone) + "-provider-home", Group: "Appliance administration", Source: zone, Target: "firewall HOME", Protocol: "tcp", Expected: "deny"},
			Expectation{Name: "admin/" + strings.ToLower(zone) + "-provider-gateway", Group: "Appliance administration", Source: zone, Target: zone + " gateway", Protocol: "tcp", Expected: "deny"},
		)
	}
	result = append(result, Expectation{Name: "admin/host-provider-home", Group: "Appliance administration", Source: "Host HOME", Target: "firewall HOME", Protocol: "tcp", Expected: "deny"})
	return result
}

func ValidateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return errors.New("unsupported firewall test request")
	}
	if request.Action != "run" && request.Action != "cleanup" && request.Action != "client-services" {
		return errors.New("unsupported firewall test action")
	}
	if request.Action == "cleanup" {
		return nil
	}
	if request.Action == "client-services" {
		if request.Service != "dhcp" && request.Service != "dns" {
			return errors.New("client-services request requires DHCP or DNS service")
		}
		if len(request.Zones) != len(ZoneOrder) {
			return errors.New("client-services request must contain six zones")
		}
	}
	if len(request.Zones) != len(ZoneOrder) {
		return errors.New("firewall test request must contain six zones")
	}
	seen := map[string]bool{}
	seenVLAN := map[int]bool{}
	types := map[string]string{"TRANSIT": "transit", "INFRA": "infrastructure", "SERVERS": "servers", "TRUSTED": "trusted", "SANDBOX": "sandbox", "MGMT": "management"}
	for _, expected := range ZoneOrder {
		found := false
		for _, zone := range request.Zones {
			if zone.Name != expected {
				continue
			}
			found = true
			if seen[zone.Name] {
				return fmt.Errorf("firewall test request contains duplicate zone %s", zone.Name)
			}
			seen[zone.Name] = true
			if zone.Type != types[zone.Name] {
				return fmt.Errorf("firewall test zone %s has an unexpected semantic type", zone.Name)
			}
			if seenVLAN[zone.VLAN] {
				return fmt.Errorf("firewall test request reuses VLAN %d", zone.VLAN)
			}
			seenVLAN[zone.VLAN] = true
			prefix, err := netip.ParsePrefix(zone.Subnet)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 || prefix.String() != zone.Subnet {
				return fmt.Errorf("firewall test zone %s has an invalid IPv4 /24 subnet", zone.Name)
			}
			gateway, err := netip.ParseAddr(zone.Gateway)
			if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
				return fmt.Errorf("firewall test zone %s has an invalid gateway", zone.Name)
			}
			if zone.VLAN < 1 || zone.VLAN > 4094 {
				return fmt.Errorf("firewall test zone %s has an invalid VLAN", zone.Name)
			}
			if request.Action == "run" {
				publicAddress, publicErr := netip.ParseAddr(request.PublicAddress)
				if publicErr != nil || !publicAddress.Is4() || request.PublicHost != PublicHost {
					return errors.New("firewall test request has an invalid public HTTPS target")
				}
			}
			break
		}
		if !found {
			return fmt.Errorf("firewall test request is missing zone %s", expected)
		}
	}
	if request.Action == "run" {
		for _, value := range []string{request.HomeProxmox, request.HomeController, request.ProviderHome} {
			address, err := netip.ParseAddr(value)
			if err != nil || !address.Is4() {
				return errors.New("firewall test request contains an invalid HOME endpoint")
			}
		}
	}
	return nil
}

func SortedResults(results []Result) []Result {
	copyResults := append([]Result(nil), results...)
	sort.SliceStable(copyResults, func(i, j int) bool { return copyResults[i].Name < copyResults[j].Name })
	return copyResults
}
