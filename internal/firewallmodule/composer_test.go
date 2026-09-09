package firewallmodule

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
)

func compositionModules(enabled bool) clientservices.Modules {
	return clientservices.Modules{
		DNS:  &clientservices.DNSConfig{Enabled: &enabled},
		DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: "peer", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: "10.10.30.225"}}},
		VPN:  &clientservices.VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{"peer"}, Forwards: []clientservices.VPNForward{{Name: "web", Reservation: "peer", Protocols: []string{"tcp", "udp"}, Port: 443}}},
	}
}

func TestComposeApplianceReturnsCompleteSharedProjectionAndExactOwnership(t *testing.T) {
	state, err := ComposeAppliance(model.NewSite("lab", "controller-local", model.GatewayModeManaged), compositionModules(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Network) == 0 || len(state.Firewall) == 0 || len(state.DHCP) == 0 || len(state.Stubby) == 0 || len(state.System) == 0 {
		t.Fatalf("incomplete appliance projection: network=%d firewall=%d dhcp=%d stubby=%d system=%d", len(state.Network), len(state.Firewall), len(state.DHCP), len(state.Stubby), len(state.System))
	}
	if len(state.Safety.ClientIPv4) != 1 || len(state.Safety.ForwardTuples) != 2 {
		t.Fatalf("VPN safety was not resolved: %#v", state.Safety)
	}
	for _, name := range state.Ownership.SafetySets {
		if !containsSection(state.Firewall, name) {
			t.Fatalf("safety set %q is missing from firewall projection", name)
		}
	}
	if got := state.Ownership.Sections["dhcp"]; len(got) == 0 || containsName(got, "boetticher_arbitrary") {
		t.Fatalf("ownership is not an exact generated set: %#v", got)
	}
	for _, names := range state.Ownership.Sections {
		for _, name := range names {
			if strings.HasSuffix(name, "*") {
				t.Fatalf("ownership contains a wildcard: %q", name)
			}
		}
	}
}

func TestComposeApplianceDerivesHomeAndLabSafetyFromDesiredSite(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	site.Gateway.ManagementNetwork = "192.168.8.0/22"
	site.Gateway.ManagementAddress = "192.168.8.1"
	site.Gateway.ManagementGateway = "192.168.8.254"
	site.Gateway.ControllerAddress = "192.168.8.6"
	for i := range site.Network.Zones {
		zone := &site.Network.Zones[i]
		zone.Network = strings.Replace(zone.Network, "10.10.", "10.20.", 1)
		zone.Gateway = strings.Replace(zone.Gateway, "10.10.", "10.20.", 1)
	}
	state, err := ComposeAppliance(site, compositionModules(false), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Safety.HomeIPv4) != 1 || state.Safety.HomeIPv4[0] != "192.168.8.0/22" {
		t.Fatalf("HOME selector not derived from desired site: %#v", state.Safety.HomeIPv4)
	}
	if len(state.Safety.LabIPv4) != len(site.Network.Zones) || state.Safety.LabIPv4[0] != site.Network.Zones[0].Network {
		t.Fatalf("LAB selectors not derived from desired zones: %#v", state.Safety.LabIPv4)
	}
}

func TestComposeApplianceDisabledVPNRetainsDeclarationButClearsActiveSafety(t *testing.T) {
	state, err := ComposeAppliance(model.NewSite("lab", "controller-local", model.GatewayModeManaged), compositionModules(false), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.DeclaredVPN.Clients) != 1 || len(state.DeclaredVPN.Forwards) != 1 {
		t.Fatalf("VPN declaration was discarded on teardown: %#v", state.DeclaredVPN)
	}
	if len(state.Safety.ClientIPv4) != 0 || len(state.Safety.ForwardTuples) != 0 {
		t.Fatalf("disabled VPN retained active permissions: %#v", state.Safety)
	}
	if len(state.Safety.ProtectedIPv4) != len(DefaultSafetyConfig().ProtectedIPv4) {
		t.Fatal("permanent protected baseline was released")
	}
}

func TestComposeApplianceRejectsMalformedReservationAndPolicy(t *testing.T) {
	modules := compositionModules(true)
	modules.VPN.Clients = []string{"missing"}
	if _, err := ComposeAppliance(model.NewSite("lab", "controller-local", model.GatewayModeManaged), modules, nil); err == nil || !strings.Contains(err.Error(), "reservation") {
		t.Fatalf("dangling reservation was accepted: %v", err)
	}
	modules = compositionModules(false)
	if _, err := ComposeAppliance(model.NewSite("lab", "controller-local", model.GatewayModeManaged), modules, &CompositionPolicy{ProtectedIPv4: []string{"10.10.10.225/28"}}); err == nil {
		t.Fatal("non-canonical protected policy was accepted")
	}
}

func TestComposeApplianceWithVPNUsesNativeAirVPNIdentityAndTerminalRules(t *testing.T) {
	enabled := true
	modules := compositionModules(true)
	modules.VPN = &clientservices.VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{"peer"}, Forwards: []clientservices.VPNForward{{Name: "web", Reservation: "peer", Protocols: []string{"tcp"}, Port: 443}}}
	composition, err := ComposeApplianceWithVPN(model.NewSite("lab", "controller-local", model.GatewayModeManaged), modules, nil, VPNProfile{
		PrivateKey: "private", Address: "10.64.12.3/32", PeerPublicKey: "peer", PresharedKey: "shared", EndpointHost: "vpn.example", EndpointPort: 1637, MTU: 1320, PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	var airvpn, terminal bool
	var mtuFix bool
	var redirect Section
	for _, section := range composition.Network {
		if section.Name == "airvpn" && section.Options["proto"] == "wireguard" {
			airvpn = true
		}
		if section.Options["action"] == "unreachable" && section.Options["priority"] == "10100" {
			terminal = true
		}
	}
	for _, section := range composition.Firewall {
		if section.Name == "boetticher_zone_vpn" && section.Options["mtu_fix"] == "1" {
			mtuFix = true
		}
		if section.Type == "redirect" {
			redirect = section
		}
	}
	if !mtuFix {
		t.Fatal("AirVPN zone is missing native MSS clamping")
	}
	if !airvpn || !terminal || redirect.Options["src_dport"] != "443" || redirect.Options["reflection"] != "0" {
		t.Fatalf("VPN composition lost native interface or terminal source rule: %#v", composition.Network)
	}
}

func containsName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func containsSection(sections []Section, want string) bool {
	for _, section := range sections {
		if section.Name == want {
			return true
		}
	}
	return false
}
