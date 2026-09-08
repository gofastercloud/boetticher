package firewallmodule

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
)

// CompositionPolicy is provider-neutral prepared policy. ProtectedIPv4 is
// used only when it is explicitly supplied; an absent policy retains the
// packaged permanent baseline from DefaultSafetyConfig.
type CompositionPolicy struct {
	ProtectedIPv4 []string
}

// Ownership names the exact native sections produced for each package. A
// These are the exact sections produced by this composition.
type Ownership struct {
	Sections   map[string][]string
	SafetySets []string
}

// ApplianceComposition is the complete desired appliance projection. All
// capability consumers receive this same aggregate so composing one service
// cannot erase another service's sections.
type ApplianceComposition struct {
	DesiredState
	DHCP        []Section
	Stubby      []Section
	System      []Section
	Safety      SafetyConfig
	DeclaredVPN VPNDeclaration
	Ownership   Ownership
}

// VPNDeclaration retains validated operator references even while VPN is
// disabled. Active safety sets intentionally remain empty until it is enabled.
type VPNDeclaration struct {
	Clients  []string
	Forwards []clientservices.VPNForward
}

// ComposeAppliance builds all native packages and safety state in one pure
// operation. WireGuard/profile material is deliberately not composed here.
func ComposeAppliance(site model.Site, modules clientservices.Modules, policy *CompositionPolicy) (ApplianceComposition, error) {
	desired, err := DesiredFromSiteWithServices(site, modules)
	if err != nil {
		return ApplianceComposition{}, err
	}
	services, err := ServiceStateFromModules(site, modules)
	if err != nil {
		return ApplianceComposition{}, err
	}
	safety := DefaultSafetyConfig()
	if policy != nil {
		if policy.ProtectedIPv4 != nil {
			safety.ProtectedIPv4 = append([]string(nil), policy.ProtectedIPv4...)
		}
	}
	safety.HomeIPv4 = []string{desired.ManagementNetwork}
	safety.LabIPv4 = make([]string, 0, len(desired.Zones))
	for _, zone := range desired.Zones {
		safety.LabIPv4 = append(safety.LabIPv4, zone.Subnet)
	}
	declaration := VPNDeclaration{}
	vpnEnabled := modules.VPN != nil && clientservices.Enabled(modules.VPN.Enabled)
	if modules.VPN != nil {
		declaration.Clients = append([]string(nil), modules.VPN.Clients...)
		declaration.Forwards = append([]clientservices.VPNForward(nil), modules.VPN.Forwards...)
		for i := range declaration.Forwards {
			declaration.Forwards[i].Protocols = append([]string(nil), modules.VPN.Forwards[i].Protocols...)
		}
	}
	if vpnEnabled {
		for _, name := range declaration.Clients {
			reservation, ok := clientservices.ResolveReservation(modules, name)
			if !ok {
				return ApplianceComposition{}, fmt.Errorf("modules.vpn client %q does not reference a DHCP reservation", name)
			}
			safety.ClientIPv4 = append(safety.ClientIPv4, reservation.Address)
		}
		for _, forward := range declaration.Forwards {
			reservation, ok := clientservices.ResolveReservation(modules, forward.Reservation)
			if !ok {
				return ApplianceComposition{}, fmt.Errorf("modules.vpn forward %q does not reference a DHCP reservation", forward.Name)
			}
			for _, protocol := range forward.Protocols {
				safety.ForwardTuples = append(safety.ForwardTuples, ForwardTuple{Address: reservation.Address, Protocol: protocol, Port: uint16(forward.Port)})
			}
		}
	}
	if err := safety.Validate(); err != nil {
		return ApplianceComposition{}, err
	}
	safetySections, err := SafetySections(safety)
	if err != nil {
		return ApplianceComposition{}, err
	}
	desired.Firewall = append(desired.Firewall, safetySections...)
	ownership := ownershipFor(desired.Network, desired.Firewall, services.DHCP, services.Stubby, services.System)
	return ApplianceComposition{DesiredState: desired, DHCP: services.DHCP, Stubby: services.Stubby, System: services.System, Safety: safety, DeclaredVPN: declaration, Ownership: ownership}, nil
}

// VPNProfile is the small provider-neutral projection needed to render the
// native WireGuard interface. It contains retained tunnel material only while
// an apply is in progress; it is never part of lab.yml or operator output.
type VPNProfile struct {
	PrivateKey          string
	Address             string
	PeerPublicKey       string
	PresharedKey        string
	EndpointHost        string
	EndpointPort        int
	MTU                 int
	PersistentKeepalive int
}

// ComposeApplianceWithVPN extends the shared appliance composition with one
// exact WireGuard connection and source-policy routing. The ordinary
// composition remains usable for DNS/DHCP and for protected teardown.
func ComposeApplianceWithVPN(site model.Site, modules clientservices.Modules, policy *CompositionPolicy, profile VPNProfile) (ApplianceComposition, error) {
	if modules.VPN == nil || !clientservices.Enabled(modules.VPN.Enabled) {
		return ComposeAppliance(site, modules, policy)
	}
	if err := ValidateVPNProfile(profile); err != nil {
		return ApplianceComposition{}, err
	}
	composition, err := ComposeAppliance(site, modules, policy)
	if err != nil {
		return ApplianceComposition{}, err
	}
	vpnNetwork, vpnFirewall := vpnSections(site, modules, profile)
	composition.Network = append(composition.Network, vpnNetwork...)
	composition.Firewall = append(composition.Firewall, vpnFirewall...)
	composition.Ownership = ownershipFor(composition.Network, composition.Firewall, composition.DHCP, composition.Stubby, composition.System)
	return composition, nil
}

func ValidateVPNProfile(profile VPNProfile) error {
	if profile.PrivateKey == "" || profile.PeerPublicKey == "" || profile.PresharedKey == "" {
		return fmt.Errorf("VPN profile is missing required WireGuard key material")
	}
	if profile.Address == "" || strings.Contains(profile.Address, ":") {
		return fmt.Errorf("VPN profile must contain one IPv4 tunnel address")
	}
	if profile.EndpointHost == "" || profile.EndpointPort <= 0 || profile.MTU < 576 || profile.MTU > 9000 {
		return fmt.Errorf("VPN profile has invalid endpoint or MTU")
	}
	if profile.PersistentKeepalive < 0 || profile.PersistentKeepalive > 120 {
		return fmt.Errorf("VPN profile has invalid persistent keepalive")
	}
	return nil
}

func ownershipFor(network, firewall, dhcp, stubby, system []Section) Ownership {
	sections := map[string][]string{}
	for packageName, values := range map[string][]Section{"network": network, "firewall": firewall, "dhcp": dhcp, "stubby": stubby, "system": system} {
		names := make([]string, 0, len(values))
		for _, section := range values {
			names = append(names, section.Name)
		}
		sort.Strings(names)
		sections[packageName] = names
	}
	return Ownership{Sections: sections, SafetySets: []string{SafetyProtectedSet, SafetyClientSet, SafetyForwardTCPSet, SafetyForwardUDPSet, SafetyHomeSet, SafetyLabSet}}
}
