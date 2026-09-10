package firewallmodule

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
)

func TestNativeVPNForwardSectionNamesEncodeHyphensAndDots(t *testing.T) {
	if got, want := nativeVPNForwardSectionName("media-qbittorrent"), "boetticher_vpn_forward_nmedia_hqbittorrent"; got != want {
		t.Fatalf("native forward name = %q, want %q", got, want)
	}
	if got := nativeVPNForwardSectionName("media.qbittorrent"); got == nativeVPNForwardSectionName("media-qbittorrent") {
		t.Fatal("distinct forward names collided")
	}
}

func TestNativeVPNClientMTURouteIsExactAndOwned(t *testing.T) {
	name := nativeVPNClientMTUSectionName("10.10.20.230")
	if name != "boetticher_vpn_client_mtu_n10_d10_d20_d230" {
		t.Fatalf("MTU route name = %q", name)
	}
	section := openwrt.UCISection{Type: "route", Options: map[string]string{"interface": "boetticher_iface_servers", "target": "10.10.20.230", "netmask": "255.255.255.255", "mtu": "1320"}}
	if !managedStaleSection(name, section) || managedStaleSection(name, openwrt.UCISection{Type: "route", Options: map[string]string{"interface": "airvpn", "target": "10.10.20.230", "netmask": "255.255.255.255", "mtu": "1320"}}) || managedStaleSection(name, openwrt.UCISection{Type: "route", Options: map[string]string{"interface": "boetticher_iface_servers", "target": "10.10.20.231", "netmask": "255.255.255.255", "mtu": "1320"}}) {
		t.Fatal("MTU route ownership contract is unsafe")
	}
}

func TestVPNClientMTURouteUsesReservationLABInterface(t *testing.T) {
	enabled := true
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	modules := clientservices.Modules{
		VPN:  &clientservices.VPNConfig{Enabled: &enabled, Clients: []string{"lab-media-01"}},
		DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: "lab-media-01", Zone: "SERVERS", Address: "10.10.20.230"}}},
	}
	network, _ := vpnSections(site, modules, VPNProfile{MTU: 1320})
	for _, section := range network {
		if section.Name != nativeVPNClientMTUSectionName("10.10.20.230") {
			continue
		}
		if section.Options["interface"] != "boetticher_iface_servers" || section.Options["target"] != "10.10.20.230" || section.Options["mtu"] != "1320" {
			t.Fatalf("MTU route does not use the reservation LAB interface: %#v", section.Options)
		}
		return
	}
	t.Fatal("missing client MTU route")
}

func TestManagedStaleVPNForwardRecognizesOwnedCurrentAndLegacyNames(t *testing.T) {
	section := openwrt.UCISection{Type: "redirect", Options: map[string]string{"name": "Boetticher VPN media-qbittorrent"}}
	if !managedStaleSection(nativeVPNForwardSectionName("media-qbittorrent"), section) {
		t.Fatal("current encoded forward was not recognized as owned")
	}
	if !managedStaleSection("boetticher_vpn_forward_media-qbittorrent", section) {
		t.Fatal("legacy forward was not recognized as owned")
	}
	if managedStaleSection("boetticher_vpn_forward_foreign", openwrt.UCISection{Type: "redirect", Options: map[string]string{"name": "foreign"}}) {
		t.Fatal("foreign redirect was recognized by prefix alone")
	}
}
