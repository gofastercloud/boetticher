package firewallmodule

import (
	"testing"

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
	section := openwrt.UCISection{Type: "route", Options: map[string]string{"interface": "airvpn", "target": "10.10.20.230", "netmask": "255.255.255.255", "mtu": "1320"}}
	if !managedStaleSection(name, section) || managedStaleSection(name, openwrt.UCISection{Type: "route", Options: map[string]string{"interface": "airvpn", "target": "10.10.20.231", "netmask": "255.255.255.255", "mtu": "1320"}}) {
		t.Fatal("MTU route ownership contract is unsafe")
	}
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
