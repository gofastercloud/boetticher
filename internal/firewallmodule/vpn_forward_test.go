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
