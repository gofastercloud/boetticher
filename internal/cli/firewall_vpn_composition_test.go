package cli

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/airvpn"
	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
)

func TestComposeFirewallApplianceRetainsConfiguredVPNContainment(t *testing.T) {
	oldLoad, oldProjection := firewallLoadVPNMaterial, firewallVPNProfileProjection
	defer func() { firewallLoadVPNMaterial, firewallVPNProfileProjection = oldLoad, oldProjection }()
	enabled := true
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	profile := airvpn.Profile{Config: "[Interface]\nPrivateKey=" + key + "\nAddress=10.64.12.3/32\n[Peer]\nPublicKey=" + key + "\nPresharedKey=" + key + "\nEndpoint=vpn.example:1637\nAllowedIPs=0.0.0.0/0\n"}
	firewallLoadVPNMaterial = func(model.Site) (airvpn.Profile, string, bool, error) { return profile, "device", true, nil }
	firewallVPNProfileProjection = vpnProfileProjection
	modules := clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &enabled}, VPN: &clientservices.VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{"media"}, Forwards: []clientservices.VPNForward{{Name: "media-qbittorrent", Reservation: "media", Protocols: []string{"tcp"}, Port: 35796}}}, DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: "media", Zone: "SERVERS", MAC: "02:00:00:00:20:e6", Address: "10.10.20.230"}}}}
	composition, err := composeFirewallAppliance(model.NewSite("lab", "controller-local", model.GatewayModeManaged), modules, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(composition.Network)+len(composition.Firewall))
	for _, section := range composition.Network {
		names = append(names, section.Name)
	}
	for _, section := range composition.Firewall {
		names = append(names, section.Name)
	}
	joined := strings.Join(names, "\n")
	for _, want := range []string{"airvpn", "boetticher_vpn_peer", "boetticher_vpn_block_0", "boetticher_vpn_client_mtu_", "boetticher_vpn_forward_", "boetticher_zone_vpn"} {
		if !containsString(joined, want) {
			t.Fatalf("retained VPN section %q missing", want)
		}
	}
	if _, _, present, err := (func() (airvpn.Profile, string, bool, error) { return firewallLoadVPNMaterial(model.Site{}) })(); err != nil || !present {
		t.Fatalf("retained profile loader was not used: present=%t err=%v", present, err)
	}
	if strings.Contains(strings.Join(names, "\n"), "delete") {
		t.Fatal("composition emitted deletion pseudo-sections")
	}
}
