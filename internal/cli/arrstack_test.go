package cli

import (
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/arrstack"
	"github.com/gofastercloud/boetticher/internal/clientservices"
)

func TestMediaApplyUsesFullParentTransportBudget(t *testing.T) {
	sc := clientServiceContext{}
	sc.Host.Transport.Timeout = 10 * time.Minute
	sc.Host.Transport.Timeout = mediaApplyTransportTimeout
	if sc.Host.Transport.Timeout != 20*time.Minute {
		t.Fatalf("media apply transport timeout = %s", sc.Host.Transport.Timeout)
	}
}

func TestPrepareArrstackAddsExactIntentAndPreservesExistingPeerPort(t *testing.T) {
	enabled := true
	current := clientservices.Modules{
		Media: &clientservices.MediaConfig{ApplicationDomain: "media.example.net", Aliases: clientservices.MediaAliases{Radarr: "movies", Sonarr: "shows", Bazarr: "subs", Prowlarr: "index", Trailarr: "trails"}},
		DNS:   &clientservices.DNSConfig{Enabled: &enabled},
		DHCP:  &clientservices.DHCPConfig{Enabled: &enabled},
		VPN:   &clientservices.VPNConfig{Enabled: &enabled, Location: "europe", Forwards: []clientservices.VPNForward{{Name: "media-qbittorrent", Reservation: "lab-media-01", Protocols: []string{"tcp", "udp"}, Port: 35797}}},
	}
	proposed, changed, err := prepareArrstackModules(current)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || proposed.Arrstack == nil || !proposed.Arrstack.Enabled {
		t.Fatalf("arrstack intent not enabled: %#v", proposed.Arrstack)
	}
	if proposed.VPN.Forwards[0].Port != 35797 {
		t.Fatalf("existing peer port changed: %#v", proposed.VPN.Forwards)
	}
	if len(proposed.DHCP.Reservations) != 1 || len(proposed.VPN.Clients) != 1 {
		t.Fatalf("fixed identity not added: %#v %#v", proposed.DHCP.Reservations, proposed.VPN.Clients)
	}
}

func TestPrepareArrstackRejectsMissingProtectionCapabilities(t *testing.T) {
	if _, _, err := prepareArrstackModules(clientservices.Modules{}); err == nil {
		t.Fatal("arrstack accepted missing DNS/DHCP/VPN protection")
	}
}

func TestPrepareArrstackRejectsGUIIngressPorts(t *testing.T) {
	enabled := true
	for _, port := range []int{443, 8080} {
		current := clientservices.Modules{
			DNS:  &clientservices.DNSConfig{Enabled: &enabled},
			DHCP: &clientservices.DHCPConfig{Enabled: &enabled},
			VPN:  &clientservices.VPNConfig{Enabled: &enabled, Location: "europe", Forwards: []clientservices.VPNForward{{Name: "media-qbittorrent", Reservation: arrstack.GuestName, Protocols: []string{"tcp", "udp"}, Port: port}}},
		}
		if _, _, err := prepareArrstackModules(current); err == nil {
			t.Fatalf("peer port %d was accepted", port)
		}
	}
}
