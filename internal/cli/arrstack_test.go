package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/arrstack"
	"github.com/gofastercloud/boetticher/internal/clientservices"
)

func TestMediaApplyRetainsInstallerAndTransportTimeoutMargins(t *testing.T) {
	if mediaApplyTransportTimeout != 21*time.Minute {
		t.Fatalf("media apply transport timeout = %s, want 21m", mediaApplyTransportTimeout)
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
	proposed, changes, err := prepareArrstackModules(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 || proposed.Arrstack == nil || !proposed.Arrstack.Enabled {
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

func appliedMediaModules() clientservices.Modules {
	enabled := true
	return clientservices.Modules{
		Media: &clientservices.MediaConfig{Enabled: true, MediaGiB: 500, ApplicationDomain: "media.example.net", Aliases: clientservices.MediaAliases{Radarr: "movies", Sonarr: "shows", Bazarr: "subs", Prowlarr: "index", Trailarr: "trails"}},
		DNS:   &clientservices.DNSConfig{Enabled: &enabled},
		DHCP:  &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{arrstack.Reservation()}},
		VPN:   &clientservices.VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{arrstack.GuestName}, Forwards: []clientservices.VPNForward{{Name: "media-qbittorrent", Reservation: arrstack.GuestName, Protocols: []string{"tcp", "udp"}, Port: 35797}}},
	}
}

// An already-applied lab.yml as loaded (no Arrstack alias, unmaterialised
// DNS/DHCP defaults) must not report drift.
func TestPrepareArrstackAlreadyAppliedIntentHasNoChanges(t *testing.T) {
	current := appliedMediaModules()
	proposed, changes, err := prepareArrstackModules(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("already-applied intent reported changes: %v", changes)
	}
	if got := proposed.VPN.Forwards[0]; got.Port != 35797 || strings.Join(got.Protocols, ",") != "tcp,udp" {
		t.Fatalf("saved forward rewritten: %#v", got)
	}
	if proposed.Arrstack == nil || proposed.Media.MediaGiB != 500 {
		t.Fatalf("proposed media intent lost: %#v", proposed.Media)
	}
}

func TestPrepareArrstackListsEachIntentChange(t *testing.T) {
	current := appliedMediaModules()
	current.Media.Enabled = false
	current.VPN.Forwards[0].Protocols = []string{"tcp", "tcp"}
	_, changes, err := prepareArrstackModules(current)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, change := range changes {
		got = append(got, change.String())
	}
	want := []string{
		"modules.media.enabled: false -> true",
		"modules.vpn.forwards[media-qbittorrent]: reservation lab-media-01 protocols tcp,tcp port 35797 -> reservation lab-media-01 protocols tcp,udp port 35797",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("changes =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// After a Host reboot the onboot=0 guest is stopped while intent is correct:
// the plan must say intent is unchanged and that apply starts the guest.
func TestArrstackPlanForStoppedGuestWithAppliedIntent(t *testing.T) {
	var out bytes.Buffer
	renderArrstackApplyPlan(&out, "MEDIA apply plan", arrstackApplyFacts{
		Guest:    arrstack.GuestFacts{Exists: true},
		Runtime:  arrstack.RuntimeStatus{Exists: true, Detail: "guest is stopped"},
		MediaGiB: 500,
	})
	text := out.String()
	for _, want := range []string{"(stopped)", "Intent: no change", "Provider: DNS/DHCP/VPN prerequisites at desired state", "Runtime: guest is stopped", "start stopped VM 290 and wait for the QEMU guest agent", "redeploy the Docker application"} {
		if !strings.Contains(text, want) {
			t.Fatalf("plan missing %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"save the lab.yml", "reconcile DNS/DHCP/VPN", "create VM"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("plan claims %q:\n%s", unwanted, text)
		}
	}
}

func TestArrstackPlanForVerifiedApplyIsNoOp(t *testing.T) {
	facts := arrstackApplyFacts{
		Guest:         arrstack.GuestFacts{Exists: true, Running: true},
		Runtime:       arrstack.RuntimeStatus{Exists: true, Running: true, AgentReady: true, DockerReady: true, AppReady: true, Detail: "guest runtime ready"},
		AdapterAgrees: true,
		MediaGiB:      500,
	}
	if !facts.NoOp() {
		t.Fatal("verified facts are not a no-op")
	}
	var out bytes.Buffer
	renderArrstackApplyPlan(&out, "MEDIA plan", facts)
	if text := out.String(); !strings.Contains(text, "Apply: no change") || strings.Contains(text, "Apply will:") {
		t.Fatalf("no-op plan lists actions:\n%s", text)
	}
	facts.VPNErr = errors.New("VPN peer handshake is stale")
	out.Reset()
	renderArrstackApplyPlan(&out, "MEDIA plan", facts)
	if !strings.Contains(out.String(), "VPN: unhealthy (VPN peer handshake is stale)") {
		t.Fatalf("plan hid unhealthy VPN:\n%s", out.String())
	}
}

func TestArrstackPlanForFirstInstallListsIntentAndCreate(t *testing.T) {
	_, changes, err := prepareArrstackModules(func() clientservices.Modules {
		m := appliedMediaModules()
		m.Media.Enabled = false
		m.DHCP.Reservations = nil
		m.VPN.Clients = nil
		m.VPN.Forwards = nil
		return m
	}())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	renderArrstackApplyPlan(&out, "MEDIA apply plan", arrstackApplyFacts{Changes: changes, Runtime: arrstack.RuntimeStatus{Detail: "guest is absent"}, MediaGiB: 500})
	text := out.String()
	for _, want := range []string{
		"modules.media.enabled: false -> true",
		"modules.dhcp.reservations[lab-media-01]: absent -> zone SERVERS mac 02:00:00:00:20:e6 address 10.10.20.230",
		"modules.vpn.clients[lab-media-01]: absent -> present",
		"modules.vpn.forwards[media-qbittorrent]: absent -> reservation lab-media-01 protocols tcp,udp port 35796",
		"save the lab.yml intent changes above",
		"reconcile DNS/DHCP/VPN prerequisites",
		"create VM 290 from the pinned image with a 500GiB media disk",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plan missing %q:\n%s", want, text)
		}
	}
}
