package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/model"
)

func TestTailnetAuthKeyInputRequiresPrivateFileOrTerminal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.key")
	if err := os.WriteFile(path, []byte("tskey-auth-synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := readTailnetAuthKey(path)
	if err != nil || string(key) != "tskey-auth-synthetic" {
		t.Fatalf("private auth key read failed: %q %v", key, err)
	}
	wipeTailnetAuthKey(key)
	for _, value := range key {
		if value != 0 {
			t.Fatalf("auth key buffer was not wiped: %v", key)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTailnetAuthKey(path); err == nil {
		t.Fatal("group-readable auth key was accepted")
	}
	if _, err := readTailnetAuthKeyPrompt(strings.NewReader("tskey-auth-synthetic\n"), io.Discard); err == nil {
		t.Fatal("non-terminal auth key input was accepted")
	}
}

func TestPrepareTailnetRefusesAdoptingUnownedIdenticalReservation(t *testing.T) {
	enabled := true
	config := controllerhost.LabConfig{Modules: clientservices.Modules{
		DNS:  &clientservices.DNSConfig{Enabled: &enabled},
		DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{tailnetReservation()}},
	}}
	if _, err := prepareTailnet(config); err == nil || !strings.Contains(err.Error(), "refusing adoption") {
		t.Fatalf("identical reservation was adopted: %v", err)
	}
}

func TestPrepareTailnetKeepsOwnedRepeatIdempotent(t *testing.T) {
	enabled := true
	config := controllerhost.LabConfig{Modules: clientservices.Modules{
		DNS:     &clientservices.DNSConfig{Enabled: &enabled},
		DHCP:    &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{tailnetReservation()}},
		Tailnet: &clientservices.TailnetConfig{Enabled: true},
	}}
	proposed, err := prepareTailnet(config)
	if err != nil || len(proposed.Modules.DHCP.Reservations) != 1 {
		t.Fatalf("owned repeat was not idempotent: proposed=%#v err=%v", proposed, err)
	}
}

func TestMissingTailnetDHCPSectionsIsExactReservationDelta(t *testing.T) {
	enabled := true
	current := controllerhost.LabConfig{Modules: clientservices.Modules{
		DNS:  &clientservices.DNSConfig{Enabled: &enabled},
		DHCP: &clientservices.DHCPConfig{Enabled: &enabled},
	}}
	proposed, err := prepareTailnet(current)
	if err != nil {
		t.Fatal(err)
	}
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	state, err := firewallmodule.ServiceStateFromModules(site, proposed.Modules)
	if err != nil {
		t.Fatal(err)
	}
	ignored := missingTailnetDHCPSections(current, proposed, state)
	if len(ignored) != 1 {
		t.Fatalf("ignored sections=%#v, want exactly the new Tailnet host section", ignored)
	}
	if _, ok := ignored["boetticher_host_lab_htailnet_h01"]; !ok {
		t.Fatalf("ignored sections=%#v, want exact Tailnet host section", ignored)
	}
	if got := missingTailnetDHCPSections(proposed, proposed, state); len(got) != 0 {
		t.Fatalf("existing reservation was incorrectly ignored: %#v", got)
	}
}

func TestMissingTailnetDHCPSectionsDoesNotHideUnrelatedConfig(t *testing.T) {
	enabled := true
	current := controllerhost.LabConfig{Modules: clientservices.Modules{
		DNS:  &clientservices.DNSConfig{Enabled: &enabled},
		DHCP: &clientservices.DHCPConfig{Enabled: &enabled},
	}}
	proposed, err := prepareTailnet(current)
	if err != nil {
		t.Fatal(err)
	}
	proposed.Modules.DNS.Records = append(proposed.Modules.DNS.Records, clientservices.DNSRecord{Name: "unrelated", Type: "A", Value: "10.10.5.20"})
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	state, err := firewallmodule.ServiceStateFromModules(site, proposed.Modules)
	if err != nil {
		t.Fatal(err)
	}
	ignored := missingTailnetDHCPSections(current, proposed, state)
	if len(ignored) != 1 {
		t.Fatalf("unrelated DNS change altered Tailnet exception scope: %#v", ignored)
	}
}
