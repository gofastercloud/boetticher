package cli

import (
	"bytes"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

func TestLXCFirewallResolutionUsesHostnameAndNetEntries(t *testing.T) {
	config := map[string]any{
		"hostname":  "user-app-01",
		"net0":      "name=eth0,bridge=vmbr1,ip=10.10.20.61/24,gw=10.10.20.1",
		"net1":      "name=eth1,bridge=vmbr1,ip6=2001:db8::1/64",
		"ipconfig0": "ip=10.10.20.99/24", // must not be treated as current identity
	}
	if err := validateGuestIdentity(config, proxmox.KindLXC, 501); err != nil {
		t.Fatal(err)
	}
	addresses := addressesFromLXCConfig(config)
	if len(addresses) != 1 || addresses[0] != "10.10.20.61" {
		t.Fatalf("LXC net entries resolved to %#v", addresses)
	}
}

func TestLXCFirewallResolutionRejectsMissingHostname(t *testing.T) {
	if err := validateGuestIdentity(map[string]any{"name": "user-app-01"}, proxmox.KindLXC, 501); err == nil {
		t.Fatal("LXC name fallback bypassed hostname identity requirement")
	}
}

func TestFirewallRuleAddValidatesAgainstComposedModuleAddresses(t *testing.T) {
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	enabled := true
	config.Modules.Monitoring = &model.ToggleModuleConfig{Enabled: &enabled}
	resolved, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	rule := model.UserFirewallRule{ID: "ufr-module", Source: "TRUSTED", Destination: "10.10.10.20/32", Protocol: "tcp", Ports: []string{"443"}}
	if err := addFirewallRule("", config, resolved, rule, true, true, false, &bytes.Buffer{}); err == nil {
		t.Fatal("rule targeting a composed Core module address was accepted")
	}
}

func TestFirewallRuleAddAcceptsReservedServersPulseClient(t *testing.T) {
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	config.DHCPReservations = []model.DHCPReservation{{Zone: "SERVERS", Hostname: "lab-display-01", Address: "10.10.20.50", MAC: "dc:a6:32:e9:dd:82"}}
	resolved, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	rule := model.UserFirewallRule{ID: "ufr-lab-display-pulse", Source: "10.10.20.50/32", Destination: "10.10.10.20/32", Protocol: "tcp", Ports: []string{"443"}}
	if err := addFirewallRule("", config, resolved, rule, true, true, false, &bytes.Buffer{}); err != nil {
		t.Fatalf("reserved SERVERS Pulse client was rejected: %v", err)
	}
}
