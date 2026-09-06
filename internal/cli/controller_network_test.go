package cli

import (
	"bytes"
	"strings"
	"testing"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestNetworkConfigureFlagsKeepAdoptionExplicit(t *testing.T) {
	for _, tc := range []struct {
		args                []string
		yes, adopt, invalid bool
	}{
		{nil, false, false, false},
		{[]string{"--yes"}, true, false, false},
		{[]string{"--adopt-existing-network"}, false, true, false},
		{[]string{"--adopt-existing-network", "--yes"}, true, true, false},
		{[]string{"--yes", "--adopt-existing-network"}, true, true, false},
		{[]string{"--force"}, false, false, true},
		{[]string{"--yes", "--yes"}, false, false, true},
		{[]string{"--adopt-existing-network", "--adopt-existing-network"}, false, false, true},
	} {
		yes, adopt, err := parseNetworkConfigureFlags(tc.args)
		if yes != tc.yes || adopt != tc.adopt || (err != nil) != tc.invalid {
			t.Fatalf("flags %v: %v %v %v", tc.args, yes, adopt, err)
		}
	}
}

func TestAdoptionPreviewAndStatus(t *testing.T) {
	plan := controllerhost.NetworkPlan{State: "adoptable", Bridge: controllerhost.BridgeState{HostAddresses: []string{"inet6 fe80::123"}}}
	var out bytes.Buffer
	renderNetworkPlan(&out, plan)
	for _, want := range []string{"--adopt-existing-network", "fe80::123", "Persist Boetticher ownership", "Disable the Proxmox Host IPv6 stack", "vmbr0", "storage", "guests"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("preview missing %s", want)
		}
	}
	out.Reset()
	if err := renderNetworkStatus(&out, plan); err == nil || strings.Contains(out.String(), "foundation: PASS") {
		t.Fatal("adoptable bridge reported healthy")
	}
}

func TestPersistIdenticalNetworkIsNoOp(t *testing.T) {
	network := controllerhost.DefaultNetworkConfig()
	// A no-op must not touch the controller's /etc configuration file.
	if err := persistNetworkConfig(controllerhost.LabConfig{Network: &network}, network); err != nil {
		t.Fatal(err)
	}
}
