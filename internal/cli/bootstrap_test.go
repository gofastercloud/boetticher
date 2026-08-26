package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

func TestHonorRequestedPhysicalModeKeepsFreshVirtualOnlySiteUnclaimed(t *testing.T) {
	discovery := networkmodel.Discovery{
		Mode:        networkmodel.ModePhysicalTrunk,
		Status:      "PASS",
		Explanation: "one candidate",
		Trunk:       &networkmodel.Interface{Name: "enp5s0"},
	}
	got := honorRequestedPhysicalMode(discovery, model.ModeVirtualOnly, "", "")
	if got.Mode != networkmodel.ModeVirtualOnly || got.Trunk != nil || got.Status != "PASS" {
		t.Fatalf("fresh virtual-only mode claimed a trunk: %#v", got)
	}
	if got.Explanation == "" {
		t.Fatal("virtual-only decision lacks an operator-facing explanation")
	}
}

func TestHonorRequestedPhysicalModeAllowsExplicitTrunkSelection(t *testing.T) {
	discovery := networkmodel.Discovery{
		Mode:  networkmodel.ModePhysicalTrunk,
		Trunk: &networkmodel.Interface{Name: "enp5s0"},
	}
	got := honorRequestedPhysicalMode(discovery, model.ModeVirtualOnly, "", "enp5s0")
	if got.Mode != networkmodel.ModePhysicalTrunk || got.Trunk == nil || got.Trunk.Name != "enp5s0" {
		t.Fatalf("explicit trunk selection was discarded: %#v", got)
	}
}
