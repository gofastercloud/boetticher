package cli

import (
	"testing"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestPhysicalLABStatusUsesObservedNetworkPlan(t *testing.T) {
	plan := controllerhost.NetworkPlan{Config: controllerhost.NetworkConfig{PhysicalTrunk: "nic1"}, State: "exact"}
	if got := physicalLABStatus(plan, nil); got != "nic1 attached" {
		t.Fatalf("physical LAB status = %q", got)
	}
	plan.State = "conflict"
	if got := physicalLABStatus(plan, nil); got != "nic1 not ready (conflict)" {
		t.Fatalf("physical LAB conflict status = %q", got)
	}
	if got := physicalLABStatus(controllerhost.NetworkPlan{}, nil); got != "Virtual bridge path" {
		t.Fatalf("virtual LAB status = %q", got)
	}
}
