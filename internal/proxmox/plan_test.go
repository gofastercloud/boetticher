package proxmox

import (
	"encoding/json"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestFoundationPlanIsDeterministic(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	first, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) {
		t.Fatal("identical sites generated different Proxmox plans")
	}
	if len(first.Guests) != 5 || first.Guests[0].VMID != model.ProxmoxVMID {
		t.Fatalf("unexpected foundation plan: %#v", first.Guests)
	}
}

func TestGatewayForFoundationZones(t *testing.T) {
	for zone, expected := range map[string]string{
		"TRUSTED": "10.10.10.1", "SERVERS": "10.10.20.1", "SANDBOX": "10.10.50.1", "MGMT": "10.10.99.1",
	} {
		if got := gatewayFor(zone); got != expected {
			t.Fatalf("gatewayFor(%q) = %q, want %q", zone, got, expected)
		}
	}
}

func TestUserWorkloadNeverEntersPlatformPlan(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Modules = append(site.Modules, model.Module{
		Name: "user-vm-550", VMID: 550, Hostname: "user-vm-550", Zone: "SANDBOX", Address: "10.10.50.50",
		Role: "user workload", ProductOwned: false,
	})
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Guests) != 5 {
		t.Fatalf("user workload changed platform guest count: %#v", plan.Guests)
	}
	for _, guest := range plan.Guests {
		if guest.VMID == 550 {
			t.Fatal("user workload entered the Lab-in-a-Box platform plan")
		}
	}
}
