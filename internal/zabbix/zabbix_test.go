package zabbix

import (
	"encoding/json"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanDoesNotAdoptUserWorkloads(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, model.Component{
		Name: "user-vm-550", VMID: 550, Hostname: "user-vm-550", Zone: "SANDBOX", Address: "10.10.40.50", Role: "user workload",
	})
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.PlatformOnly || plan.HostGroup != PlatformHostGroup || plan.ManagedBy != "boetticher" {
		t.Fatalf("unexpected Zabbix ownership contract: %#v", plan)
	}
	for _, component := range plan.Components {
		if component.Name == "user-vm-550" {
			t.Fatal("user workload entered platform Zabbix plan")
		}
	}
}

func TestPlatformObjectsAreDeterministicAndNamespaced(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	first, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(first.Objects)
	right, _ := json.Marshal(second.Objects)
	if string(left) != string(right) {
		t.Fatal("Zabbix object manifest is not deterministic")
	}
	if len(first.Objects) < 3 {
		t.Fatalf("object manifest is unexpectedly small: %#v", first.Objects)
	}
	for _, object := range first.Objects {
		if object.ManagedBy != "boetticher" || len(object.Tags) != 1 || object.Tags[0] != "boetticher/platform" {
			t.Fatalf("object is outside the boetticher namespace: %#v", object)
		}
	}
}
