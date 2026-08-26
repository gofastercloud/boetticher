package zabbix

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanDoesNotAdoptUserWorkloads(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, model.Component{
		Name: "user-vm-550", VMID: 550, Hostname: "user-vm-550", Zone: "SANDBOX", Address: "10.10.50.50", Role: "user workload",
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
