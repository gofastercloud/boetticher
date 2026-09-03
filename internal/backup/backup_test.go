package backup

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanOwnsOnlyPlatformGuests(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.JobName != PlatformJobName || !plan.PlatformOnly || plan.UserWorkloadsManaged || plan.SelectionTag != model.TagBackup || len(plan.GuestVMIDs) != 3 || plan.VMIDList() != "100,110,120" {
		t.Fatalf("unexpected backup ownership plan: %#v", plan)
	}
	if plan.StorageTarget != "local" || plan.Schedule != "daily" || plan.Retention != "keep-last=7" {
		t.Fatalf("unexpected backup job policy: %#v", plan)
	}
}

func TestPlanFollowsComponentBackupIntent(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.VMIDList() != "100,110,120" {
		t.Fatalf("backup plan ignored component backup intent: %#v", plan)
	}
}

func TestUserGuestTagDoesNotEnterBackupPlan(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, model.Component{
		Name: "user-vm-550", VMID: 550, Hostname: "user-vm-550", Zone: "SANDBOX", Address: "10.10.40.50",
		Role: "user workload", Tags: []string{model.TagBoetticher, model.TagManaged, model.TagBackup}, ProductOwned: false,
	})
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.VMIDList() != "100,110,120" {
		t.Fatalf("user guest tag changed platform backup selection: %#v", plan)
	}
}
