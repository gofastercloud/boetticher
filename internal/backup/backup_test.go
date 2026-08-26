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
	if plan.JobName != PlatformJobName || !plan.PlatformOnly || plan.UserWorkloadsManaged || len(plan.GuestVMIDs) != 5 || plan.VMIDList() != "100,110,111,120,130" {
		t.Fatalf("unexpected backup ownership plan: %#v", plan)
	}
	if plan.StorageTarget != "local" || plan.Schedule != "daily" || plan.Retention != "keep-last=7" {
		t.Fatalf("unexpected backup job policy: %#v", plan)
	}
}
