package backup

import (
	"testing"

	"github.com/dave/labinabox/internal/model"
)

func TestPlanOwnsOnlyPlatformGuests(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.JobName != PlatformJobName || !plan.PlatformOnly || plan.UserWorkloadsManaged || len(plan.GuestVMIDs) != 5 {
		t.Fatalf("unexpected backup ownership plan: %#v", plan)
	}
}
