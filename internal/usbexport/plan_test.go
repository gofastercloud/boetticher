package usbexport

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanFromSiteIgnoresModulesWithoutUSBRequirements(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 0 {
		t.Fatalf("unexpected USB manifests for modules without USB requirements: %#v", plan)
	}
}
