package logging

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanProjectsMandatoryCollectorAndManagedSources(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Collector != CollectorName || plan.CollectorPort != 19532 || plan.RemoteJournalPath != RemoteJournalPath || !plan.MTLS {
		t.Fatalf("incomplete logging plan: %#v", plan)
	}
	if len(plan.Sources) != 6 || plan.SourceUnitsOptional == false {
		t.Fatalf("unexpected managed logging sources: %#v", plan.Sources)
	}
	if strings.Contains(CollectorConfiguration(plan), "Requires=") {
		t.Fatal("collector availability became an application startup dependency")
	}
	if !strings.Contains(UploadConfiguration(plan, "lab-dns-01"), "https://logs.lab.home.arpa:19532") {
		t.Fatal("upload configuration does not use the canonical collector URL")
	}
}

func TestPlanRejectsMissingMandatoryCollector(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	for index, component := range site.Components {
		if component.Name == CollectorName {
			site.Components = append(site.Components[:index], site.Components[index+1:]...)
			break
		}
	}
	if _, err := PlanFromSite(site); err == nil {
		t.Fatal("missing collector was accepted")
	}
}
