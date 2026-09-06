package cli

import (
	"testing"

	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

func TestCheckDefinitionsHaveUniqueStableKeysAndLabels(t *testing.T) {
	ids := map[string]struct{}{}
	labels := map[string]struct{}{}
	for _, definition := range checkDefinitions {
		if definition.ID == "" || definition.Label == "" || definition.EvidenceTier == "" {
			t.Fatalf("incomplete check definition: %#v", definition)
		}
		if _, exists := ids[definition.ID]; exists {
			t.Fatalf("duplicate check ID %q", definition.ID)
		}
		if _, exists := labels[definition.Label]; exists {
			t.Fatalf("duplicate check label %q", definition.Label)
		}
		ids[definition.ID] = struct{}{}
		labels[definition.Label] = struct{}{}
	}
	if len(checkDefinitions) != len(ids) || len(checkDefinitions) != len(labels) {
		t.Fatalf("check definition registry is incomplete: %#v", checkDefinitions)
	}
}

func TestNormalizeCheckResultUsesIDForLabelAndTier(t *testing.T) {
	result := statusmodel.CheckResult{ID: checkManagedGatewayServices, Name: "spoofed label", Tier: statusmodel.TierLocal}
	definition, err := normalizeCheckResult(&result)
	if err != nil {
		t.Fatal(err)
	}
	if definition.Label != "managed gateway services" || result.Name != definition.Label || result.Tier == statusmodel.TierLocal {
		t.Fatalf("check metadata was not resolved from its ID: definition=%#v result=%#v", definition, result)
	}
}

func TestNormalizeCheckResultRejectsUnknownIDEvenWithKnownLabel(t *testing.T) {
	result := statusmodel.CheckResult{ID: "unknown-check", Name: "managed gateway services"}
	if _, err := normalizeCheckResult(&result); err == nil {
		t.Fatal("unknown check ID was accepted through a display label")
	}
}

func TestFilterHealthStatusReportUsesStableID(t *testing.T) {
	report := statusmodel.Report{Checks: []statusmodel.Check{
		{ID: checkManagedGatewayServices, Component: "renamed display text", Tier: statusmodel.TierLocal},
		{ID: "unknown-check", Component: "managed gateway services"},
	}}
	filtered := filterHealthStatusReport(report)
	if len(filtered.Checks) != 1 {
		t.Fatalf("unexpected filtered checks: %#v", filtered.Checks)
	}
	check := filtered.Checks[0]
	if check.ID != checkManagedGatewayServices || check.Component != "managed gateway services" || check.Tier != statusmodel.TierDeployed {
		t.Fatalf("stable check definition was not applied: %#v", check)
	}
}
