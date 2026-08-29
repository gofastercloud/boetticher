package status

import "testing"

func TestFromLegacyUsesExactEvidenceAndOperatorVocabulary(t *testing.T) {
	report := FromLegacy("revision", "2026-08-29T00:00:00Z", []LegacyCheck{
		{Name: "static model", Status: "STATIC PASS", Detail: "source check"},
		{Name: "live gateway", Status: "NOT TESTED", Detail: "requires deployed journey"},
	})
	if report.StatusModelVersion != ModelVersion || report.OverallState != ActionRequired {
		t.Fatalf("unexpected report metadata: %#v", report)
	}
	if report.Checks[0].Evidence != PASS || report.Checks[0].State != Healthy {
		t.Fatalf("static pass was not normalized: %#v", report.Checks[0])
	}
	if report.Checks[1].Evidence != NOTTESTED || report.Checks[1].State != ActionRequired || report.Checks[1].Tier != TierJourney {
		t.Fatalf("not-tested journey was not represented safely: %#v", report.Checks[1])
	}
}

func TestDisabledChecksDoNotDegradeOverallHealth(t *testing.T) {
	report := FromLegacy("revision", "now", []LegacyCheck{{Name: "printer", Status: "PASS", Detail: "optional module is intentionally disabled"}})
	report.Checks[0].State = Disabled
	if got := Overall(report.Checks); got != Healthy {
		t.Fatalf("disabled check degraded platform health: %s", got)
	}
}
