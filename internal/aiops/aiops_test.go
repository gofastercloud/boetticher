package aiops

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAdmissionCommitsBeforeAcceptanceAndDeduplicates(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	alert := Alert{PulseAlertID: "alert-1", StartedAt: now, ResourceID: "vm/101", Kind: "cpu", Severity: "warning", Title: "CPU high"}
	first, duplicate, err := store.Admit(context.Background(), alert, now)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate || first.State != StateQueued {
		t.Fatalf("first admission = %#v duplicate=%v", first, duplicate)
	}
	second, duplicate, err := store.Admit(context.Background(), alert, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate || second.ID != first.ID || second.DeliveryCount != 2 {
		t.Fatalf("duplicate admission = %#v duplicate=%v", second, duplicate)
	}
}

func TestBudgetsDeferWithoutDroppingAdmission(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	for i := 0; i < MaxQueue+1; i++ {
		incident, _, err := store.Admit(context.Background(), Alert{PulseAlertID: fmt.Sprintf("a-%d", i), StartedAt: now.Add(time.Duration(i) * time.Second), ResourceID: "vm/101", Kind: "cpu", Severity: "warning", Title: "bounded"}, now)
		if err != nil {
			t.Fatal(err)
		}
		if i == MaxQueue && (incident.State != StateDeferred || incident.DeferReason != "queue_full") {
			t.Fatalf("overflow admission = %#v", incident)
		}
	}
}

func TestEvidenceRequestCannotCreateAuthority(t *testing.T) {
	policy := EvidencePolicy{IncidentID: "incident-1", ResourceIDs: map[string]bool{"vm/101": true}, Hosts: map[string]map[string]bool{"lab-dns-01": {"blocky.service": true}}}
	valid := EvidenceRequest{Operation: OperationJournal, IncidentID: "incident-1", Host: "lab-dns-01", Unit: "blocky.service", SinceMinutes: 120, Limit: 200, Priority: "warning"}
	if err := policy.Validate(valid); err != nil {
		t.Fatal(err)
	}
	attacks := []EvidenceRequest{
		{Operation: OperationJournal, IncidentID: "incident-1", Host: "attacker.example", Limit: 1},
		{Operation: OperationJournal, IncidentID: "incident-1", Host: "lab-dns-01", Unit: "../../etc/shadow", Limit: 1},
		{Operation: OperationResource, IncidentID: "other", ResourceID: "vm/101"},
		{Operation: "new_tool", IncidentID: "incident-1"},
	}
	for _, attack := range attacks {
		if err := policy.Validate(attack); err == nil {
			t.Fatalf("attack accepted: %#v", attack)
		}
	}
}

func TestReportPreservesInconclusiveAndEvidenceReferences(t *testing.T) {
	report := Report{Outcome: OutcomeInconclusive, Summary: "Cause not established", Confidence: "low", EvidenceGaps: []string{"service journal unavailable"}}
	if err := report.Validate(nil); err != nil {
		t.Fatal(err)
	}
	report.LikelyCause = "invented cause"
	if err := report.Validate(nil); err == nil || !strings.Contains(err.Error(), "null cause") {
		t.Fatalf("inconclusive cause accepted: %v", err)
	}
	report = Report{Outcome: OutcomeCompleted, Summary: "Found", LikelyCause: "disk full", Confidence: "high", EvidenceReferences: []string{"unknown"}}
	if err := report.Validate(map[string]bool{"known": true}); err == nil {
		t.Fatal("unknown evidence reference accepted")
	}
}
