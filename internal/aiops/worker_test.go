package aiops

import (
	"context"
	"testing"
	"time"
)

type fixedInvestigator struct {
	result InvestigationResult
	err    error
}

func (f fixedInvestigator) Investigate(context.Context, Incident, string) (InvestigationResult, error) {
	return f.result, f.err
}

func TestWorkerPreservesInconclusiveOutcome(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	incident, _, err := store.Admit(context.Background(), Alert{PulseAlertID: "alert-1", StartedAt: now, ResourceID: "vm:101", Kind: "cpu", Severity: "warning", Title: "hostile\x1b[31m evidence"}, now)
	if err != nil {
		t.Fatal(err)
	}
	worker := Worker{
		Store: store, Capabilities: NewCapabilityRegistry(),
		Investigator: fixedInvestigator{result: InvestigationResult{Report: Report{Outcome: OutcomeInconclusive, Summary: "Evidence did not establish a cause", Confidence: "low", EvidenceGaps: []string{"journal unavailable"}}, Usage: Usage{InputTokens: 100, OutputTokens: 40}}},
		Policy: func(i Incident) (EvidencePolicy, error) {
			return EvidencePolicy{IncidentID: i.ID, PulseAlertID: i.PulseAlertID, ResourceIDs: map[string]bool{i.ResourceID: true}}, nil
		},
		Now: func() time.Time { return now.Add(time.Minute) },
	}
	ran, err := worker.RunOnce(context.Background())
	if err != nil || !ran {
		t.Fatalf("RunOnce() ran=%v err=%v", ran, err)
	}
	var state State
	var outcome Outcome
	var cause string
	if err := store.db.QueryRow(`SELECT state,outcome,coalesce(json_extract(final_report,'$.likely_cause'),'') FROM incidents WHERE id=?`, incident.ID).Scan(&state, &outcome, &cause); err != nil {
		t.Fatal(err)
	}
	if state != StateInconclusive || outcome != OutcomeInconclusive || cause != "" {
		t.Fatalf("terminal result state=%s outcome=%s cause=%q", state, outcome, cause)
	}
}

func TestClaimEnforcesConcurrencyAndRollingHourBudget(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 8, 28, 3, 0, 0, 0, time.UTC)
	for i := 0; i < MaxInvestigationsHour+1; i++ {
		if _, _, err := store.Admit(context.Background(), Alert{PulseAlertID: string(rune('a' + i)), StartedAt: now.Add(time.Duration(i) * time.Second), ResourceID: "vm:101", Kind: "cpu", Severity: "warning", Title: "bounded"}, now); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < MaxInvestigationsHour; i++ {
		incident, ok, err := store.ClaimNext(context.Background(), now.Add(time.Duration(i)*time.Minute))
		if err != nil || !ok {
			t.Fatalf("claim %d ok=%v err=%v", i, ok, err)
		}
		if _, ok, err := store.ClaimNext(context.Background(), now); err != nil || ok {
			t.Fatalf("concurrent claim ok=%v err=%v", ok, err)
		}
		if err := store.Fail(context.Background(), incident.ID, "test_failure", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, err := store.ClaimNext(context.Background(), now.Add(10*time.Minute)); err != nil || ok {
		t.Fatalf("fifth hourly claim ok=%v err=%v", ok, err)
	}
}

func TestCompletionRejectsBudgetAndUnissuedEvidence(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	admitted, _, _ := store.Admit(context.Background(), Alert{PulseAlertID: "alert-1", StartedAt: now, ResourceID: "vm:101", Kind: "cpu", Severity: "warning", Title: "bounded"}, now)
	_, _, _ = store.ClaimNext(context.Background(), now)
	report := Report{Outcome: OutcomeCompleted, Summary: "cause", LikelyCause: "disk full", Confidence: "high", EvidenceReferences: []string{"missing"}}
	if err := store.Complete(context.Background(), admitted.ID, report, Usage{OutputTokens: MaxOutputTokens + 1}, nil, now); err == nil {
		t.Fatal("unsafe completion was accepted")
	}
}
