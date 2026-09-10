package incidents

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "incidents.db"), Limits{MaxRounds: 2, MaxInvestigations: 1, MaxIncidents: 3, InvestigationDeadline: time.Second, InvestigationBudget: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestIntakeDeduplicatesAndGroups(t *testing.T) {
	s := testStore(t)
	a := Alert{Source: "gatus", Title: "DNS down", Group: "dns", Fingerprint: "dns-1", Labels: map[string]string{"zone": "infra"}}
	one, duplicate, err := s.Intake(context.Background(), a)
	if err != nil || duplicate {
		t.Fatalf("first intake=%#v duplicate=%v err=%v", one, duplicate, err)
	}
	two, duplicate, err := s.Intake(context.Background(), a)
	if err != nil || !duplicate || two.ID != one.ID {
		t.Fatalf("dedupe=%#v duplicate=%v err=%v", two, duplicate, err)
	}
	if two.Group != "dns" || two.State != Queued {
		t.Fatalf("group/state=%#v", two)
	}
}

func TestIntakeRejectsUnboundedPayload(t *testing.T) {
	s := testStore(t)
	a := Alert{Source: "gatus", Title: "x", Body: string(make([]byte, maxAlertText+1))}
	if _, _, err := s.Intake(context.Background(), a); err == nil {
		t.Fatal("oversized alert accepted")
	}
}

func TestLifecycleRejectsOutOfOrderAndRecoversRestart(t *testing.T) {
	s := testStore(t)
	i, _, err := s.Intake(context.Background(), Alert{Source: "gatus", Title: "x", Fingerprint: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Transition(context.Background(), i.ID, Completed, Investigating, ""); err == nil {
		t.Fatal("out-of-order transition accepted")
	}
	if err = s.Transition(context.Background(), i.ID, Queued, Investigating, ""); err != nil {
		t.Fatal(err)
	}
	n, err := s.Recover(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("recover n=%d err=%v", n, err)
	}
	got, ok, err := s.Get(context.Background(), i.ID, true)
	if err != nil || !ok || got.State != Recovery {
		t.Fatalf("recovered=%#v ok=%v err=%v", got, ok, err)
	}
}

type testInvestigator struct {
	result  InvestigationResult
	request InvestigationRequest
}

func (i *testInvestigator) Investigate(_ context.Context, r InvestigationRequest) (InvestigationResult, error) {
	i.request = r
	return i.result, nil
}

func TestInvestigateIsBoundedAndPersistsResult(t *testing.T) {
	s := testStore(t)
	i, _, _ := s.Intake(context.Background(), Alert{Source: "gatus", Title: "x", Fingerprint: "x"})
	inv := &testInvestigator{result: InvestigationResult{State: Completed, Detail: "read-only evidence"}}
	got, err := s.Investigate(context.Background(), i.ID, inv)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Completed || got.Rounds != 1 || inv.request.Deadline > time.Second {
		t.Fatalf("result=%#v request=%#v", got, inv.request)
	}
}

func TestInvestigateBudgetAndRoundCaps(t *testing.T) {
	s := testStore(t)
	i, _, _ := s.Intake(context.Background(), Alert{Source: "gatus", Title: "x", Fingerprint: "x"})
	if _, err := s.Investigate(context.Background(), i.ID, &testInvestigator{result: InvestigationResult{State: Recovery}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Investigate(context.Background(), i.ID, &testInvestigator{result: InvestigationResult{State: Completed}}); err == nil {
		t.Fatal("second investigation exceeded attempt cap")
	}
	if _, _, err := s.Get(context.Background(), i.ID, true); errors.Is(err, sql.ErrNoRows) {
		t.Fatal("incident disappeared")
	}
}

func TestInvestigateReservesDailyBudgetBeforeModelCall(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "incidents.db"), Limits{DailyBudgetUSD: 0.25, InvestigationBudgetUSD: 0.25, MaxIncidents: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for n := 0; n < 2; n++ {
		i, _, intakeErr := s.Intake(context.Background(), Alert{Source: "gatus", Title: "x", Fingerprint: string(rune('a' + n))})
		if intakeErr != nil {
			t.Fatal(intakeErr)
		}
		_, investigateErr := s.Investigate(context.Background(), i.ID, &testInvestigator{result: InvestigationResult{State: Completed}})
		if investigateErr != nil && n == 0 {
			t.Fatal(investigateErr)
		}
		if n == 1 && investigateErr == nil {
			t.Fatal("investigation exceeded the conservative daily budget")
		}
	}
}
