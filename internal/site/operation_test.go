package site

import (
	"strings"
	"testing"
)

func TestOperationAndLastAppliedStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	operation := OperationState{ID: "run-1", Kind: "deploy", Phase: PhaseApply, ModelRevision: "model-1", PlanDigest: strings.Repeat("a", 64)}
	if err := SaveOperationState(dir, operation); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := LoadOperationState(dir)
	if err != nil || !found || loaded.ID != operation.ID || loaded.Phase != PhaseApply {
		t.Fatalf("operation state = %#v, err=%v, found=%t", loaded, err, found)
	}
	lastApplied := LastAppliedState{ModelRevision: "model-1", PlanDigest: strings.Repeat("b", 64)}
	if err := SaveLastAppliedState(dir, lastApplied); err != nil {
		t.Fatal(err)
	}
	committed, found, err := LoadLastAppliedState(dir)
	if err != nil || !found || committed.ModelRevision != lastApplied.ModelRevision {
		t.Fatalf("last-applied state = %#v, err=%v, found=%t", committed, err, found)
	}
	if err := ClearOperationState(dir); err != nil {
		t.Fatal(err)
	}
	if _, found, err := LoadOperationState(dir); err != nil || found {
		t.Fatalf("operation state remained after clear: err=%v, found=%t", err, found)
	}
}

func TestOperationStateRejectsInvalidPhase(t *testing.T) {
	err := SaveOperationState(t.TempDir(), OperationState{ID: "run-1", Kind: "deploy", Phase: "MUTATE", ModelRevision: "model", PlanDigest: strings.Repeat("a", 64)})
	if err == nil {
		t.Fatal("invalid operation phase was accepted")
	}
}
