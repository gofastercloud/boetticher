package site

import (
	"strings"
	"testing"
)

func TestOperationAndLastAppliedStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	operation := OperationState{
		ID: "run-1", Kind: "deploy", Phase: PhaseApply, ModelRevision: "model-1", PlanDigest: strings.Repeat("a", 64),
		TemporaryPublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample boetticher-apply",
		TemporaryCleanupGuests: []OperationGuest{{Name: "lab-fw-01", Kind: "qemu", VMID: 100, Address: "10.10.99.1"}},
	}
	if err := SaveOperationState(dir, operation); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := LoadOperationState(dir)
	if err != nil || !found || loaded.ID != operation.ID || loaded.Phase != PhaseApply || loaded.TemporaryPublicKey != operation.TemporaryPublicKey || len(loaded.TemporaryCleanupGuests) != 1 {
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

func TestOperationStateRejectsCleanupTargetsWithoutAuthority(t *testing.T) {
	err := SaveOperationState(t.TempDir(), OperationState{
		ID: "run-1", Kind: "deploy", Phase: PhaseApply, ModelRevision: "model", PlanDigest: strings.Repeat("a", 64),
		TemporaryCleanupGuests: []OperationGuest{{Name: "lab-fw-01", Kind: "qemu", VMID: 100, Address: "10.10.99.1"}},
	})
	if err == nil || !strings.Contains(err.Error(), "cleanup guests without a temporary public key") {
		t.Fatalf("cleanup target without authority was accepted: %v", err)
	}
}
