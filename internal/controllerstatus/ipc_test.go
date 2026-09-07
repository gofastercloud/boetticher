package controllerstatus

import (
	"context"
	"testing"
)

func TestValidateEventRejectsUnknownOrOversizedEvents(t *testing.T) {
	if err := ValidateEvent(OperationEvent{Event: "run-command", Name: "bad"}); err == nil {
		t.Fatal("unknown event was accepted")
	}
	if err := ValidateEvent(OperationEvent{Event: "operation-start", Name: "bad", TotalSteps: PixelCount*16 + 1}); err == nil {
		t.Fatal("oversized event was accepted")
	}
	if err := ValidateEvent(OperationEvent{Event: "operation-start", Name: "host apply", TotalSteps: 5}); err != nil {
		t.Fatal(err)
	}
}

func TestMissingSocketIsAnAdvisoryError(t *testing.T) {
	err := Notify(context.Background(), "/nonexistent/boetticher-status.sock", OperationEvent{Event: "operation-start", Name: "host apply", Steps: 5})
	if err == nil {
		t.Fatal("missing status socket unexpectedly succeeded")
	}
	// CLI callers use NotifyBestEffort/ignore the returned error; this test
	// preserves the explicit non-gating boundary.
}
