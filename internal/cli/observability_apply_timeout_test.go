package cli

import (
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
)

func TestObservabilityApplyUsesItsExistingLongBudget(t *testing.T) {
	previous := observabilityTransport
	defer func() { observabilityTransport = previous }()
	observabilityTransport = func(controllerhost.LabConfig) (observability.Runner, error) {
		return controllerhost.Transport{Timeout: 30 * time.Second}, nil
	}
	transport, err := observabilityApplyTransport(controllerhost.LabConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if transport.Timeout != 30*time.Minute {
		t.Fatalf("observability apply transport timeout = %s, want 30m", transport.Timeout)
	}
}
