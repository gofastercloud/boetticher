package cli

import (
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
)

func TestHolmesAskUsesBoundedModelTransportTimeout(t *testing.T) {
	previous := observabilityTransport
	defer func() { observabilityTransport = previous }()
	observabilityTransport = func(controllerhost.LabConfig) (observability.Runner, error) {
		return controllerhost.Transport{Timeout: 30 * time.Second, Address: "192.0.2.10", User: "root"}, nil
	}
	transport, err := holmesAskTransport(controllerhost.LabConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if transport.Timeout != holmesAskTimeout {
		t.Fatalf("Holmes transport timeout = %s, want %s", transport.Timeout, holmesAskTimeout)
	}
}
