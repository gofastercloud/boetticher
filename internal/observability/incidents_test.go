package observability

import (
	"context"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"strings"
	"testing"
)

type incidentCommandRunner struct{ calls []string }

func (r *incidentCommandRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	return controllerhost.Result{Stdout: []byte("{}\n")}, nil
}

// Keep the command assertion small and use the existing controller result
// type through the test helper below; this test is primarily a secret-boundary
// regression.
func TestGrafanaIncidentCommandUsesGuestAuthBoundary(t *testing.T) {
	// The endpoint builder is covered by the invalid-id path without invoking a
	// remote runner. Secret values must never be accepted as an incident id.
	client := HostClient{}
	if _, err := client.GrafanaIncident(context.Background(), binding, "password secret"); err == nil {
		t.Fatal("invalid incident id was accepted")
	}
}

func TestGrafanaIncidentCommandUsesHolmesCredentialAndLocalService(t *testing.T) {
	runner := &incidentCommandRunner{}
	_, err := (HostClient{Transport: runner}).GrafanaIncidents(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !strings.Contains(runner.calls[0], "holmes-client-token.cred") || !strings.Contains(runner.calls[0], "127.0.0.1:8091") {
		t.Fatalf("incident command boundary = %v", runner.calls)
	}
	if strings.Contains(runner.calls[0], "grafana-admin-password") {
		t.Fatal("incident command accessed Grafana admin credential")
	}
}
