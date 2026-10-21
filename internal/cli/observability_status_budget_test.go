package cli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
)

// budgetRunner answers like an owned, running observability guest. results
// overrides per-service batched outcomes; blockBatch makes the batched check
// wait for the caller's deadline the way the SSH transport does.
type budgetRunner struct {
	mu         sync.Mutex
	calls      []string
	results    map[string][2]string
	blockBatch bool
}

func (r *budgetRunner) Run(ctx context.Context, command string) (controllerhost.Result, error) {
	r.mu.Lock()
	r.calls = append(r.calls, command)
	r.mu.Unlock()
	if strings.Contains(command, "boetticher-service-check") {
		if r.blockBatch {
			<-ctx.Done()
			return controllerhost.Result{ExitCode: 1}, fmt.Errorf("Proxmox SSH command timed out: %w", ctx.Err())
		}
		return controllerhost.Result{Stdout: []byte(batchedServiceResults(command, func(service string) (string, string) {
			if result, ok := r.results[service]; ok {
				return result[0], result[1]
			}
			return "active", "healthy"
		}))}, nil
	}
	return capabilityStatusRunner{}.Run(ctx, command)
}

func withHolmesObservability(t *testing.T, runner observability.Runner) {
	t.Helper()
	previousLoad, previousTransport, previousBudget := loadLabConfig, observabilityTransport, observabilityReadBudget
	t.Cleanup(func() {
		loadLabConfig, observabilityTransport, observabilityReadBudget = previousLoad, previousTransport, previousBudget
	})
	enabled, holmesEnabled := true, true
	loadLabConfig = func() (controllerhost.LabConfig, error) {
		return controllerhost.LabConfig{Name: "lab", Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}, Modules: clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, Monitoring: clientservices.MonitoringConfig{Holmes: &clientservices.HolmesConfig{Enabled: &holmesEnabled, ModelAlias: "operations", Bifrost: clientservices.BifrostConfig{ClientCredential: "holmes-client-token", Upstreams: []clientservices.BifrostUpstream{{Name: "provider", BaseURL: "https://provider.example", SecretRef: "provider-key"}}, Models: []clientservices.BifrostModel{{Alias: "operations", Upstream: "provider", Model: "provider/model"}}}}}}}}, nil
	}
	observabilityTransport = func(controllerhost.LabConfig) (observability.Runner, error) { return runner, nil }
}

func TestObservabilityStatusChecksAllServicesInBoundedRoundTrips(t *testing.T) {
	runner := &budgetRunner{}
	withHolmesObservability(t, runner)
	var out, errOut bytes.Buffer
	if err := runObservabilityCapability("observability", "status", nil, nil, &out, &errOut); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	// Ownership, guest state, and one batched check, independent of the seven
	// providers; per-service round trips are what overran the live budget.
	if len(runner.calls) != 3 {
		t.Fatalf("status used %d Host round trips, want 3: %q", len(runner.calls), runner.calls)
	}
	for _, service := range observability.ServicesForModules(mustLoadLab(t).Modules) {
		if !strings.Contains(out.String(), service+"=active") || !strings.Contains(out.String(), service+"-endpoint=healthy") {
			t.Fatalf("status output missing %s: %s", service, out.String())
		}
	}
}

func TestObservabilityStatusBudgetExhaustionIsNotReportedAsUnhealthy(t *testing.T) {
	runner := &budgetRunner{blockBatch: true}
	withHolmesObservability(t, runner)
	observabilityReadBudget = 50 * time.Millisecond
	var out, errOut bytes.Buffer
	err := runObservabilityCapability("observability", "status", nil, nil, &out, &errOut)
	if err == nil {
		t.Fatal("status passed after its budget ran out")
	}
	message := err.Error()
	for _, want := range []string{"module observability status budget of 50ms ran out during check services", "bifrost.service", "health not determined"} {
		if !strings.Contains(message, want) {
			t.Fatalf("budget error %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "unhealthy") {
		t.Fatalf("budget exhaustion blamed a service: %q", message)
	}
}

func TestObservabilityStatusReportsRealUnhealthyProviders(t *testing.T) {
	runner := &budgetRunner{results: map[string][2]string{
		"bifrost.service": {"active", "curl-7"},
		"grafana.service": {"failed", ""},
	}}
	withHolmesObservability(t, runner)
	var out, errOut bytes.Buffer
	err := runObservabilityCapability("observability", "status", nil, nil, &out, &errOut)
	if err == nil {
		t.Fatal("status passed with unhealthy providers")
	}
	for _, want := range []string{"service grafana.service unhealthy: failed", "provider bifrost.service unhealthy: bifrost.service health endpoint failed: connection refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("unhealthy error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "budget") {
		t.Fatalf("observed failure reported as budget exhaustion: %q", err)
	}
}

func TestObservabilityPlanDoesNotCallRuntimeHealthyFromOneService(t *testing.T) {
	runner := &budgetRunner{results: map[string][2]string{"grafana.service": {"active", "curl-22"}}}
	withHolmesObservability(t, runner)
	var out, errOut bytes.Buffer
	if err := runObservabilityCapability("observability", "plan", nil, nil, &out, &errOut); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	text := out.String()
	if strings.Contains(text, "Preserve") || !strings.Contains(text, "6/7 required services") || !strings.Contains(text, "Reconcile owned runtime and provider (unhealthy: grafana.service)") {
		t.Fatalf("plan did not report the unhealthy runtime truthfully:\n%s", text)
	}

	runner.results = nil
	out.Reset()
	if err := runObservabilityCapability("observability", "plan", nil, nil, &out, &errOut); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if !strings.Contains(out.String(), "7/7 required services active with healthy endpoints") || !strings.Contains(out.String(), "Preserve owned runtime unless apply finds configuration drift") {
		t.Fatalf("healthy plan did not state what it checked:\n%s", out.String())
	}
}

func TestObservabilityPlanNamesExhaustedBudget(t *testing.T) {
	runner := &budgetRunner{blockBatch: true}
	withHolmesObservability(t, runner)
	observabilityReadBudget = 50 * time.Millisecond
	var out, errOut bytes.Buffer
	if err := runObservabilityCapability("observability", "plan", nil, nil, &out, &errOut); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	text := out.String()
	if strings.Contains(text, "Preserve") || !strings.Contains(text, "runtime health not determined: module observability plan budget of 50ms ran out during check services") {
		t.Fatalf("plan did not name the exhausted budget:\n%s", text)
	}
}

func mustLoadLab(t *testing.T) controllerhost.LabConfig {
	t.Helper()
	config, err := loadLabConfig()
	if err != nil {
		t.Fatal(err)
	}
	return config
}
