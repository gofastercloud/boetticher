package controllerstatus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseTailnetResultRejectsStaleAndUnknownEvidence(t *testing.T) {
	now := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)
	valid := []byte(`{"configured":true,"state":"healthy","detail":"router healthy","observed_at":"2026-09-08T00:59:30Z"}`)
	if got := parseTailnetResult(valid, nil, now); got.State != Healthy || !got.Healthy {
		t.Fatalf("valid Tailnet status = %#v", got)
	}
	stale := []byte(`{"configured":true,"state":"healthy","detail":"router healthy","observed_at":"2026-09-08T00:00:00Z"}`)
	if got := parseTailnetResult(stale, nil, now); got.State != Failed {
		t.Fatalf("stale Tailnet status = %#v", got)
	}
	unknown := []byte(`{"configured":true,"state":"green","detail":"router healthy","observed_at":"2026-09-08T00:59:30Z"}`)
	if got := parseTailnetResult(unknown, nil, now); got.State != Failed {
		t.Fatalf("unknown Tailnet status = %#v", got)
	}
}

func TestParseTailnetResultAllowsValidNonzeroCommandStatesButNeverHealthy(t *testing.T) {
	now := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)
	attention := []byte(`{"configured":true,"state":"attention","detail":"route approval required","observed_at":"2026-09-08T00:59:30Z"}`)
	if got := parseTailnetResult(attention, errors.New("status exited 1"), now); got.State != Attention {
		t.Fatalf("attention Tailnet status = %#v", got)
	}
	healthy := []byte(`{"configured":true,"state":"healthy","detail":"router healthy","observed_at":"2026-09-08T00:59:30Z"}`)
	if got := parseTailnetResult(healthy, errors.New("status exited 1"), now); got.State != Failed {
		t.Fatalf("failed healthy Tailnet status = %#v", got)
	}
}

func TestModuleCheckerReusesNativeFirewallStatusCommand(t *testing.T) {
	var command string
	checker := ModuleChecker{
		CommandPath: "/usr/local/bin/boetticher",
		RunCommand: func(_ context.Context, path string, args ...string) ([]byte, error) {
			command = path + " " + strings.Join(args, " ")
			if strings.Join(args, " ") == "module firewall status" {
				return []byte("Firewall: PASS\n"), nil
			}
			return []byte("capability: not configured\n"), errors.New("not configured")
		},
	}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || !result.Firewall.Healthy {
		t.Fatalf("healthy firewall result = %#v", result.Firewall)
	}
	if result.DHCPNTP.Configured || result.DHCPNTP.State != Off || result.Tailnet.State != Failed || result.DHCPNTP.Detail == "" || result.Tailnet.Detail == "" {
		t.Fatalf("unimplemented capability result = %#v", result)
	}
	if command != "/usr/local/bin/boetticher module firewall status" {
		t.Fatalf("module status command = %s", command)
	}
	if strings.Contains(command, "site.yml") {
		t.Fatalf("module status command reintroduced site.yml: %s", command)
	}
}

func TestModuleCheckerTreatsUnconfiguredCapabilitiesAsOff(t *testing.T) {
	checker := ModuleChecker{FirewallCommand: func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true, Detail: "ok"} }}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || !result.Firewall.Healthy {
		t.Fatalf("firewall result = %#v", result.Firewall)
	}
	if result.DHCPNTP.Configured || result.DHCPNTP.State != Off || result.Tailnet.Configured || result.Tailnet.State != Off || !strings.Contains(result.DHCPNTP.Detail, "not configured") || !strings.Contains(result.Tailnet.Detail, "not configured") {
		t.Fatalf("unconfigured capabilities were not off: %#v", result)
	}
}

func TestDaemonMapsModuleStatusToExistingDisplaySlots(t *testing.T) {
	d := NewDaemon(DefaultSettings(), nil)
	d.Controller = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Host = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Connectivity = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Throughput = func(context.Context) (float64, error) { return 600, nil }
	d.Modules = func(context.Context) ModuleStatus {
		return ModuleStatus{
			Firewall: CheckResult{Configured: true, Healthy: true, Detail: "firewall provider is running"},
			DHCPNTP:  CheckResult{Configured: true, State: Failed, Detail: "DHCP/NTP capability is unavailable"},
			Tailnet:  CheckResult{Configured: true, State: Failed, Detail: "Tailnet capability is unavailable"},
		}
	}
	d.Now = func() time.Time { return time.Unix(100, 0) }
	d.refresh(context.Background())
	if d.snapshot.Firewall.State != Healthy || d.snapshot.DHCPNTP.State != Failed || d.snapshot.Tailnet.State != Failed {
		t.Fatalf("module display slots = firewall:%#v dhcp:%#v tailnet:%#v", d.snapshot.Firewall, d.snapshot.DHCPNTP, d.snapshot.Tailnet)
	}
	if d.snapshot.Firewall.Detail == "" {
		t.Fatal("firewall detail was lost")
	}
}

func TestDaemonGivesSequentialModuleChecksTheirBoundedBudget(t *testing.T) {
	d := NewDaemon(DefaultSettings(), nil)
	d.Controller = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Host = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Connectivity = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Throughput = func(context.Context) (float64, error) { return 600, nil }
	var deadline time.Time
	d.Modules = func(ctx context.Context) ModuleStatus {
		deadline, _ = ctx.Deadline()
		return ModuleStatus{Firewall: CheckResult{Configured: true, Healthy: true}}
	}

	d.refresh(context.Background())

	remaining := time.Until(deadline)
	if deadline.IsZero() || remaining < 15*time.Second || remaining > moduleCheckTimeout {
		t.Fatalf("module check deadline = %v from now, want a bounded %s budget", remaining, moduleCheckTimeout)
	}
}

func TestModuleComponentPreservesActionRequiredAndConfigStagedStates(t *testing.T) {
	for _, test := range []struct {
		name  string
		state State
	}{
		{name: "action required", state: Attention},
		{name: "configuration staged", state: Checking},
		{name: "healthy", state: Healthy},
		{name: "error", state: Failed},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := moduleComponent(CheckResult{Configured: true, State: test.state, Detail: test.name})
			if result.State != test.state || result.Detail != test.name {
				t.Fatalf("module state = %#v, want %s", result, test.state)
			}
		})
	}
}

func TestDebouncedModuleComponentPreservesExplicitNonHealthStates(t *testing.T) {
	debouncer := NewDebouncer(Healthy)
	attention := debouncedModuleComponent(debouncer, CheckResult{Configured: true, State: Attention, Detail: "action required"})
	if attention.State != Attention {
		t.Fatalf("action-required module state = %#v", attention)
	}
	staged := debouncedModuleComponent(debouncer, CheckResult{Configured: true, State: Checking, Detail: "configuration staged"})
	if staged.State != Checking {
		t.Fatalf("staged module state = %#v", staged)
	}
}
