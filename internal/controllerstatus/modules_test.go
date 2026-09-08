package controllerstatus

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

type responsiveStatusDeck struct {
	events   chan KeyEvent
	nodeSeen chan struct{}
}

func (d *responsiveStatusDeck) SetKey(_ context.Context, _ int, key KeyImage) error {
	if key.Title == "NODE" {
		select {
		case d.nodeSeen <- struct{}{}:
		default:
		}
	}
	return nil
}
func (d *responsiveStatusDeck) Clear(context.Context) error { return nil }
func (d *responsiveStatusDeck) Events() <-chan KeyEvent     { return d.events }
func (d *responsiveStatusDeck) Close() error                { return nil }

type statusLogWriter chan<- string

func (w statusLogWriter) Write(data []byte) (int, error) {
	w <- string(data)
	return len(data), nil
}

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
	var firewallCommand bool
	checker := ModuleChecker{
		CommandPath: "/usr/local/bin/boetticher",
		RunCommand: func(_ context.Context, path string, args ...string) ([]byte, error) {
			if strings.Join(args, " ") == "module firewall status" {
				firewallCommand = path == "/usr/local/bin/boetticher"
				return []byte("Firewall: PASS\n"), nil
			}
			return []byte("capability: not configured\n"), errors.New("not configured")
		},
	}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || !result.Firewall.Healthy {
		t.Fatalf("healthy firewall result = %#v", result.Firewall)
	}
	if result.DHCPNTP.Configured || result.DHCPNTP.State != Off || result.DNS.Configured || result.DNS.State != Off || result.VPN.State != Failed || result.Tailnet.State != Failed || result.DHCPNTP.Detail == "" || result.DNS.Detail == "" || result.VPN.Detail == "" || result.Tailnet.Detail == "" {
		t.Fatalf("unimplemented capability result = %#v", result)
	}
	if !firewallCommand {
		t.Fatal("native firewall status command was not used")
	}
}

func TestModuleCheckerDistinguishesVPNFailureAndDNSFailureFromOff(t *testing.T) {
	checker := ModuleChecker{
		CommandPath: "/usr/local/bin/boetticher",
		RunCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			switch strings.Join(args, " ") {
			case "module dhcp status":
				return []byte("DHCP: PASS\n"), nil
			case "module dns status":
				return []byte("DNS: FAIL\n"), errors.New("dns unavailable")
			case "module vpn status":
				return []byte("VPN: BLOCKED\n"), errors.New("vpn unavailable")
			case "module tailnet status --json":
				return []byte(`{"configured":false,"state":"off","detail":"Tailnet capability not configured","observed_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`), nil
			case "module firewall status":
				return []byte("Firewall: PASS\n"), nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	}
	result := checker.Check(context.Background())
	if !result.DHCPNTP.Healthy || result.DHCPNTP.State != Healthy {
		t.Fatalf("healthy DHCP result = %#v", result.DHCPNTP)
	}
	if result.DNS.State != Failed || !result.DNS.Configured {
		t.Fatalf("failed DNS result = %#v", result.DNS)
	}
	if result.VPN.State != Failed || !result.VPN.Configured {
		t.Fatalf("failed VPN result = %#v", result.VPN)
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
			VPN:      CheckResult{Configured: true, State: Failed, Detail: "VPN status is not healthy"},
			DHCPNTP:  CheckResult{Configured: true, State: Failed, Detail: "DHCP/NTP capability is unavailable"},
			DNS:      CheckResult{Configured: true, State: Healthy, Detail: "DNS capability is healthy"},
			Tailnet:  CheckResult{Configured: true, State: Failed, Detail: "Tailnet capability is unavailable"},
		}
	}
	d.Now = func() time.Time { return time.Unix(100, 0) }
	d.refresh(context.Background())
	if d.snapshot.Firewall.State != Healthy || d.snapshot.VPN.State != Failed || d.snapshot.DHCPNTP.State != Failed || d.snapshot.DNS.State != Healthy || d.snapshot.Tailnet.State != Failed {
		t.Fatalf("module display slots = firewall:%#v vpn:%#v dhcp:%#v dns:%#v tailnet:%#v", d.snapshot.Firewall, d.snapshot.VPN, d.snapshot.DHCPNTP, d.snapshot.DNS, d.snapshot.Tailnet)
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

func TestDaemonProcessesIPCAndStreamDeckWhileModuleCheckRuns(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "bcs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	settings := DefaultSettings()
	settings.SocketPath = dir + "/status.sock"
	settings.Interval = time.Hour
	settings.TelemetryInterval = time.Hour
	deck := &responsiveStatusDeck{events: make(chan KeyEvent, 1), nodeSeen: make(chan struct{}, 1)}
	started := make(chan struct{})
	hostStarted := make(chan struct{})
	release := make(chan struct{})
	throughputStarted := make(chan struct{})
	throughputRelease := make(chan struct{})
	logs := make(chan string, 8)
	d := NewDaemon(settings, nil)
	d.Logger = log.New(statusLogWriter(logs), "", 0)
	d.StreamDeckFactory = func(context.Context) (StreamDeck, error) { return deck, nil }
	d.Controller = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Host = func(ctx context.Context) CheckResult {
		close(hostStarted)
		select {
		case <-release:
			return CheckResult{Configured: true, Healthy: true}
		case <-ctx.Done():
			return CheckResult{}
		}
	}
	d.Connectivity = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Throughput = func(ctx context.Context) (float64, error) {
		close(throughputStarted)
		select {
		case <-throughputRelease:
			return 600, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	d.Telemetry = func(context.Context) (ProxmoxSnapshot, error) { return ProxmoxSnapshot{}, nil }
	d.Modules = func(ctx context.Context) ModuleStatus {
		close(started)
		select {
		case <-release:
			return ModuleStatus{}
		case <-ctx.Done():
			return ModuleStatus{}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("status daemon exited before module check started: %v", err)
	case <-time.After(time.Second):
		t.Fatal("module check did not start")
	}
	select {
	case <-hostStarted:
	case err := <-done:
		t.Fatalf("status daemon exited before host check started: %v", err)
	case <-time.After(time.Second):
		t.Fatal("host check did not start")
	}
	if err := Notify(context.Background(), settings.SocketPath, OperationEvent{Event: "operation-start", Name: "host apply", TotalSteps: 1}); err != nil {
		t.Fatalf("notify operation: %v", err)
	}
	operationDeadline := time.After(time.Second)
	for {
		select {
		case message := <-logs:
			if strings.Contains(message, "operation started: host apply") {
				goto operationStarted
			}
		case <-operationDeadline:
			t.Fatal("operation IPC was blocked by module check")
		}
	}

operationStarted:
	deck.events <- KeyEvent{Index: 0}
	select {
	case <-deck.nodeSeen:
	case <-time.After(time.Second):
		t.Fatal("StreamDeck input was blocked by module check")
	}
	close(release)
	select {
	case <-throughputStarted:
	case <-time.After(time.Second):
		t.Fatal("throughput check did not start after refresh publication")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("status daemon did not stop")
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
