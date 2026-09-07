package controllerstatus

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestModuleCheckerReusesNativeFirewallStatusCommand(t *testing.T) {
	var command string
	checker := ModuleChecker{
		CommandPath: "/usr/local/bin/boetticher",
		RunCommand: func(_ context.Context, path string, args ...string) ([]byte, error) {
			command = path + " " + strings.Join(args, " ")
			return []byte("Firewall: PASS\n"), nil
		},
	}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || !result.Firewall.Healthy {
		t.Fatalf("healthy firewall result = %#v", result.Firewall)
	}
	if !result.DHCPNTP.Configured || result.DHCPNTP.State != Failed || !result.DNS.Configured || result.DNS.State != Failed || result.DHCPNTP.Detail == "" || result.DNS.Detail == "" {
		t.Fatalf("unimplemented capability result = %#v", result)
	}
	if command != "/usr/local/bin/boetticher module firewall status" {
		t.Fatalf("module status command = %s", command)
	}
	if strings.Contains(command, "site.yml") {
		t.Fatalf("module status command reintroduced site.yml: %s", command)
	}
}

func TestModuleCheckerKeepsUnimplementedCapabilitiesRed(t *testing.T) {
	checker := ModuleChecker{FirewallCommand: func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true, Detail: "ok"} }}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || !result.Firewall.Healthy {
		t.Fatalf("firewall result = %#v", result.Firewall)
	}
	if !result.DHCPNTP.Configured || result.DHCPNTP.State != Failed || !result.DNS.Configured || result.DNS.State != Failed || !strings.Contains(result.DHCPNTP.Detail, "not implemented") || !strings.Contains(result.DNS.Detail, "not implemented") {
		t.Fatalf("unimplemented capabilities did not remain red: %#v", result)
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
			DHCPNTP:  CheckResult{Configured: true, State: Failed, Detail: "DHCP/DDNS/NTP capability is not implemented"},
			DNS:      CheckResult{Configured: true, State: Failed, Detail: "DNS capability is not implemented"},
		}
	}
	d.Now = func() time.Time { return time.Unix(100, 0) }
	d.refresh(context.Background())
	if d.snapshot.Firewall.State != Healthy || d.snapshot.DHCPNTP.State != Failed || d.snapshot.DNS.State != Failed {
		t.Fatalf("module display slots = firewall:%#v dhcp:%#v dns:%#v", d.snapshot.Firewall, d.snapshot.DHCPNTP, d.snapshot.DNS)
	}
	if d.snapshot.Firewall.Detail == "" {
		t.Fatal("firewall detail was lost")
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
