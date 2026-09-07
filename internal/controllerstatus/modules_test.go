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
	if result.DHCPNTP.Configured || result.DNS.Configured || result.DHCPNTP.Detail == "" || result.DNS.Detail == "" {
		t.Fatalf("unimplemented capability result = %#v", result)
	}
	if command != "/usr/local/bin/boetticher module firewall status" {
		t.Fatalf("module status command = %s", command)
	}
	if strings.Contains(command, "site.yml") {
		t.Fatalf("module status command reintroduced site.yml: %s", command)
	}
}

func TestModuleCheckerKeepsUnimplementedCapabilitiesOff(t *testing.T) {
	checker := ModuleChecker{FirewallCommand: func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true, Detail: "ok"} }}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || !result.Firewall.Healthy {
		t.Fatalf("firewall result = %#v", result.Firewall)
	}
	if result.DHCPNTP.Configured || result.DNS.Configured || !strings.Contains(result.DHCPNTP.Detail, "not configured") || !strings.Contains(result.DNS.Detail, "not configured") {
		t.Fatalf("unimplemented capabilities did not remain off: %#v", result)
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
			DHCPNTP:  CheckResult{Detail: "DHCP/DDNS/NTP capability is not configured"},
			DNS:      CheckResult{Detail: "DNS capability is not configured"},
		}
	}
	d.Now = func() time.Time { return time.Unix(100, 0) }
	d.refresh(context.Background())
	if d.snapshot.Firewall.State != Healthy || d.snapshot.DHCPNTP.State != Off || d.snapshot.DNS.State != Off {
		t.Fatalf("module display slots = firewall:%#v dhcp:%#v dns:%#v", d.snapshot.Firewall, d.snapshot.DHCPNTP, d.snapshot.DNS)
	}
	if d.snapshot.Firewall.Detail == "" {
		t.Fatal("firewall detail was lost")
	}
}
