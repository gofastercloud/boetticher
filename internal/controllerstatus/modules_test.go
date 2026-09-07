package controllerstatus

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestModuleCheckerUsesReadOnlyHostProviderIdentityCheck(t *testing.T) {
	config := controllerhost.LabConfig{
		Name:    "lab",
		Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.5", User: "root", Node: "pve", Repository: "no-subscription"},
	}
	var command string
	checker := ModuleChecker{
		LoadConfig: func() (controllerhost.LabConfig, error) { return config, nil },
		Transport: func(controllerhost.LabConfig) (controllerhost.Transport, error) {
			return controllerhost.Transport{}, nil
		},
		Run: func(_ context.Context, _ controllerhost.Transport, value string) (controllerhost.Result, error) {
			command = value
			return controllerhost.Result{}, nil
		},
	}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || !result.Firewall.Healthy {
		t.Fatalf("healthy firewall result = %#v", result.Firewall)
	}
	if result.DHCPNTP.Healthy || result.DNS.Healthy || result.DHCPNTP.Detail == "" || result.DNS.Detail == "" {
		t.Fatalf("unimplemented capability result = %#v", result)
	}
	if !containsAll(command, "qm status", "qm config", "name: lab-firewall-01", "bridge=vmbr0", "bridge=vmbr1") {
		t.Fatalf("provider identity check omitted required read-only checks: %s", command)
	}
	if containsAny(command, "apply", "start", "stop", "destroy", "rm ", "uci", "curl") {
		t.Fatalf("provider identity check contains mutation or provider API access: %s", command)
	}
}

func TestModuleCheckerKeepsUnimplementedCapabilitiesRedWhenHostIsUnavailable(t *testing.T) {
	checker := ModuleChecker{LoadConfig: func() (controllerhost.LabConfig, error) { return controllerhost.LabConfig{}, os.ErrNotExist }}
	result := checker.Check(context.Background())
	if result.Firewall.Configured || result.Firewall.Healthy {
		t.Fatalf("unenrolled firewall result = %#v", result.Firewall)
	}
	if result.DHCPNTP.Healthy || result.DNS.Healthy || !strings.Contains(result.DHCPNTP.Detail, "not implemented") || !strings.Contains(result.DNS.Detail, "not implemented") {
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
			DHCPNTP:  CheckResult{Configured: true, Detail: "DHCP/DDNS/NTP capability is not implemented"},
			DNS:      CheckResult{Configured: true, Detail: "DNS capability is not implemented"},
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

func TestModuleCheckerPreservesTransportFailureAsFirewallFailure(t *testing.T) {
	checker := ModuleChecker{
		LoadConfig: func() (controllerhost.LabConfig, error) {
			return controllerhost.LabConfig{Proxmox: controllerhost.ProxmoxConfig{Node: "pve"}}, nil
		},
		Transport: func(controllerhost.LabConfig) (controllerhost.Transport, error) {
			return controllerhost.Transport{}, errors.New("invalid")
		},
	}
	result := checker.Check(context.Background())
	if !result.Firewall.Configured || result.Firewall.Healthy {
		t.Fatalf("transport failure result = %#v", result.Firewall)
	}
}
