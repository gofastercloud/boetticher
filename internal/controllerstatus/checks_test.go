package controllerstatus

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestControllerCheckerRequiresReadableConfigServicesAndDiskSpace(t *testing.T) {
	config := filepath.Join(t.TempDir(), "controller.yml")
	if err := os.WriteFile(config, []byte("operator_user: pi\n"), 0600); err != nil {
		t.Fatal(err)
	}
	updates := filepath.Join(t.TempDir(), "unattended.conf")
	if err := os.WriteFile(updates, []byte("APT::Periodic::Unattended-Upgrade \"1\";\nUnattended-Upgrade::Automatic-Reboot \"false\";\n"), 0600); err != nil {
		t.Fatal(err)
	}
	checker := ControllerChecker{
		ConfigPath:       config,
		UpdateConfigPath: updates,
		RequiredServices: []string{"ssh.service"},
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return nil, nil
		},
		Statfs: func(_ string, stat *syscall.Statfs_t) error {
			stat.Bavail = 1 << 20
			stat.Bsize = 4096
			return nil
		},
	}
	if result := checker.Check(context.Background()); !result.Healthy || result.Update.State != Healthy {
		t.Fatalf("healthy controller result = %#v", result)
	}
	checker.RunCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("inactive") }
	if result := checker.Check(context.Background()); result.Healthy {
		t.Fatal("inactive required service was accepted")
	}
	checker.RunCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	checker.Statfs = func(_ string, stat *syscall.Statfs_t) error {
		stat.Bavail = 1
		stat.Bsize = 4096
		return nil
	}
	if result := checker.Check(context.Background()); result.Healthy {
		t.Fatal("critically full root filesystem was accepted")
	}
}

func TestHostCheckerIsOffWhenNotEnrolledAndReadOnlyWhenEnrolled(t *testing.T) {
	checker := HostChecker{LoadConfig: func() (controllerhost.LabConfig, error) {
		return controllerhost.LabConfig{}, os.ErrNotExist
	}}
	if result := checker.Check(context.Background()); result.Configured || result.Healthy {
		t.Fatalf("unenrolled Host result = %#v", result)
	}
	network := controllerhost.DefaultNetworkConfig()
	config := controllerhost.LabConfig{
		Name:    "lab",
		Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.5", User: "root", Node: "pve", Repository: "no-subscription"},
		Network: &network,
	}
	var command string
	checker.LoadConfig = func() (controllerhost.LabConfig, error) { return config, nil }
	checker.Transport = func(controllerhost.LabConfig) (controllerhost.Transport, error) {
		return controllerhost.Transport{}, nil
	}
	checker.Run = func(_ context.Context, _ controllerhost.Transport, value string) (controllerhost.Result, error) {
		command = value
		return controllerhost.Result{Stdout: []byte("BOETTICHER_PVE_UPDATES=pve-manager,\nBOETTICHER_PVE_REBOOT=0\n")}, nil
	}
	if result := checker.Check(context.Background()); !result.Healthy {
		t.Fatalf("healthy Host result = %#v", result)
	}
	if command == "" || !containsAll(command, "hostname", "pve-cluster", "192.0.2.5", "vmbr1") {
		t.Fatalf("Host check command omitted read-only fundamentals: %s", command)
	}
	if containsAny(command, "ansible", "apply", "rm -", "mktemp") {
		t.Fatalf("Host check command contains mutation: %s", command)
	}
	if containsAny(command, "--output-format json") {
		t.Fatalf("Host check used unsupported pvesm JSON output: %s", command)
	}
	if !strings.Contains(command, "/sys/class/net/$interface/device") {
		t.Fatalf("Host check does not distinguish guest bridge ports from physical members: %s", command)
	}
	if result := checker.Check(context.Background()); result.Update.State != Attention {
		t.Fatalf("Host update state did not report pending Proxmox update: %#v", result.Update)
	}
	checker.Run = func(_ context.Context, _ controllerhost.Transport, _ string) (controllerhost.Result, error) {
		return controllerhost.Result{Stdout: []byte("BOETTICHER_PVE_UPDATES=\nBOETTICHER_PVE_REBOOT=0\n")}, errors.New("vmbr1 conflict")
	}
	if result := checker.Check(context.Background()); result.Healthy || result.Update.State != Healthy {
		t.Fatalf("Host health failure obscured update state = %#v", result)
	}
	checker.Run = func(_ context.Context, _ controllerhost.Transport, _ string) (controllerhost.Result, error) {
		return controllerhost.Result{}, errors.New("connection failed")
	}
	if result := checker.Check(context.Background()); result.Update.State != Attention {
		t.Fatalf("missing Host update markers were accepted: %#v", result.Update)
	}
}

func TestHostSpeedtestCheckerUsesTheHostHelperAndParsesDownload(t *testing.T) {
	network := controllerhost.DefaultNetworkConfig()
	config := controllerhost.LabConfig{
		Name:    "lab",
		Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.5", User: "root", Node: "pve", Repository: "no-subscription"},
		Network: &network,
	}
	var command string
	checker := HostSpeedtestChecker{
		LoadConfig: func() (controllerhost.LabConfig, error) { return config, nil },
		Transport: func(controllerhost.LabConfig) (controllerhost.Transport, error) {
			return controllerhost.Transport{}, nil
		},
		Run: func(_ context.Context, _ controllerhost.Transport, value string) (controllerhost.Result, error) {
			command = value
			return controllerhost.Result{Stdout: []byte(`[{"download_mbps": 612.5}]`)}, nil
		},
	}
	speed, err := checker.Sample(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if speed != 612.5 || command != DefaultHostSpeedtestPath+" --source vmbr0 --json" {
		t.Fatalf("Host speedtest = %.1f command=%q", speed, command)
	}
}

func TestRebootRequiredMapping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reboot-required")
	if result := RebootResult(path); result.State != Off {
		t.Fatalf("missing reboot marker = %#v", result)
	}
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	if result := RebootResult(path); result.State != Attention {
		t.Fatalf("reboot marker = %#v", result)
	}
}

func TestInternetThresholdAndFailureDebounce(t *testing.T) {
	settings := DefaultSettings()
	settings.ThroughputInterval = time.Hour
	settings.HealthyMbps = 500
	settings.ConfigPath = filepath.Join(t.TempDir(), "controller.yml")
	if err := os.WriteFile(settings.ConfigPath, []byte("operator_user: pi\n"), 0600); err != nil {
		t.Fatal(err)
	}
	makeDaemon := func(online CheckResult, speed float64, haveSample bool) *Daemon {
		d := NewDaemon(settings, nil)
		d.Controller = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
		d.Host = func(context.Context) CheckResult { return CheckResult{} }
		d.Connectivity = func(context.Context) CheckResult { return online }
		d.Throughput = func(context.Context) (float64, error) {
			if !haveSample {
				return 0, errors.New("no sample")
			}
			return speed, nil
		}
		d.Now = func() time.Time { return time.Unix(100, 0) }
		return d
	}
	for _, test := range []struct {
		name  string
		speed float64
		state State
	}{
		{"fast", 500, Healthy},
		{"slow", 499, Attention},
		{"missing", 0, Attention},
	} {
		d := makeDaemon(CheckResult{Configured: true, Healthy: true}, test.speed, test.name != "missing")
		d.refresh(context.Background())
		if d.snapshot.Internet.State != test.state {
			t.Fatalf("%s Internet state = %s, want %s", test.name, d.snapshot.Internet.State, test.state)
		}
	}
	d := makeDaemon(CheckResult{Configured: true, Healthy: false}, 0, false)
	d.refresh(context.Background())
	if d.snapshot.Internet.State != Checking {
		t.Fatalf("first connectivity failure = %s, want checking", d.snapshot.Internet.State)
	}
	d.connectivityAt = time.Time{}
	d.refresh(context.Background())
	if d.snapshot.Internet.State != Failed {
		t.Fatalf("second connectivity failure = %s, want failed", d.snapshot.Internet.State)
	}
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
