package controllerstatus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestParseProxmoxTelemetryNormalizesAndSorts(t *testing.T) {
	host, err := parseProxmoxHost([]byte(`{"data":{"node":"pve","pveversion":"pve-manager/9.2.2","cpu":0.18,"memory":{"used":4294967296,"total":8589934592},"uptime":3600}}`), "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if host.Node != "pve" || host.CPUPercent != 18 || host.MemoryUsed != 4294967296 || host.Uptime != time.Hour {
		t.Fatalf("host = %#v", host)
	}
	storage, err := parseProxmoxStorage([]byte(`[{"storage":"local","used":25,"total":100},{"storage":"boetticher-data","used":45,"total":100}]`))
	if err != nil || len(storage) != 2 || storage[0].Name != "boetticher-data" || storage[0].Percent != 45 {
		t.Fatalf("storage = %#v, err=%v", storage, err)
	}
	guests, err := parseProxmoxGuests([]byte(`{"data":[{"vmid":310,"name":"kali","type":"qemu","status":"stopped"},{"vmid":201,"name":"pulse","type":"lxc","status":"running","cpu":0.03,"mem":412,"maxmem":1024,"uptime":86400},{"vmid":280,"name":"lab-firewall-01","type":"qemu","status":"running"}]}`))
	if err != nil || len(guests) != 3 || guests[0].VMID != 201 || guests[0].Kind != "lxc" || guests[1].VMID != 280 || guests[1].Name != "lab-firewall-01" || guests[2].Kind != "vm" {
		t.Fatalf("guests = %#v, err=%v", guests, err)
	}
}

func TestParseProxmoxTelemetryRejectsMalformedGuest(t *testing.T) {
	if _, err := parseProxmoxGuests([]byte(`[{"vmid":1,"name":"bad","type":"unknown"}]`)); err == nil {
		t.Fatal("unknown guest type was accepted")
	}
	if _, err := parseProxmoxHost([]byte(`{"data":null}`), "pve"); err == nil {
		t.Fatal("empty Host response was accepted")
	}
}

func TestProxmoxCollectorUsesFixedReadOnlyCommands(t *testing.T) {
	config := controllerhost.LabConfig{Proxmox: controllerhost.ProxmoxConfig{Node: "pve", Address: "192.0.2.5", User: "root"}}
	var commands []string
	collector := ProxmoxCollector{
		LoadConfig: func() (controllerhost.LabConfig, error) { return config, nil },
		Transport: func(controllerhost.LabConfig) (controllerhost.Transport, error) {
			return controllerhost.Transport{}, nil
		},
		Run: func(_ context.Context, _ controllerhost.Transport, command string) (controllerhost.Result, error) {
			commands = append(commands, command)
			switch len(commands) {
			case 1:
				return controllerhost.Result{Stdout: []byte(`{"node":"pve","cpu":0.5,"mem":1,"maxmem":2,"uptime":1}`)}, nil
			case 2:
				return controllerhost.Result{Stdout: []byte(`[]`)}, nil
			default:
				return controllerhost.Result{Stdout: []byte(`[]`)}, nil
			}
		},
		Now: func() time.Time { return time.Unix(100, 0) },
	}
	snapshot, err := collector.Collect(context.Background())
	if err != nil || snapshot.Host.Node != "pve" || !snapshot.FetchedAt.Equal(time.Unix(100, 0).UTC()) {
		t.Fatalf("snapshot = %#v, err=%v", snapshot, err)
	}
	if len(commands) != 3 || !strings.Contains(commands[0], "pvesh get /nodes/'pve'/status") || !strings.Contains(commands[2], "--type vm") {
		t.Fatalf("collector commands = %#v", commands)
	}
	for _, command := range commands {
		if strings.Contains(command, "apt-get") || strings.Contains(command, "systemctl") || strings.Contains(command, "rm ") {
			t.Fatalf("collector command mutates Host: %s", command)
		}
	}
}

func TestProxmoxCollectorRequiresEnrollment(t *testing.T) {
	collector := ProxmoxCollector{LoadConfig: func() (controllerhost.LabConfig, error) { return controllerhost.LabConfig{}, os.ErrNotExist }}
	if _, err := collector.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "Host not enrolled") {
		t.Fatalf("unenrolled collector error = %v", err)
	}
}

func TestDaemonRefreshesStreamDeckTelemetryIndependently(t *testing.T) {
	settings := DefaultSettings()
	settings.Interval = time.Hour
	settings.TelemetryInterval = 20 * time.Millisecond
	dir, err := os.MkdirTemp("/tmp", "boetticher-status-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	settings.SocketPath = filepath.Join(dir, "status.sock")
	d := NewDaemon(settings, nil)
	d.StreamDeckFactory = func(context.Context) (StreamDeck, error) { return nil, nil }
	d.Controller = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Host = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Modules = func(context.Context) ModuleStatus { return ModuleStatus{} }
	d.Connectivity = func(context.Context) CheckResult { return CheckResult{Configured: true, Healthy: true} }
	d.Throughput = func(context.Context) (float64, error) { return 600, nil }
	telemetryCalls := make(chan struct{}, 4)
	d.Telemetry = func(context.Context) (ProxmoxSnapshot, error) {
		telemetryCalls <- struct{}{}
		return ProxmoxSnapshot{Host: ProxmoxHostStats{Node: "pve"}, FetchedAt: time.Now()}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	for call := 0; call < 2; call++ {
		select {
		case <-telemetryCalls:
		case err := <-done:
			t.Fatalf("status daemon stopped before telemetry call %d: %v", call+1, err)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("telemetry call %d was not scheduled independently of the status interval", call+1)
		}
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
