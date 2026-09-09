package observability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/model"
)

func TestDefaultControllerIdentityUsesObservabilityRoute(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$ROUTE_ARGS\"\nprintf '2: eth1 inet 10.10.20.10/24 scope global eth1\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "cat"), []byte("#!/bin/sh\nprintf '6c:1f:f7:d2:5d:97\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	args := filepath.Join(bin, "args")
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("ROUTE_ARGS", args)
	got, err := defaultLocalControllerIdentityLookup()
	if err != nil || len(got) != 1 || got[0].Interface != "eth1" || got[0].Address != "10.10.20.10" || got[0].MAC != "6c:1f:f7:d2:5d:97" {
		t.Fatalf("identity = %#v, %v", got, err)
	}
	routeArgs, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(routeArgs)) != "-o -4 addr show up" {
		t.Fatalf("interface lookup = %q", routeArgs)
	}
}

func TestCollectionConfigRejectsUnknownAndMismatchedTargets(t *testing.T) {
	base := DefaultCollectionConfig()
	for _, target := range []Target{{Name: "attacker", Address: "10.10.10.60", Port: NodeExporterPort}, {Name: "lab-dns-01", Address: "10.10.10.60", Port: NodeExporterPort}, {Name: "lab-dns-01", Address: "10.10.10.10", Port: 80}} {
		config := CollectionConfig{Targets: []Target{target}, MetricsRetentionDays: MetricsRetentionDays, LogsRetentionDays: LogsRetentionDays}
		if err := config.Validate(); err == nil {
			t.Fatalf("unsafe collection target accepted: %#v", target)
		}
	}
	base.Targets = append(base.Targets, base.Targets[0])
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate collection target was not rejected: %v", err)
	}
}

func TestControllerCollectionAddressMatchesLocalMACToSERVERSReservation(t *testing.T) {
	previous := LocalControllerIdentityLookup
	defer func() { LocalControllerIdentityLookup = previous }()
	LocalControllerIdentityLookup = func() ([]ControllerIdentity, error) {
		return []ControllerIdentity{{Address: "10.10.20.10", MAC: "dc:a6:32:e9:dd:82"}}, nil
	}
	enabled := true
	config := controllerhost.LabConfig{Modules: clientservices.Modules{DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: "lab-companion", Zone: "SERVERS", MAC: "dc:a6:32:e9:dd:82", Address: "10.10.20.10"}}}}}
	address, err := ControllerCollectionAddress(config)
	if err != nil || address != "10.10.20.10" {
		t.Fatalf("matching Controller reservation rejected: address=%q err=%v", address, err)
	}
	config.Modules.DHCP.Reservations[0].Address = "10.10.20.11"
	if _, err := ControllerCollectionAddress(config); err == nil {
		t.Fatal("Controller address mismatch accepted")
	}
	config.Modules.DHCP.Reservations = nil
	if _, err := ControllerCollectionAddress(config); err == nil {
		t.Fatal("unreserved Controller interface accepted")
	}
}

func TestControllerCollectionAddressRejectsAmbiguousSERVERSInterfaces(t *testing.T) {
	previous := LocalControllerIdentityLookup
	defer func() { LocalControllerIdentityLookup = previous }()
	LocalControllerIdentityLookup = func() ([]ControllerIdentity, error) {
		return []ControllerIdentity{{Address: "10.10.20.10", MAC: "aa:aa:aa:aa:aa:01"}, {Address: "10.10.20.11", MAC: "aa:aa:aa:aa:aa:02"}}, nil
	}
	enabled := true
	config := controllerhost.LabConfig{Modules: clientservices.Modules{DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Zone: "SERVERS", MAC: "aa:aa:aa:aa:aa:01", Address: "10.10.20.10"}, {Zone: "SERVERS", MAC: "aa:aa:aa:aa:aa:02", Address: "10.10.20.11"}}}}}
	if _, err := ControllerCollectionAddress(config); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("ambiguous Controller interfaces accepted: %v", err)
	}
}

func TestCollectionConfigUsesOwnedSiteTargetsAndPinnedRetention(t *testing.T) {
	config := CollectionConfigFromSite(model.NewDefaultSite("test", "age1example"))
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(config.Targets) != 3 || config.MetricsRetentionDays != 30 || config.LogsRetentionDays != 7 {
		t.Fatalf("unexpected collection defaults: %#v", config)
	}
	scrape, err := config.VictoriaMetricsScrapeConfig("davebarton.cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"scrape_interval: 30s", "scheme: https", "insecure_skip_verify: false", "ca_file: '/etc/ssl/certs/ca-certificates.crt'", "basic_auth:", "password_file: '/run/credentials/victoriametrics.service/node-exporter-read-token'", "server_name: 'metrics.davebarton.cc'", "metrics.davebarton.cc:443", "metrics_path: '/lab-monitor-01/metrics'", "boetticher_host: 'lab-monitor-01'"} {
		if !strings.Contains(scrape, required) {
			t.Errorf("scrape config missing %q: %s", required, scrape)
		}
	}
	metrics, err := config.VictoriaMetricsRetentionFlag()
	if err != nil || metrics != "-retentionPeriod=30d" {
		t.Fatalf("metrics retention flag = %q, %v", metrics, err)
	}
	logs, err := config.VictoriaLogsRetentionFlag()
	if err != nil || logs != "-retentionPeriod=7d" {
		t.Fatalf("logs retention flag = %q, %v", logs, err)
	}
}

func TestCollectionConfigAcceptsIntentRetentionAndRejectsInvalidRange(t *testing.T) {
	config := DefaultCollectionConfig()
	config.LogsRetentionDays = 30
	if err := config.Validate(); err != nil {
		t.Fatalf("intent retention rejected: %v", err)
	}
	config.LogsRetentionDays = 3651
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("invalid retention accepted: %v", err)
	}
}

func TestObservedControllerIPUsesAuthenticatedConnectionThenLocalRoute(t *testing.T) {
	previous := LocalRouteLookup
	t.Cleanup(func() { LocalRouteLookup = previous })
	LocalRouteLookup = func() (string, error) { return "192.0.2.44", nil }
	t.Setenv("SSH_CONNECTION", "198.51.100.7 54321 192.0.2.44 22")
	got, err := ObservedControllerIP()
	if err != nil || got != "198.51.100.7" {
		t.Fatalf("authenticated Controller address = %q, %v", got, err)
	}
	if err := os.Unsetenv("SSH_CONNECTION"); err != nil {
		t.Fatal(err)
	}
	got, err = ObservedControllerIP()
	if err != nil || got != "192.0.2.44" {
		t.Fatalf("local route Controller address = %q, %v", got, err)
	}
}
