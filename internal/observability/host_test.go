package observability

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

type lifecycleRunner struct {
	calls      []string
	config     string
	configErr  error
	installErr error
}

func (r *lifecycleRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	if strings.Contains(command, "pct create 120") {
		r.configErr = nil
		r.config = ownedGuestOutput(binding, "boetticher;managed;module-observability;boetticher-module-observability", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24")
	}
	if strings.HasPrefix(command, "pct config ") {
		if r.configErr != nil {
			return controllerhost.Result{ExitCode: 1, Stderr: []byte(r.configErr.Error())}, r.configErr
		}
		return controllerhost.Result{Stdout: []byte(r.config)}, nil
	}
	if strings.Contains(command, "cat /etc/boetticher/observability/collection.yml") {
		return controllerhost.Result{Stdout: []byte("scrape_configs: []\n")}, nil
	}
	if strings.Contains(command, "cat '/etc/boetticher/gatus/config.yaml'") {
		return controllerhost.Result{Stdout: []byte("endpoints: []\n")}, nil
	}
	if strings.Contains(command, "systemctl is-active 'gatus.service'") {
		return controllerhost.Result{Stdout: []byte("active\n")}, nil
	}
	if strings.Contains(command, "install-observability-providers") && r.installErr != nil {
		err := r.installErr
		r.installErr = nil
		return controllerhost.Result{ExitCode: 1, Stderr: []byte(err.Error())}, err
	}
	return controllerhost.Result{}, nil
}

func (r *lifecycleRunner) RunWithStdin(ctx context.Context, command string, stdin io.Reader) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	_, _ = io.Copy(io.Discard, stdin)
	return controllerhost.Result{}, ctx.Err()
}

func payloadFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{"controller/proxmox/libexec/boetticher-build-observability-base", "controller/proxmox/libexec/build-temp.py", "controller/observability/base/debian.yaml", "controller/proxmox/libexec/boetticher-install-observability-providers", "controller/observability/assets/catalog.json", "controller/observability/assets/victorialogs.service", "controller/observability/assets/victoriametrics.service", "controller/observability/assets/grafana.service", "controller/observability/assets/gatus.service", "controller/observability/assets/caddy.service", "controller/observability/assets/gatus.config.yaml", "controller/observability/assets/bifrost.service", "controller/observability/assets/grafana-datasource.yaml", "controller/observability/assets/grafana-dashboard.yaml", "controller/observability/assets/grafana-overview.json", "controller/observability/assets/grafana-host-resources.json", "controller/observability/assets/grafana-service-logs.json", "controller/observability/assets/grafana-observability-health.json", "controller/observability/assets/grafana-alerting.yaml", "controller/observability/bin/bifrost", "controller/observability/bin/gatus", "controller/observability/bin/caddy", "controller/observability/holmes/holmes-runner.py", "controller/observability/holmes/holmes.yaml", "controller/observability/holmes/requirements.lock"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func observabilityTestModules() clientservices.Modules {
	enabled := true
	return clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, Monitoring: clientservices.MonitoringConfig{Holmes: &clientservices.HolmesConfig{Enabled: &enabled, ModelAlias: "operations", Bifrost: clientservices.BifrostConfig{ClientCredential: "holmes-client-token", Upstreams: []clientservices.BifrostUpstream{{Name: "provider", BaseURL: "https://provider.example", SecretRef: "provider-key"}}, Models: []clientservices.BifrostModel{{Alias: "operations", Upstream: "provider", Model: "model"}}}}}}}
}

func observabilityTestSecrets() map[string][]byte {
	return map[string][]byte{"grafana-admin-password": []byte("test-grafana-password"), "statuspage-password": []byte("test-status-password"), "holmes-client-token": []byte("test-client-token"), "provider-key": []byte("test-provider-key")}
}

type fakeRunner struct {
	calls   []string
	outputs map[string]string
}

func (f *fakeRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	f.calls = append(f.calls, command)
	return controllerhost.Result{Stdout: []byte(f.outputs[command])}, nil
}

func ownedGuestOutput(b Binding, tags, network string) string {
	return "hostname: " + b.Hostname + "\ntags: " + tags + "\nnet0: " + network + "\n"
}

func TestGuestConfigRequiresExactLegacyOwnershipAndNetwork(t *testing.T) {
	b, _ := BindingFor("observability")
	f := &fakeRunner{outputs: map[string]string{"pct config 120": ownedGuestOutput(b, "boetticher;managed;module-observability;boetticher-module-observability;backup", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24")}}
	if _, err := (HostClient{Transport: f}).GuestConfig(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	f.outputs["pct config 120"] = ownedGuestOutput(b, "boetticher;managed;module-observability;boetticher-module-observability;backup", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.21/24")
	if _, err := (HostClient{Transport: f}).GuestConfig(context.Background(), b); err == nil || !strings.Contains(err.Error(), "network identity") {
		t.Fatalf("expected exact network rejection, got %v", err)
	}
	f.outputs["pct config 120"] = ownedGuestOutput(b, "boetticher;managed;module-observability;boetticher-module-observability;backup", "name=eth0,bridge=vmbr1,tag=20,ip=10.10.10.20/24")
	if _, err := (HostClient{Transport: f}).GuestConfig(context.Background(), b); err == nil || !strings.Contains(err.Error(), "network identity") {
		t.Fatalf("expected VLAN rejection, got %v", err)
	}
}

func TestLifecycleSpecsKeepProviderOwnershipAndRetainedData(t *testing.T) {
	got, ok := BindingFor("observability")
	if !ok || got.VMID != 120 || got.VLAN != 10 || got.MemoryMiB != 4096 || len(got.Volumes) != 3 || got.Volumes[0].SizeGiB != 24 || got.Volumes[1].SizeGiB != 24 || got.Volumes[2].SizeGiB != 4 {
		t.Fatalf("observability binding=%+v", got)
	}
}

func TestReconcileCreatesOwnedGuestAndRetriesWithoutRecreating(t *testing.T) {
	b, _ := BindingFor("observability")
	payload := payloadFixture(t)
	runner := &lifecycleRunner{configErr: errors.New("guest does not exist")}
	client := HostClient{Transport: runner}
	if err := client.ReconcileGuest(context.Background(), b, payload, observabilityTestModules(), observabilityTestSecrets(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if !containsCall(runner.calls, "pct create 120") || !containsCall(runner.calls, "pct push 120") || !containsCall(runner.calls, "pct exec 120 -- sh -c '") {
		t.Fatalf("create reconciliation calls=%v", runner.calls)
	}
	if containsCall(runner.calls, "install -d -m 0700 /tmp") || !containsCall(runner.calls, "/tmp/boetticher-observability-120-base-stage") || !containsCall(runner.calls, "chmod 0700 '/tmp/boetticher-observability-120-base-stage/build-base'") {
		t.Fatalf("base staging changed the shared /tmp parent or omitted the private staging directory: %v", runner.calls)
	}
	if !containsCall(runner.calls, "sha256sum \"$base\"") || !containsCall(runner.calls, "meta=$base.inputs") {
		t.Fatalf("base cache checksum/input binding missing: %v", runner.calls)
	}
	if !containsCall(runner.calls, "rm -rf -- '/tmp/boetticher-observability-120-base-stage'") {
		t.Fatalf("owned base staging directory was not cleaned: %v", runner.calls)
	}
	for _, mount := range []string{"--mp0 boetticher-data:24", "--mp1 boetticher-data:24", "--mp2 boetticher-data:4"} {
		if !containsCall(runner.calls, mount) {
			t.Fatalf("shared runtime omitted %s: %v", mount, runner.calls)
		}
	}
	if countCallContains(runner.calls, "sh /root/boetticher-install-observability-providers") != 6 {
		t.Fatalf("atomic reconciliation did not select all providers: %v", runner.calls)
	}
	if countCallContains(runner.calls, "pct exec 120 -- chmod 0755") != 3 {
		t.Fatalf("provider binaries were not made executable after push: %v", runner.calls)
	}
	if !containsCall(runner.calls, "install -d -o root -g root -m 0755 /var/lib/boetticher/observability") || !containsCall(runner.calls, "chmod 0600 /var/lib/boetticher/observability/boetticher-config.digest") {
		t.Fatalf("shared observability state parent or digest permissions are unsafe: %v", runner.calls)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "pct exec 120 -- set -eu") {
			t.Fatalf("guest shell script was exposed to Host shell: %s", call)
		}
		if strings.Contains(call, "pct push 120") && strings.Contains(call, payload) {
			t.Fatalf("Controller path was passed directly to Host pct push: %s", call)
		}
		if strings.Contains(call, "test-client-token") || strings.Contains(call, "test-provider-key") {
			t.Fatalf("secret leaked into Host command: %s", call)
		}
	}
	createCount := countCallPrefix(runner.calls, "set -eu; test -n")
	runner.configErr = nil
	runner.config = ownedGuestOutput(b, "boetticher;managed;module-observability;boetticher-module-observability", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24")
	if err := client.ReconcileGuest(context.Background(), b, payload, observabilityTestModules(), observabilityTestSecrets(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if countCallPrefix(runner.calls, "set -eu; test -n") != createCount {
		t.Fatalf("owned repeat attempted another guest create: %v", runner.calls)
	}
}

func TestReconcileChecksBasePayloadBeforeHostMutation(t *testing.T) {
	b, _ := BindingFor("observability")
	payload := payloadFixture(t)
	if err := os.Remove(filepath.Join(payload, "controller", "observability", "base", "debian.yaml")); err != nil {
		t.Fatal(err)
	}
	runner := &lifecycleRunner{configErr: errors.New("guest does not exist")}
	err := (HostClient{Transport: runner}).ReconcileGuest(context.Background(), b, payload, observabilityTestModules(), observabilityTestSecrets(), strings.Repeat("a", 64))
	if err == nil || !strings.Contains(err.Error(), "base definition") {
		t.Fatalf("missing base definition was not rejected: %v", err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "install -d") || strings.Contains(call, "pct create") || strings.Contains(call, "pct push") {
			t.Fatalf("missing base definition caused Host mutation: %s", call)
		}
	}
}

func TestBaseStageRejectsUnsafePathsAndBindsBothInputs(t *testing.T) {
	for _, path := range []string{"/tmp", "/var/tmp/boetticher", "/tmp/boetticher-observability-120/../foreign", "/tmp/boetticher-observability-120-'foreign"} {
		if err := validateHostStageRoot(path); err == nil {
			t.Fatalf("unsafe Host staging path accepted: %s", path)
		}
	}
	first := baseImageInputDigest([]byte("helper-a"), []byte("definition-a"))
	if first == baseImageInputDigest([]byte("helper-b"), []byte("definition-a")) || first == baseImageInputDigest([]byte("helper-a"), []byte("definition-b")) {
		t.Fatal("base cache input digest does not bind both helper and definition")
	}
	command := prepareHostStageCommand("/tmp/boetticher-observability-120-base-stage")
	if strings.Contains(command, "install -d -m 0700 /tmp;") || !strings.Contains(command, ".boetticher-owned") || !strings.Contains(command, "stat -c") {
		t.Fatalf("Host stage preparation does not protect shared parent or foreign directory: %s", command)
	}
}

func TestReconcileRefusesForeignGuestAndRetriesFailedProviderInstall(t *testing.T) {
	b, _ := BindingFor("observability")
	payload := payloadFixture(t)
	foreign := &lifecycleRunner{config: ownedGuestOutput(b, "unrelated;managed", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24")}
	if err := (HostClient{Transport: foreign}).ReconcileGuest(context.Background(), b, payload, observabilityTestModules(), observabilityTestSecrets(), strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("foreign guest was accepted: %v calls=%v", err, foreign.calls)
	}
	runner := &lifecycleRunner{config: ownedGuestOutput(b, "boetticher;managed;module-observability;boetticher-module-observability", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24"), installErr: errors.New("provider installer failed")}
	client := HostClient{Transport: runner}
	if err := client.ReconcileGuest(context.Background(), b, payload, observabilityTestModules(), observabilityTestSecrets(), strings.Repeat("a", 64)); err == nil {
		t.Fatal("failed provider installation was reported as successful")
	}
	if err := client.ReconcileGuest(context.Background(), b, payload, observabilityTestModules(), observabilityTestSecrets(), strings.Repeat("a", 64)); err != nil {
		t.Fatalf("retry after provider failure failed: %v", err)
	}
	runner = &lifecycleRunner{config: runner.config}
	client = HostClient{Transport: runner}
	if err := client.ReconcileGuest(context.Background(), b, payload, observabilityTestModules(), observabilityTestSecrets(), strings.Repeat("a", 64)); err != nil {
		t.Fatalf("monitoring Bifrost reconciliation failed: %v", err)
	}
	if !containsCall(runner.calls, "bifrost") {
		t.Fatalf("monitoring reconciliation omitted Bifrost: %v", runner.calls)
	}
}

func TestTeardownStopsOwnedGuestAndRetainsDataMount(t *testing.T) {
	b, _ := BindingFor("observability")
	runner := &lifecycleRunner{config: ownedGuestOutput(b, "boetticher;managed;module-observability;boetticher-module-observability", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24")}
	if err := (HostClient{Transport: runner, LocalRunner: runner}).TeardownGuest(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if !containsCall(runner.calls, "pct exec 120 -- systemctl disable --now") || !containsCall(runner.calls, "pct set 120 --onboot 0") {
		t.Fatalf("teardown calls=%v", runner.calls)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "--purge") {
			t.Fatalf("teardown would purge retained data: %s", call)
		}
	}
}

func containsCall(calls []string, fragment string) bool {
	for _, call := range calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

func TestServicesForModulesIncludesCaddyAndOnlyConfiguredBifrost(t *testing.T) {
	base := ServicesForModules(clientservices.Modules{})
	if containsService(base, "bifrost.service") || !containsService(base, "caddy.service") {
		t.Fatalf("unconfigured service set = %#v", base)
	}
	enabled := true
	modules := clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, Monitoring: clientservices.MonitoringConfig{Holmes: &clientservices.HolmesConfig{Enabled: &enabled}}}}
	configured := ServicesForModules(modules)
	if !containsService(configured, "bifrost.service") || !containsService(configured, "caddy.service") {
		t.Fatalf("configured service set = %#v", configured)
	}
}

func containsService(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func countCallPrefix(calls []string, prefix string) int {
	count := 0
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}

func countCallContains(calls []string, fragment string) int {
	count := 0
	for _, call := range calls {
		if strings.Contains(call, fragment) {
			count++
		}
	}
	return count
}
