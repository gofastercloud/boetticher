package observability

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"gopkg.in/yaml.v3"
)

func monitoredSystem() clientservices.System {
	return clientservices.System{Name: "print", Kind: "lxc", GuestName: "print-01", VMID: 301, Address: "10.10.20.50", Port: 631, Monitoring: true}
}

func TestRenderGatusConfigProjectsAndRemovesOnlyOwnedSystems(t *testing.T) {
	base := []byte("endpoints:\n  - name: built-in\n    url: http://127.0.0.1:8080/health\n    interval: 30s\n    conditions: [\"[STATUS] == 200\"]\n  - name: foreign\n    group: boetticher-operator-systems\n    url: tcp://10.10.20.60:22\n")
	out, err := RenderGatusConfig(base, []clientservices.System{monitoredSystem()})
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, required := range []string{"boetticher-system-print", "tcp://10.10.20.50:631", "foreign"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %q: %s", required, text)
		}
	}
	out, err = RenderGatusConfig(out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "boetticher-system-print") || !strings.Contains(string(out), "foreign") {
		t.Fatalf("owned removal did not preserve foreign endpoint: %s", out)
	}
}

func TestMediaGatusEndpointsUsePinnedHealthPathsAndInternalListener(t *testing.T) {
	m := clientservices.Modules{Media: &clientservices.MediaConfig{Enabled: true, ApplicationDomain: "media.example.test", Aliases: clientservices.MediaAliases{Radarr: "radarr", Sonarr: "sonarr", Bazarr: "bazarr", Prowlarr: "prowlarr", Trailarr: "trailarr"}}}
	endpoints, err := MediaGatusEndpoints(m)
	if err != nil || len(endpoints) != 11 {
		t.Fatalf("media endpoints = %d, err=%v", len(endpoints), err)
	}
	for _, endpoint := range endpoints {
		if endpoint["method"] != "GET" || endpoint["url"].(string)[:len("http://10.10.20.230:9110")] != "http://10.10.20.230:9110" {
			t.Fatalf("unsafe media endpoint: %#v", endpoint)
		}
		headers := endpoint["headers"].(map[string]string)
		if headers["Cookie"] != "" || headers["Authorization"] != "" {
			t.Fatalf("media endpoint forwards credentials: %#v", headers)
		}
	}
}

func TestMediaGatusEndpointsRejectIncompleteAliases(t *testing.T) {
	_, err := MediaGatusEndpoints(clientservices.Modules{Media: &clientservices.MediaConfig{Enabled: true, ApplicationDomain: "media.example.test", Aliases: clientservices.MediaAliases{Radarr: "radarr"}}})
	if err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("incomplete media aliases accepted: %v", err)
	}
}

func TestGatusSystemsMatchCountsMediaProjection(t *testing.T) {
	modules := clientservices.Modules{Media: &clientservices.MediaConfig{Enabled: true, ApplicationDomain: "media.example.test", Aliases: clientservices.MediaAliases{Radarr: "radarr", Sonarr: "sonarr", Bazarr: "bazarr", Prowlarr: "prowlarr", Trailarr: "trailarr"}}}
	config, err := RenderGatusConfig([]byte("endpoints: []\n"), nil, modules)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := gatusSystemsMatch(config, nil, modules)
	if err != nil || !matched {
		t.Fatalf("complete media projection was not matched: matched=%v err=%v", matched, err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(config, &parsed); err != nil {
		t.Fatal(err)
	}
	endpoints := parsed["endpoints"].([]interface{})
	parsed["endpoints"] = endpoints[:len(endpoints)-1]
	short, err := yaml.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	matched, err = gatusSystemsMatch(short, nil, modules)
	if err != nil || matched {
		t.Fatalf("incomplete media projection was accepted: matched=%v err=%v", matched, err)
	}
}

func TestRenderGatusConfigRefusesReservedNameCollision(t *testing.T) {
	base := []byte("endpoints:\n  - name: boetticher-system-print\n    group: foreign\n    url: tcp://10.10.20.50:631\n")
	if _, err := RenderGatusConfig(base, []clientservices.System{monitoredSystem()}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved identity collision was accepted: %v", err)
	}
}

func TestRenderGatusConfigRejectsInvalidSystemBeforeOutput(t *testing.T) {
	_, err := RenderGatusConfig([]byte("endpoints: []\n"), []clientservices.System{{Name: "bad", Kind: "lxc", GuestName: "bad", VMID: 301, Address: "10.0.0.2", Port: 0, Monitoring: true}})
	if err == nil {
		t.Fatal("expected invalid system refusal")
	}
}

type systemsRunner struct {
	config                 string
	calls                  []string
	stdinCalls             int
	writeErr               error
	failReadbackAfterWrite bool
	catCalls               int
	serviceStatus          string
}

func (r *systemsRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	switch {
	case strings.HasPrefix(command, "pct config 120"):
		return controllerhost.Result{Stdout: []byte(ownedGuestOutput(binding, "boetticher;managed;module-observability;boetticher-module-observability", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24"))}, nil
	case strings.Contains(command, "cat '/etc/boetticher/gatus/config.yaml'"):
		r.catCalls++
		if r.failReadbackAfterWrite && r.stdinCalls != 0 && r.catCalls > 1 {
			return controllerhost.Result{}, errors.New("readback unavailable")
		}
		return controllerhost.Result{Stdout: []byte(r.config)}, nil
	case strings.Contains(command, "systemctl is-active 'gatus.service'"):
		status := r.serviceStatus
		if status == "" {
			status = "active"
		}
		return controllerhost.Result{Stdout: []byte(status + "\n")}, nil
	case strings.Contains(command, "curl --fail"):
		return controllerhost.Result{}, nil
	}
	return controllerhost.Result{}, nil
}

func (r *systemsRunner) RunWithStdin(_ context.Context, command string, stdin io.Reader) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	r.stdinCalls++
	payload, _ := io.ReadAll(stdin)
	if r.writeErr != nil {
		return controllerhost.Result{Stderr: []byte("provider diagnostic")}, r.writeErr
	}
	r.config = string(payload)
	r.serviceStatus = "active"
	return controllerhost.Result{}, nil
}

func TestReconcileGatusUsesAtomicOwnedReplacementAndReadback(t *testing.T) {
	runner := &systemsRunner{config: "endpoints: []\n"}
	client := HostClient{Transport: runner}
	if err := client.ReconcileGatus(context.Background(), []byte(runner.config), []clientservices.System{monitoredSystem()}); err != nil {
		t.Fatal(err)
	}
	if runner.stdinCalls != 1 || !strings.Contains(runner.config, "boetticher-system-print") {
		t.Fatalf("projection was not installed: writes=%d config=%s", runner.stdinCalls, runner.config)
	}
	command := strings.Join(runner.calls, "\n")
	for _, required := range []string{"test ! -L", "mktemp \"$dir/.config.yaml.new", "chown root:gatus", "chmod 0640", "mv -f \"$tmp\" \"$target\"", "mv -f \"$old\" \"$target\"", "systemctl reload-or-restart gatus.service", "curl --fail"} {
		if !strings.Contains(command, required) {
			t.Errorf("atomic replacement omitted %q: %s", required, command)
		}
	}
	if strings.Contains(command, "install -o root -g root -m 0640 /dev/stdin") {
		t.Fatalf("unsafe direct install remained: %s", command)
	}
}

func TestReconcileGatusNoOpRequiresHealthyExactRuntime(t *testing.T) {
	base, err := RenderGatusConfig([]byte("endpoints: []\n"), []clientservices.System{monitoredSystem()})
	if err != nil {
		t.Fatal(err)
	}
	runner := &systemsRunner{config: string(base)}
	if err := (HostClient{Transport: runner}).ReconcileGatus(context.Background(), base, []clientservices.System{monitoredSystem()}); err != nil {
		t.Fatal(err)
	}
	if runner.stdinCalls != 0 {
		t.Fatalf("healthy exact projection was rewritten %d times", runner.stdinCalls)
	}
}

func TestReconcileGatusReplacesAnUnhealthyExactRuntime(t *testing.T) {
	base, err := RenderGatusConfig([]byte("endpoints: []\n"), []clientservices.System{monitoredSystem()})
	if err != nil {
		t.Fatal(err)
	}
	runner := &systemsRunner{config: string(base), serviceStatus: "inactive"}
	if err := (HostClient{Transport: runner}).ReconcileGatus(context.Background(), base, []clientservices.System{monitoredSystem()}); err != nil {
		t.Fatal(err)
	}
	if runner.stdinCalls != 1 {
		t.Fatalf("unhealthy Gatus runtime incorrectly satisfied no-op gate")
	}
}

func TestReconcileGatusFailsWithoutReplacingOnNativeReloadFailure(t *testing.T) {
	base := "endpoints: []\n"
	runner := &systemsRunner{config: base, writeErr: errors.New("reload failed")}
	err := (HostClient{Transport: runner}).ReconcileGatus(context.Background(), []byte(base), []clientservices.System{monitoredSystem()})
	if err == nil || !strings.Contains(err.Error(), "replacement") {
		t.Fatalf("reload failure was not reported safely: %v", err)
	}
	if runner.config != base {
		t.Fatalf("failed replacement changed retained config: %q", runner.config)
	}
}

func TestReconcileGatusFailsWhenReadbackCannotVerifyPersistence(t *testing.T) {
	runner := &systemsRunner{config: "endpoints: []\n", failReadbackAfterWrite: true}
	err := (HostClient{Transport: runner}).ReconcileGatus(context.Background(), []byte(runner.config), []clientservices.System{monitoredSystem()})
	if err == nil || !strings.Contains(err.Error(), "read back") {
		t.Fatalf("readback failure was accepted: %v", err)
	}
}
