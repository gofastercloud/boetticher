package observability

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

// TestServiceChecksScriptReportsEachServiceUnderItsOwnTimeout runs the exact
// guest script with fake systemctl/curl/timeout so the shell contract (one
// line per service, unit state, curl exit mapping, always exit zero) is
// exercised rather than only string-matched.
func TestServiceChecksScriptReportsEachServiceUnderItsOwnTimeout(t *testing.T) {
	bin := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// timeout must receive the per-check bound; it runs the wrapped command,
	// except that the gatus unit query simulates a hung systemctl.
	write("timeout", `[ "$1" = 5 ] || exit 99; shift; case "$*" in *gatus*) exit 124;; esac; exec "$@"`+"\n")
	write("systemctl", `case "$2" in grafana.service) echo failed; exit 3;; *) echo active;; esac`+"\n")
	write("curl", `case "$*" in *"--max-time 5"*) ;; *) exit 98;; esac; case "$*" in *4000*) exit 7;; *8428*) exit 28;; esac; exit 0`+"\n")
	services := []string{"victoriametrics.service", "grafana.service", "gatus.service", "bifrost.service", "caddy.service"}
	script, err := serviceChecksScript(services)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("script exited non-zero: %v", err)
	}
	results, err := parseServiceChecks(string(output), services)
	if err != nil {
		t.Fatalf("parse %q: %v", output, err)
	}
	want := []ServiceHealth{
		{"victoriametrics.service", "active", "no response within 5s"},
		{"grafana.service", "failed", ""},
		{"gatus.service", "check-timed-out", ""},
		{"bifrost.service", "active", "connection refused"},
		{"caddy.service", "active", "healthy"},
	}
	for index, result := range results {
		if result != want[index] {
			t.Fatalf("result %d = %+v, want %+v", index, result, want[index])
		}
	}
}

func TestServiceChecksRejectUnknownDuplicateAndMissingResults(t *testing.T) {
	if _, err := serviceChecksScript([]string{"sshd.service"}); err == nil {
		t.Fatal("unknown provider accepted")
	}
	if _, err := serviceChecksScript([]string{"gatus.service", "gatus.service"}); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	if _, err := parseServiceChecks(serviceCheckMarker+"\tgatus.service\tactive\thealthy\n", []string{"gatus.service", "caddy.service"}); err == nil || !strings.Contains(err.Error(), "no result for caddy.service") {
		t.Fatalf("missing result accepted: %v", err)
	}
	line := serviceCheckMarker + "\tgatus.service\tactive\thealthy\n"
	if _, err := parseServiceChecks(line+line, []string{"gatus.service"}); err == nil {
		t.Fatal("duplicate result accepted")
	}
}

type runtimeRunner struct {
	calls  []string
	config string
	state  string
}

func (r *runtimeRunner) Run(ctx context.Context, command string) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	switch {
	case strings.HasPrefix(command, "pct config "):
		return controllerhost.Result{Stdout: []byte(r.config)}, nil
	case strings.HasPrefix(command, "pct status "):
		return controllerhost.Result{Stdout: []byte(r.state)}, nil
	case strings.Contains(command, serviceCheckMarker):
		var out strings.Builder
		for _, service := range Services() {
			if strings.Contains(command, service) {
				out.WriteString(serviceCheckMarker + "\t" + service + "\tactive\thealthy\n")
			}
		}
		return controllerhost.Result{Stdout: []byte(out.String())}, nil
	}
	return controllerhost.Result{}, errors.New("unexpected command " + command)
}

func TestObserveRuntimeVerifiesOwnershipOnceAndBatchesServices(t *testing.T) {
	runner := &runtimeRunner{config: ownedGuestOutput(binding, "boetticher;managed;module-observability;boetticher-module-observability", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24"), state: "status: running\n"}
	client := HostClient{Transport: runner}
	observation, err := client.ObserveRuntime(context.Background(), binding, Services())
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 3 || len(observation.Services) != len(Services()) || !observation.Running {
		t.Fatalf("observation=%+v calls=%q", observation, runner.calls)
	}
	for _, service := range observation.Services {
		if !service.Healthy() {
			t.Fatalf("service not healthy: %+v", service)
		}
	}

	runner.calls = nil
	runner.state = "status: stopped\n"
	observation, err = client.ObserveRuntime(context.Background(), binding, Services())
	if err != nil || observation.Running || observation.Services != nil || len(runner.calls) != 2 {
		t.Fatalf("stopped guest: observation=%+v err=%v calls=%q", observation, err, runner.calls)
	}

	runner.calls = nil
	runner.config = ownedGuestOutput(binding, "boetticher;managed", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24")
	_, err = client.ObserveRuntime(context.Background(), binding, Services())
	var checkErr *CheckError
	if !errors.As(err, &checkErr) || !strings.Contains(checkErr.Check, "ownership") || len(runner.calls) != 1 {
		t.Fatalf("foreign guest: err=%v calls=%q", err, runner.calls)
	}
}

func TestObserveRuntimeNamesCheckOnDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	client := HostClient{Transport: deadlineRunner{}}
	_, err := client.ObserveRuntime(ctx, binding, Services())
	var checkErr *CheckError
	if !errors.As(err, &checkErr) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(checkErr.Check, "ownership") {
		t.Fatalf("deadline error = %v", err)
	}
}

type deadlineRunner struct{}

func (deadlineRunner) Run(ctx context.Context, _ string) (controllerhost.Result, error) {
	return controllerhost.Result{}, ctx.Err()
}
