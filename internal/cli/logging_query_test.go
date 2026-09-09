package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
)

type loggingQueryTestRunner struct {
	calls       []string
	guestConfig string
	queryOutput []byte
	queryErr    error
}

func (r *loggingQueryTestRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	if strings.HasPrefix(command, "pct config ") {
		return controllerhost.Result{Stdout: []byte(r.guestConfig)}, nil
	}
	if strings.Contains(command, "/select/logsql/query") {
		if r.queryErr != nil {
			return controllerhost.Result{}, r.queryErr
		}
		return controllerhost.Result{Stdout: r.queryOutput}, nil
	}
	return controllerhost.Result{}, nil
}

func ownedLoggingQueryGuestConfig() string {
	return "hostname: lab-monitor-01\ntags: boetticher;managed;module-observability;boetticher-module-observability\nnet0: name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24\n"
}

func withLoggingQueryTestHooks(t *testing.T, runner *loggingQueryTestRunner) {
	t.Helper()
	oldLoad, oldTransport := loadLabConfig, loggingQueryTransport
	loadLabConfig = func() (controllerhost.LabConfig, error) {
		return controllerhost.LabConfig{Name: "test", Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}}, nil
	}
	loggingQueryTransport = func(controllerhost.LabConfig) (observability.Runner, error) { return runner, nil }
	t.Cleanup(func() {
		loadLabConfig, loggingQueryTransport = oldLoad, oldTransport
	})
}

func TestLoggingQueryCallsOwnedRuntimeAndRendersJSONL(t *testing.T) {
	runner := &loggingQueryTestRunner{
		guestConfig: ownedLoggingQueryGuestConfig(),
		queryOutput: []byte(`{"_time":"2026-09-08T01:02:03Z","level":"warning","host":"lab-dns-01","unit":"blocky.service","_msg":"resolver warning"}` + "\n"),
	}
	withLoggingQueryTestHooks(t, runner)
	var output bytes.Buffer
	err := runModuleWithInput([]string{"logging", "query", "--host", "lab-dns-01", "--unit", "blocky.service", "--level", "warning", "--since", "2h", "--limit", "20"}, nil, &output, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || !strings.HasPrefix(runner.calls[0], "pct config 120") || !strings.Contains(runner.calls[1], "pct exec 120 -- sh -c ") {
		t.Fatalf("query did not verify and execute in owned VM 120: %#v", runner.calls)
	}
	if !strings.Contains(output.String(), "2026-09-08T01:02:03Z\twarning\tlab-dns-01\tblocky.service\tresolver warning") {
		t.Fatalf("unexpected concise log output: %q", output.String())
	}
	if !strings.Contains(runner.calls[1], "127.0.0.1:9428/select/logsql/query") {
		t.Fatalf("query did not use fixed VictoriaLogs endpoint: %s", runner.calls[1])
	}

	queryURL := queryURLFromGuestCommand(t, runner.calls[1])
	values, err := url.ParseQuery(queryURL)
	if err != nil {
		t.Fatal(err)
	}
	if values.Get("limit") != "20" || !strings.Contains(values.Get("query"), `host="lab-dns-01"`) || !strings.Contains(values.Get("query"), `_time:2h`) {
		t.Fatalf("unexpected encoded LogsQL request: %#v", values)
	}
}

func TestLoggingQueryEscapesValuesIntoLogsQLWithoutShellInjection(t *testing.T) {
	runner := &loggingQueryTestRunner{guestConfig: ownedLoggingQueryGuestConfig(), queryOutput: []byte{}}
	withLoggingQueryTestHooks(t, runner)
	var output bytes.Buffer
	value := `host" | delete "; touch /tmp/pwned`
	if err := runModuleWithInput([]string{"logging", "query", "--host", value}, nil, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("escaped query did not execute exactly once after ownership check: %#v", runner.calls)
	}
	command := runner.calls[1]
	if strings.Contains(command, "; touch /tmp/pwned") || strings.Contains(command, " | delete ") {
		t.Fatalf("unencoded injection reached guest shell: %s", command)
	}
	queryValues, err := url.ParseQuery(queryURLFromGuestCommand(t, command))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(queryValues.Get("query"), `host="host\" | delete \"; touch /tmp/pwned`) {
		t.Fatalf("host value was not retained as an escaped LogsQL literal: %q", queryValues.Get("query"))
	}
}

func TestLoggingQueryRejectsInvalidArgumentsBeforeAnyIO(t *testing.T) {
	oldLoad, oldTransport := loadLabConfig, loggingQueryTransport
	t.Cleanup(func() { loadLabConfig, loggingQueryTransport = oldLoad, oldTransport })
	loadLabConfig = func() (controllerhost.LabConfig, error) {
		t.Fatal("invalid query loaded configuration")
		return controllerhost.LabConfig{}, nil
	}
	loggingQueryTransport = func(controllerhost.LabConfig) (observability.Runner, error) {
		t.Fatal("invalid query created transport")
		return nil, nil
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"limit low", []string{"--limit", "0"}},
		{"limit high", []string{"--limit", "501"}},
		{"since invalid", []string{"--since", "never"}},
		{"since too long", []string{"--since", "169h"}},
		{"positional", []string{"unexpected"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runLoggingQuery(test.args, io.Discard, io.Discard); err == nil {
				t.Fatal("invalid query was accepted")
			}
		})
	}
}

func TestLoggingQueryRefusesForeignRuntimeBeforeQuery(t *testing.T) {
	runner := &loggingQueryTestRunner{guestConfig: "hostname: foreign\ntags: unrelated\nnet0: name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.99/24\n"}
	withLoggingQueryTestHooks(t, runner)
	if err := runLoggingQuery(nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("foreign runtime was not refused: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("foreign runtime reached query: %#v", runner.calls)
	}
}

func TestLoggingQueryPropagatesHTTPFailure(t *testing.T) {
	runner := &loggingQueryTestRunner{guestConfig: ownedLoggingQueryGuestConfig(), queryErr: errors.New("curl: (22) HTTP 503")}
	withLoggingQueryTestHooks(t, runner)
	err := runLoggingQuery(nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("HTTP failure was not returned: %v", err)
	}
}

func TestLoggingQueryJSONLParsingAndOutputTruncation(t *testing.T) {
	entries, err := parseLoggingQueryJSONL([]byte(`{"time":"2026-09-08T00:00:00Z","severity":"info","hostname":"lab-dns-01","_SYSTEMD_UNIT":"blocky.service","message":"ok"}` + "\n"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("JSONL parse failed: %v %#v", err, entries)
	}
	if entries[0].timestamp != "2026-09-08T00:00:00Z" || entries[0].severity != "info" || entries[0].host != "lab-dns-01" || entries[0].unit != "blocky.service" || entries[0].message != "ok" {
		t.Fatalf("fields were not preserved: %#v", entries[0])
	}
	entries = []loggingQueryEntry{{timestamp: "t", severity: "info", host: "h", unit: "u", message: strings.Repeat("x", maxLoggingQueryOutputBytes)}}
	var output bytes.Buffer
	renderLoggingQuery(&output, entries)
	if output.Len() > maxLoggingQueryOutputBytes || !strings.Contains(output.String(), "[output truncated]") {
		t.Fatalf("rendered output was not bounded/truncated: %d", output.Len())
	}
	if _, err := parseLoggingQueryJSONL([]byte(`{"message":`)); err == nil {
		t.Fatal("malformed JSONL was accepted")
	}
}

func queryURLFromGuestCommand(t *testing.T, command string) string {
	t.Helper()
	marker := "http://127.0.0.1:9428/select/logsql/query?"
	start := strings.Index(command, marker)
	if start < 0 {
		t.Fatalf("fixed query URL missing from command: %s", command)
	}
	value := command[start+len(marker):]
	if end := strings.IndexByte(value, '\''); end >= 0 {
		value = value[:end]
	}
	return value
}
