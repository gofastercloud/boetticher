package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

func TestProgressWriterStreamsOnlyBoundedOperatorLines(t *testing.T) {
	var output bytes.Buffer
	progress := make(chan string, 8)
	writer := &progressWriter{dst: &output, channel: progress}
	if _, err := writer.Write([]byte("verbose provider chatter\n[1/9] Validate desired state\n      Timing: ansible/all managed targets (42ms)\n")); err != nil {
		t.Fatalf("progressWriter.Write() error = %v", err)
	}
	writer.flush()
	close(progress)
	var got []string
	for line := range progress {
		got = append(got, line)
	}
	if !reflect.DeepEqual(got, []string{"[1/9] Validate desired state", "Timing: ansible/all managed targets (42ms)"}) {
		t.Fatalf("progress lines = %v", got)
	}
	if !strings.Contains(output.String(), "verbose provider chatter") {
		t.Fatalf("progress writer did not preserve command output: %q", output.String())
	}
}

func TestCommandPathStripsBinaryAndPlaceholders(t *testing.T) {
	if got := commandPath("boetticher firewall rule add [--source SOURCE]"); got != "firewall rule add" {
		t.Fatalf("commandPath() = %q", got)
	}
}

func TestCommandItemHighlightsNetworkTestAsLiveDiagnostic(t *testing.T) {
	item := commandItem{usage: "boetticher network test [--site DIR] [--zones ZONE,...]"}
	if got := item.Title(); got != "network test" {
		t.Fatalf("network test title = %q", got)
	}
	if got := item.Description(); !strings.Contains(got, "temporary probes") {
		t.Fatalf("network test description = %q", got)
	}
}

func TestSensitiveCommandsUseSecureHandoff(t *testing.T) {
	for _, args := range [][]string{
		{"module", "secrets", "set", "litellm"},
		{"module", "configure", "litellm", "--secret", "openrouter_api_key"},
	} {
		if !containsSensitiveInput(args) {
			t.Errorf("containsSensitiveInput(%q) = false", args)
		}
	}
	if containsSensitiveInput([]string{"module", "status", "litellm"}) {
		t.Fatal("read-only module status was treated as sensitive input")
	}
}

func TestRefreshUsesLiveStatusJSONAndPreservesCommandError(t *testing.T) {
	want := statusmodel.Report{
		StatusModelVersion: statusmodel.ModelVersion,
		ModelRevision:      "revision",
		ObservedAt:         "2026-08-30T00:00:00Z",
		OverallState:       statusmodel.Healthy,
	}
	var gotArgs []string
	m := modelState{options: Options{SiteDir: "/site", Runner: func(args []string, _ io.Reader, out, _ io.Writer) error {
		gotArgs = append([]string(nil), args...)
		data, _ := json.Marshal(want)
		_, _ = out.Write(data)
		return errors.New("status failed: review the named failure and its next action")
	}}}
	result := m.refresh()().(refreshResult)
	if !reflect.DeepEqual(result.report, want) || result.err == nil {
		t.Fatalf("refresh result = %#v", result)
	}
	if strings.Join(gotArgs, " ") != "status --site /site --live --json" {
		t.Fatalf("refresh args = %v", gotArgs)
	}
}

func TestDesiredReportUsesBinaryResultsWithoutLiveEvidence(t *testing.T) {
	report := desiredReport(model.Site{Modules: []model.ResolvedModule{
		{Name: "monitoring", Enabled: true},
		{Name: "printer", Enabled: false},
	}}, "revision")
	if report.OverallState != statusmodel.Failed {
		t.Fatalf("offline report overall state = %q, want %q", report.OverallState, statusmodel.Failed)
	}
	if got := report.Checks[1].Evidence; got != statusmodel.FAIL {
		t.Fatalf("enabled module evidence = %q, want FAIL", got)
	}
	if got := report.Checks[2].Evidence; got != statusmodel.PASS {
		t.Fatalf("disabled module evidence = %q, want PASS", got)
	}
	for _, check := range report.Checks {
		if strings.Contains(string(check.Evidence), "NOT TESTED") || strings.Contains(check.Reason, "NOT TESTED") {
			t.Fatalf("offline report exposed non-binary evidence: %#v", check)
		}
	}
}
