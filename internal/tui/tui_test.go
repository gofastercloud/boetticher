package tui

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

func TestCommandPathStripsBinaryAndPlaceholders(t *testing.T) {
	if got := commandPath("boetticher firewall rule add [--source SOURCE]"); got != "firewall rule add" {
		t.Fatalf("commandPath() = %q", got)
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
