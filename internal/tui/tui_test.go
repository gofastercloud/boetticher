package tui

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/application"
	"github.com/gofastercloud/boetticher/internal/model"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

type fakeExecutor struct {
	request application.Request
	result  application.Result
	err     error
}

func (f *fakeExecutor) Execute(_ context.Context, request application.Request, _ func(application.Event)) (application.Result, error) {
	f.request = request
	return f.result, f.err
}

func TestCommandItemUsesTypedApplicationCommand(t *testing.T) {
	item := commandItem{command: application.Command{
		Name:        "network status",
		Description: "Inspect the physical trunk contract",
		Request:     application.Request{Operation: application.OperationNetworkStatus},
	}}
	if item.Title() != "network status" || item.FilterValue() != "network status" {
		t.Fatalf("typed command identity was not preserved: %#v", item)
	}
	if item.Description() != "Inspect the physical trunk contract" {
		t.Fatalf("typed command description was not preserved: %q", item.Description())
	}
}

func TestRefreshUsesTypedLiveStatusOperation(t *testing.T) {
	want := statusmodel.Report{
		StatusModelVersion: statusmodel.ModelVersion,
		ModelRevision:      "revision",
		ObservedAt:         "2026-08-30T00:00:00Z",
		OverallState:       statusmodel.Healthy,
	}
	executor := &fakeExecutor{result: application.Result{Operation: application.OperationStatus, Report: want, Output: "typed status"}, err: errors.New("status failed")}
	m := modelState{options: Options{SiteDir: "/site", Executor: executor}}
	result := m.refresh()().(refreshResult)
	if !reflect.DeepEqual(result.report, want) || result.err == nil {
		t.Fatalf("refresh result = %#v", result)
	}
	if executor.request.Operation != application.OperationStatus || !executor.request.Live || executor.request.SiteDir != "/site" {
		t.Fatalf("refresh request = %#v", executor.request)
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
		t.Fatalf("enabled module evidence = %q, want %q", got, statusmodel.FAIL)
	}
	if got := report.Checks[2].Evidence; got != statusmodel.PASS {
		t.Fatalf("disabled module evidence = %q, want %q", got, statusmodel.PASS)
	}
	for _, check := range report.Checks {
		if strings.Contains(string(check.Evidence), "NOT TESTED") || strings.Contains(check.Reason, "NOT TESTED") {
			t.Fatalf("offline report exposed non-binary evidence: %#v", check)
		}
	}
}
