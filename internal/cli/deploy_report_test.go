package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeploymentReportRendersSuccessfulBinarySummary(t *testing.T) {
	var output bytes.Buffer
	report := newDeploymentReport(&output)
	report.start("validate", "Validate desired state")
	report.complete()
	report.start("artifacts", "Resolve qualified artifacts")
	report.complete()
	report.finalize(nil)

	text := output.String()
	for _, want := range []string{"[1/9] Validate desired state", "PASS Validate desired state", "PASS Resolve qualified artifacts", "Infrastructure changed: NO", "Temporary authority: not established", "Deployment: PASS"} {
		if !strings.Contains(text, want) {
			t.Fatalf("deployment report omitted %q:\n%s", want, text)
		}
	}
	assertNoHumanEvidenceStates(t, text)
}

func TestDeploymentReportRendersFailureAfterCoarseMutation(t *testing.T) {
	var output bytes.Buffer
	report := newDeploymentReport(&output)
	report.start("validate", "Validate desired state")
	report.complete()
	report.start("appliances", "Reconcile appliance guests")
	report.recordMutation("Proxmox", "lab-aiops-01", "created", true)
	report.finalize(errors.New("HOLD: AIOps service entrypoint is missing"))

	text := output.String()
	for _, want := range []string{"PASS Validate desired state", "FAIL Reconcile appliance guests", "Changed: Proxmox: lab-aiops-01 created", "Component: aiops", "Reason: FAIL: AIOps service entrypoint is missing", "Infrastructure changed: YES", "Changes before failure:", "Proxmox: lab-aiops-01 created", "Deployment: FAIL", "Failed phase: Reconcile appliance guests", "Next action:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("deployment failure report omitted %q:\n%s", want, text)
		}
	}
	assertNoHumanEvidenceStates(t, text)
}

func TestDeploymentReportCleanupFailureWinsAfterForwardSuccess(t *testing.T) {
	var output bytes.Buffer
	report := newDeploymentReport(&output)
	report.start("persist", "Persist final state")
	report.complete()
	cleanupErr := errors.New("root access remains on lab-aiops-01")
	report.setCleanup(true, false, cleanupErr)
	report.finalize(combineDeploymentErrors(nil, cleanupErr))

	text := output.String()
	for _, want := range []string{"PASS Persist final state", "Temporary authority removed: NO", "Deployment: FAIL", "Failed phase: Temporary authority cleanup", "Retry: NO"} {
		if !strings.Contains(text, want) {
			t.Fatalf("cleanup failure report omitted %q:\n%s", want, text)
		}
	}
	assertNoHumanEvidenceStates(t, text)
}

func TestDeploymentReportPersistsTimingAndMutationSummary(t *testing.T) {
	var output bytes.Buffer
	report := newDeploymentReport(&output)
	report.setTimingPath(filepath.Join(t.TempDir(), "deploy", "timing.json"))
	report.start("proxmox", "Reconcile Proxmox platform and storage")
	report.recordMutation("Proxmox", "lab-fw-01", "guest created", true)
	report.recordTiming("ansible/lab-fw-01", time.Now().Add(-25*time.Millisecond))
	report.complete()
	report.finalize(nil)

	data, err := os.ReadFile(report.timingPath)
	if err != nil {
		t.Fatalf("read deployment timing report: %v", err)
	}
	var document struct {
		Succeeded             bool              `json:"succeeded"`
		InfrastructureChanged bool              `json:"infrastructure_changed"`
		MutationScopeCertain  bool              `json:"mutation_scope_certain"`
		Mutations             []json.RawMessage `json:"mutations"`
		Phases                []json.RawMessage `json:"phases"`
		Suboperations         []struct {
			Name       string `json:"name"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"suboperations"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode deployment timing report: %v", err)
	}
	if !document.Succeeded || !document.InfrastructureChanged || !document.MutationScopeCertain || len(document.Mutations) != 1 || len(document.Phases) != 1 || len(document.Suboperations) != 1 {
		t.Fatalf("unexpected deployment timing report: %+v", document)
	}
	if document.Suboperations[0].Name != "ansible/lab-fw-01" || document.Suboperations[0].DurationMS < 0 {
		t.Fatalf("unexpected deployment suboperation timing: %+v", document.Suboperations[0])
	}
	if strings.Contains(string(data), "failure") {
		t.Fatalf("deployment timing report should not contain failure details: %s", data)
	}
}

func assertNoHumanEvidenceStates(t *testing.T, text string) {
	t.Helper()
	for _, forbidden := range []string{"HOLD", "NOT TESTED", "NOT VERIFIED", "PARTIAL", "INCONCLUSIVE", "UNKNOWN"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("human deployment report contains forbidden result state %q:\n%s", forbidden, text)
		}
	}
}
