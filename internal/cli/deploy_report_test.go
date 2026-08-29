package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
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
	for _, want := range []string{"PASS Validate desired state", "FAIL Reconcile appliance guests", "Component: aiops", "Reason: FAIL: AIOps service entrypoint is missing", "Infrastructure changed: YES", "Changes before failure:", "Proxmox: lab-aiops-01 created", "Deployment: FAIL", "Failed phase: Reconcile appliance guests", "Next action:"} {
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

func assertNoHumanEvidenceStates(t *testing.T, text string) {
	t.Helper()
	for _, forbidden := range []string{"HOLD", "NOT TESTED", "NOT VERIFIED", "PARTIAL", "INCONCLUSIVE", "UNKNOWN"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("human deployment report contains forbidden result state %q:\n%s", forbidden, text)
		}
	}
}
