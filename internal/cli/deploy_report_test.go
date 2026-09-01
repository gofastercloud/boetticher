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

	"github.com/gofastercloud/boetticher/internal/ansible"
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
	report.setIdentity("0.4.1", "sha256:model")
	report.setTimingPath(filepath.Join(t.TempDir(), "deploy", "timing.json"))
	report.start("proxmox", "Reconcile Proxmox platform and storage")
	report.recordMutation("Proxmox", "lab-fw-01", "guest created", true)
	report.recordTiming("proxmox", "ansible", "lab-fw-01", time.Now().Add(-25*time.Millisecond))
	report.recordAnsibleTaskTimings("proxmox", []ansible.TaskTiming{{Host: "lab-fw-01", Task: "Apply config", Path: "roles/base/tasks/main.yml:12", Status: "ok", DurationMS: 17, Changed: true}})
	report.recordAnsibleTaskBatches("proxmox", []ansible.TaskBatchTiming{{Task: "Apply config", Path: "roles/base/tasks/main.yml:12", DurationMS: 21}})
	report.complete()
	report.finalize(nil)

	data, err := os.ReadFile(report.timingPath)
	if err != nil {
		t.Fatalf("read deployment timing report: %v", err)
	}
	var document struct {
		Operation             string            `json:"operation"`
		PlatformVersion       string            `json:"platform_version"`
		ModelRevision         string            `json:"model_revision"`
		Succeeded             bool              `json:"succeeded"`
		InfrastructureChanged bool              `json:"infrastructure_changed"`
		MutationScopeCertain  bool              `json:"mutation_scope_certain"`
		Mutations             []json.RawMessage `json:"mutations"`
		Phases                []json.RawMessage `json:"phases"`
		Suboperations         []struct {
			Phase      string `json:"phase"`
			Kind       string `json:"kind"`
			Target     string `json:"target"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"suboperations"`
		AnsibleTaskTimings []struct {
			Phase      string `json:"phase"`
			Host       string `json:"host"`
			Task       string `json:"task"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"ansible_task_timings"`
		AnsibleTaskBatches []struct {
			Phase      string `json:"phase"`
			Task       string `json:"task"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"ansible_task_batches"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode deployment timing report: %v", err)
	}
	if document.Operation != "deploy" || document.PlatformVersion != "0.4.1" || document.ModelRevision != "sha256:model" || !document.Succeeded || !document.InfrastructureChanged || !document.MutationScopeCertain || len(document.Mutations) != 1 || len(document.Phases) != 1 || len(document.Suboperations) != 1 || len(document.AnsibleTaskTimings) != 1 || len(document.AnsibleTaskBatches) != 1 {
		t.Fatalf("unexpected deployment timing report: %+v", document)
	}
	if document.Suboperations[0].Phase != "proxmox" || document.Suboperations[0].Kind != "ansible" || document.Suboperations[0].Target != "lab-fw-01" || document.Suboperations[0].DurationMS < 0 {
		t.Fatalf("unexpected deployment suboperation timing: %+v", document.Suboperations[0])
	}
	if document.AnsibleTaskTimings[0].Phase != "proxmox" || document.AnsibleTaskTimings[0].Host != "lab-fw-01" || document.AnsibleTaskTimings[0].Task != "Apply config" || document.AnsibleTaskTimings[0].DurationMS != 17 {
		t.Fatalf("unexpected Ansible task timing: %+v", document.AnsibleTaskTimings[0])
	}
	if document.AnsibleTaskBatches[0].Phase != "proxmox" || document.AnsibleTaskBatches[0].Task != "Apply config" || document.AnsibleTaskBatches[0].DurationMS != 21 {
		t.Fatalf("unexpected Ansible task batch timing: %+v", document.AnsibleTaskBatches[0])
	}
	if strings.Contains(string(data), "failure") {
		t.Fatalf("deployment timing report should not contain failure details: %s", data)
	}
}

func TestDeploymentTimingPersistenceFailureDoesNotFailDeployment(t *testing.T) {
	var output bytes.Buffer
	report := newDeploymentReport(&output)
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	report.setTimingPath(filepath.Join(blocked, "deploy.json"))
	report.start("persist", "Persist final state")
	report.complete()
	if err := report.finalize(nil); err != nil {
		t.Fatalf("timing persistence failure changed deployment result: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "Deployment: PASS") || !strings.Contains(text, "Timing report: unavailable") {
		t.Fatalf("successful deployment did not remain PASS with unavailable timing report:\n%s", text)
	}
	if strings.Contains(text, "Failed phase: Persist final state") {
		t.Fatalf("timing persistence failure was reported as a failed phase:\n%s", text)
	}
}

func TestDeploymentFailedTimingReportRedactsFailureDetails(t *testing.T) {
	var output bytes.Buffer
	report := newDeploymentReport(&output)
	report.setTimingPath(filepath.Join(t.TempDir(), "deploy", "timing.json"))
	report.start("health", "Run live health gates")
	if err := report.finalize(errors.New("TOP_SECRET_SENTINEL")); err == nil {
		t.Fatal("failed deployment unexpectedly passed")
	}
	data, err := os.ReadFile(report.timingPath)
	if err != nil {
		t.Fatalf("read failed deployment timing report: %v", err)
	}
	if strings.Contains(string(data), "TOP_SECRET_SENTINEL") {
		t.Fatalf("failed deployment timing report leaked failure detail: %s", data)
	}
	var document struct {
		Succeeded bool `json:"succeeded"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.Succeeded {
		t.Fatal("failed deployment timing report was marked successful")
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
