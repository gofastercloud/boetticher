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

func TestBootstrapReportRendersProgressAndSuccessfulSummary(t *testing.T) {
	var output bytes.Buffer
	report := newBootstrapReport(&output, 2)
	report.start("validate", "Validate bootstrap request")
	report.complete()
	report.start("persist", "Persist bootstrap state")
	report.complete()
	report.finalize(nil)

	text := output.String()
	for _, want := range []string{
		"[1/2] Validate bootstrap request",
		"PASS Validate bootstrap request",
		"PASS Persist bootstrap state",
		"Bootstrap: PASS",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("bootstrap report omitted %q:\n%s", want, text)
		}
	}
	assertNoHumanEvidenceStates(t, text)
}

func TestBootstrapReportRendersFailureNextAction(t *testing.T) {
	var output bytes.Buffer
	report := newBootstrapReport(&output, 2)
	report.start("validate", "Validate bootstrap request")
	report.complete()
	report.start("trust", "Establish host trust and scoped access")
	err := errors.New("HOLD: independent Age recovery copy is not secured")
	report.finalize(err)

	text := output.String()
	for _, want := range []string{
		"PASS Validate bootstrap request",
		"FAIL Establish host trust and scoped access",
		"Reason: FAIL: independent Age recovery copy is not secured",
		"Bootstrap: FAIL",
		"Next action: Secure and verify the independent Age recovery copy",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("bootstrap failure report omitted %q:\n%s", want, text)
		}
	}
	assertNoHumanEvidenceStates(t, text)
}

func TestBootstrapReportPersistsTimingWithoutFailureDetails(t *testing.T) {
	var output bytes.Buffer
	report := newBootstrapReport(&output, 1)
	report.setIdentity("0.4.1", "sha256:model")
	report.setTimingPath(filepath.Join(t.TempDir(), "bootstrap", "timing.json"))
	report.start("validate", "Validate bootstrap request")
	report.recordTiming("builder_build_and_qualification", time.Now().Add(-25*time.Millisecond))
	report.complete()
	report.finalize(nil)

	data, err := os.ReadFile(report.timingPath)
	if err != nil {
		t.Fatalf("read bootstrap timing report: %v", err)
	}
	var document struct {
		Operation       string            `json:"operation"`
		PlatformVersion string            `json:"platform_version"`
		ModelRevision   string            `json:"model_revision"`
		Succeeded       bool              `json:"succeeded"`
		DurationMS      int64             `json:"duration_ms"`
		Phases          []json.RawMessage `json:"phases"`
		Suboperations   []struct {
			Phase      string `json:"phase"`
			Kind       string `json:"kind"`
			Target     string `json:"target"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"suboperations"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode bootstrap timing report: %v", err)
	}
	if document.Operation != "bootstrap" || document.PlatformVersion != "0.4.1" || document.ModelRevision != "sha256:model" || !document.Succeeded || document.DurationMS < 0 || len(document.Phases) != 1 || len(document.Suboperations) != 1 {
		t.Fatalf("unexpected bootstrap timing report: %+v", document)
	}
	if document.Suboperations[0].Phase != "artifacts" || document.Suboperations[0].Kind != "artifact" || document.Suboperations[0].Target != "builder_build_and_qualification" || document.Suboperations[0].DurationMS < 0 {
		t.Fatalf("unexpected bootstrap suboperation timing: %+v", document.Suboperations[0])
	}
	if strings.Contains(string(data), "failure") {
		t.Fatalf("bootstrap timing report should not contain failure details: %s", data)
	}
}

func TestBootstrapTimingPersistenceFailureDoesNotFailBootstrap(t *testing.T) {
	var output bytes.Buffer
	report := newBootstrapReport(&output, 1)
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	report.setTimingPath(filepath.Join(blocked, "bootstrap.json"))
	report.start("persist", "Persist bootstrap state")
	report.complete()
	if err := report.finalize(nil); err != nil {
		t.Fatalf("timing persistence failure changed bootstrap result: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "Bootstrap: PASS") || !strings.Contains(text, "Timing report: unavailable") {
		t.Fatalf("successful bootstrap did not remain PASS with unavailable timing report:\n%s", text)
	}
}

func TestBootstrapFailedTimingReportRedactsFailureDetails(t *testing.T) {
	var output bytes.Buffer
	report := newBootstrapReport(&output, 1)
	report.setTimingPath(filepath.Join(t.TempDir(), "bootstrap", "timing.json"))
	report.start("trust", "Establish host trust and scoped access")
	if err := report.finalize(errors.New("TOP_SECRET_SENTINEL")); err == nil {
		t.Fatal("failed bootstrap unexpectedly passed")
	}
	data, err := os.ReadFile(report.timingPath)
	if err != nil {
		t.Fatalf("read failed bootstrap timing report: %v", err)
	}
	if strings.Contains(string(data), "TOP_SECRET_SENTINEL") {
		t.Fatalf("failed bootstrap timing report leaked failure detail: %s", data)
	}
	var document struct {
		Succeeded bool `json:"succeeded"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.Succeeded {
		t.Fatal("failed bootstrap timing report was marked successful")
	}
}
