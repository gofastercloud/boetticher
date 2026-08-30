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
		Succeeded     bool              `json:"succeeded"`
		DurationMS    int64             `json:"duration_ms"`
		Phases        []json.RawMessage `json:"phases"`
		Suboperations []struct {
			Name       string `json:"name"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"suboperations"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode bootstrap timing report: %v", err)
	}
	if !document.Succeeded || document.DurationMS < 0 || len(document.Phases) != 1 || len(document.Suboperations) != 1 {
		t.Fatalf("unexpected bootstrap timing report: %+v", document)
	}
	if document.Suboperations[0].Name != "builder_build_and_qualification" || document.Suboperations[0].DurationMS < 0 {
		t.Fatalf("unexpected bootstrap suboperation timing: %+v", document.Suboperations[0])
	}
	if strings.Contains(string(data), "failure") {
		t.Fatalf("bootstrap timing report should not contain failure details: %s", data)
	}
}
