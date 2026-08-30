package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const bootstrapPhaseCount = 6

type bootstrapPhase struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Started   time.Time `json:"started_at"`
	Finished  time.Time `json:"finished_at,omitempty"`
	Completed bool
	Cause     error
}

type bootstrapTiming struct {
	Name       string `json:"name"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMS int64  `json:"duration_ms"`
}

type bootstrapReport struct {
	out        io.Writer
	phases     []bootstrapPhase
	active     int
	total      int
	runID      string
	startedAt  time.Time
	finishedAt time.Time
	timingPath string
	timings    []bootstrapTiming
}

func newBootstrapReport(out io.Writer, total int) *bootstrapReport {
	started := time.Now()
	runID := "bootstrap-" + started.UTC().Format("20060102T150405.000000000Z")
	return &bootstrapReport{out: out, active: -1, total: total, runID: runID, startedAt: started}
}

func (r *bootstrapReport) start(id, name string) {
	r.phases = append(r.phases, bootstrapPhase{ID: id, Name: name, Started: time.Now()})
	r.active = len(r.phases) - 1
	fmt.Fprintf(r.out, "[%d/%d] %s\n", len(r.phases), r.total, name)
}

func (r *bootstrapReport) complete() {
	if r.active < 0 || r.active >= len(r.phases) || r.phases[r.active].Completed {
		return
	}
	phase := &r.phases[r.active]
	phase.Completed = true
	phase.Finished = time.Now()
	fmt.Fprintf(r.out, "      PASS (%s)\n", formatOperationDuration(time.Since(phase.Started)))
}

func (r *bootstrapReport) fail(err error) {
	if r.active < 0 || r.active >= len(r.phases) || r.phases[r.active].Completed {
		return
	}
	phase := &r.phases[r.active]
	phase.Cause = err
	phase.Finished = time.Now()
	fmt.Fprintf(r.out, "      FAIL: %s\n", compactError(err))
}

func (r *bootstrapReport) setTimingPath(path string) {
	r.timingPath = path
}

func (r *bootstrapReport) recordTiming(name string, started time.Time) {
	if name == "" || started.IsZero() {
		return
	}
	finished := time.Now()
	r.timings = append(r.timings, bootstrapTiming{
		Name:       name,
		StartedAt:  started.UTC().Format(time.RFC3339Nano),
		FinishedAt: finished.UTC().Format(time.RFC3339Nano),
		DurationMS: finished.Sub(started).Milliseconds(),
	})
}

func (r *bootstrapReport) emitTiming(out io.Writer, name string, started time.Time) {
	r.recordTiming(name, started)
	emitTiming(out, name, started)
}

func (r *bootstrapReport) finalize(operationErr error) error {
	if operationErr != nil {
		r.fail(operationErr)
	}
	r.finishedAt = time.Now()
	timingErr := r.persist(operationErr)
	if timingErr != nil {
		if operationErr == nil {
			operationErr = fmt.Errorf("persist bootstrap timing report: %w", timingErr)
		} else {
			operationErr = errors.Join(operationErr, fmt.Errorf("persist bootstrap timing report: %w", timingErr))
		}
		if r.active >= 0 && r.active < len(r.phases) && !r.phases[r.active].Completed && r.phases[r.active].Cause == nil {
			r.fail(operationErr)
		}
	}

	fmt.Fprintln(r.out)
	reportedCause := false
	for _, phase := range r.phases {
		result := "PASS"
		if !phase.Completed {
			result = "FAIL"
		}
		fmt.Fprintf(r.out, "%s %s (%s)\n", result, phase.Name, formatOperationDuration(phaseDuration(phase, r.finishedAt)))
		if phase.Cause != nil {
			reportedCause = true
			fmt.Fprintf(r.out, "      Reason: %s\n", compactError(phase.Cause))
		}
	}
	if operationErr == nil {
		fmt.Fprintln(r.out, "Bootstrap: PASS")
		if r.timingPath != "" {
			fmt.Fprintf(r.out, "Timing report: %s\n", r.timingPath)
		}
		return operationErr
	}
	fmt.Fprintln(r.out, "Bootstrap: FAIL")
	if r.active >= 0 && r.active < len(r.phases) && !r.phases[r.active].Completed {
		fmt.Fprintf(r.out, "Failed phase: %s\n", r.phases[r.active].Name)
	} else if timingErr != nil {
		fmt.Fprintf(r.out, "Failed finalization: %s\n", compactError(timingErr))
	}
	if !reportedCause {
		fmt.Fprintf(r.out, "Reason: %s\n", compactError(operationErr))
	}
	fmt.Fprintf(r.out, "Next action: %s\n", bootstrapNextAction(operationErr))
	if r.timingPath != "" && timingErr == nil {
		fmt.Fprintf(r.out, "Timing report: %s\n", r.timingPath)
	}
	return operationErr
}

func phaseDuration(phase bootstrapPhase, finishedAt time.Time) time.Duration {
	if phase.Started.IsZero() {
		return 0
	}
	finished := phase.Finished
	if finished.IsZero() {
		finished = finishedAt
	}
	if finished.Before(phase.Started) {
		return 0
	}
	return finished.Sub(phase.Started)
}

func (r *bootstrapReport) persist(operationErr error) error {
	if r.timingPath == "" {
		return nil
	}
	if r.finishedAt.IsZero() {
		r.finishedAt = time.Now()
	}
	type phaseTiming struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at,omitempty"`
		DurationMS int64  `json:"duration_ms"`
		Completed  bool   `json:"completed"`
	}
	phases := make([]phaseTiming, 0, len(r.phases))
	for _, phase := range r.phases {
		finished := phase.Finished
		if finished.IsZero() && !phase.Started.IsZero() {
			finished = r.finishedAt
		}
		entry := phaseTiming{
			ID:        phase.ID,
			Name:      phase.Name,
			StartedAt: phase.Started.UTC().Format(time.RFC3339Nano),
			Completed: phase.Completed,
		}
		if !finished.IsZero() {
			entry.FinishedAt = finished.UTC().Format(time.RFC3339Nano)
			entry.DurationMS = phaseDuration(phase, finished).Milliseconds()
		}
		phases = append(phases, entry)
	}
	document := struct {
		Version       int               `json:"version"`
		RunID         string            `json:"run_id"`
		StartedAt     string            `json:"started_at"`
		FinishedAt    string            `json:"finished_at"`
		DurationMS    int64             `json:"duration_ms"`
		Succeeded     bool              `json:"succeeded"`
		Phases        []phaseTiming     `json:"phases"`
		Suboperations []bootstrapTiming `json:"suboperations"`
	}{
		Version:       1,
		RunID:         r.runID,
		StartedAt:     r.startedAt.UTC().Format(time.RFC3339Nano),
		FinishedAt:    r.finishedAt.UTC().Format(time.RFC3339Nano),
		DurationMS:    r.finishedAt.Sub(r.startedAt).Milliseconds(),
		Succeeded:     operationErr == nil,
		Phases:        phases,
		Suboperations: append([]bootstrapTiming(nil), r.timings...),
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap timing report: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.timingPath), 0700); err != nil {
		return fmt.Errorf("create bootstrap timing directory: %w", err)
	}
	if err := writePrivate(r.timingPath, append(data, '\n')); err != nil {
		return fmt.Errorf("write bootstrap timing report: %w", err)
	}
	return nil
}

func bootstrapNextAction(err error) string {
	if err == nil {
		return "No action required."
	}
	if containsAnyFold(err.Error(), "recovery copy", "recovery-confirmed", "age identity") {
		return "Secure and verify the independent Age recovery copy, then rerun boetticher bootstrap with --recovery-confirmed."
	}
	if containsAnyFold(err.Error(), "storage-confirmed", "dedicated-data-disk", "storage device") {
		return "Review the configured storage device, then rerun boetticher bootstrap with --storage-confirmed."
	}
	if containsAnyFold(err.Error(), "trunk-interface", "physical VLAN", "physical trunk") {
		return "Choose the intended physical interface, then rerun boetticher bootstrap with --trunk-interface IFACE."
	}
	return "Review the reported failure, then rerun boetticher bootstrap with the same site and trust options."
}

func containsAnyFold(value string, terms ...string) bool {
	value = strings.ToLower(value)
	for _, term := range terms {
		if strings.Contains(value, strings.ToLower(term)) {
			return true
		}
	}
	return false
}

func formatOperationDuration(duration time.Duration) string {
	if duration < time.Second {
		return fmt.Sprintf("%dms", duration.Milliseconds())
	}
	return duration.Round(time.Second).String()
}
