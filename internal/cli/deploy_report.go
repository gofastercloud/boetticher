package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofastercloud/boetticher/internal/telemetry"
)

const deploymentPhaseCount = 9

type deploymentPhase struct {
	ID        string
	Name      string
	Started   time.Time
	Finished  time.Time
	Completed bool
	Component string
	Cause     error
}

type deploymentMutation struct {
	Domain string `json:"domain"`
	Target string `json:"target"`
	Action string `json:"action"`
}

type deploymentTiming struct {
	Phase      string `json:"phase"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMS int64  `json:"duration_ms"`
}

type deploymentReport struct {
	out                   io.Writer
	phases                []deploymentPhase
	active                int
	failedComponent       string
	mutations             []deploymentMutation
	infrastructureChanged bool
	mutationScopeCertain  bool
	cleanupAttempted      bool
	cleanupRemoved        bool
	cleanupErr            error
	dryRun                bool
	runID                 string
	operation             string
	platformVersion       string
	modelRevision         string
	startedAt             time.Time
	finishedAt            time.Time
	timingPath            string
	timings               []deploymentTiming
	measurements          operationMeasurements
	measurementMu         sync.Mutex
}

func (r *deploymentReport) Observe(event telemetry.Event) {
	r.measurementMu.Lock()
	defer r.measurementMu.Unlock()
	r.measurements.Observe(event)
}

func newDeploymentReport(out io.Writer) *deploymentReport {
	started := time.Now()
	runID := "deploy-" + started.UTC().Format("20060102T150405.000000000Z")
	return &deploymentReport{out: out, active: -1, mutationScopeCertain: true, runID: runID, operation: "deploy", startedAt: started}
}

func (r *deploymentReport) setIdentity(platformVersion, modelRevision string) {
	r.platformVersion = platformVersion
	r.modelRevision = modelRevision
}

func (r *deploymentReport) activePhaseID() string {
	if r.active >= 0 && r.active < len(r.phases) {
		return r.phases[r.active].ID
	}
	return "unknown"
}

func (r *deploymentReport) start(id, name string) {
	r.phases = append(r.phases, deploymentPhase{ID: id, Name: name, Started: time.Now()})
	r.active = len(r.phases) - 1
	fmt.Fprintf(r.out, "[%d/%d] %s\n", len(r.phases), deploymentPhaseCount, name)
}

func (r *deploymentReport) complete() {
	if r.active < 0 || r.active >= len(r.phases) || r.phases[r.active].Completed {
		return
	}
	r.phases[r.active].Completed = true
	r.phases[r.active].Finished = time.Now()
	fmt.Fprintf(r.out, "      PASS (%s)\n", formatOperationDuration(deploymentPhaseDuration(r.phases[r.active], time.Now())))
}

func (r *deploymentReport) fail(err error, component string) {
	if r.active < 0 || r.active >= len(r.phases) {
		return
	}
	phase := &r.phases[r.active]
	if phase.Completed {
		return
	}
	phase.Cause = err
	phase.Finished = time.Now()
	if component == "" {
		component = phase.Name
	}
	phase.Component = component
	r.failedComponent = component
	fmt.Fprintf(r.out, "      FAIL: %s\n", compactError(err))
}

func (r *deploymentReport) recordFailure(operationErr error) {
	if operationErr == nil || r.active < 0 || r.active >= len(r.phases) {
		return
	}
	if r.phases[r.active].Completed || r.phases[r.active].Cause != nil {
		return
	}
	r.fail(operationErr, deploymentFailureComponent(operationErr))
}

func (r *deploymentReport) setTimingPath(path string) {
	r.timingPath = path
}

func (r *deploymentReport) recordTiming(phase, kind, target string, started time.Time) {
	if phase == "" || kind == "" || target == "" || started.IsZero() {
		return
	}
	finished := time.Now()
	r.timings = append(r.timings, deploymentTiming{
		Phase:      phase,
		Kind:       kind,
		Target:     target,
		StartedAt:  started.UTC().Format(time.RFC3339Nano),
		FinishedAt: finished.UTC().Format(time.RFC3339Nano),
		DurationMS: finished.Sub(started).Milliseconds(),
	})
	fmt.Fprintf(r.out, "      Timing: %s/%s/%s (%s)\n", phase, kind, target, formatOperationDuration(finished.Sub(started)))
}

func (r *deploymentReport) timed(phase, kind, target string, fn func() error) error {
	started := time.Now()
	err := fn()
	r.recordTiming(phase, kind, target, started)
	return err
}

func (r *deploymentReport) recordMutation(domain, target, action string, changed bool) {
	if !changed {
		return
	}
	r.infrastructureChanged = true
	r.mutations = append(r.mutations, deploymentMutation{Domain: domain, Target: target, Action: action})
	fmt.Fprintf(r.out, "      Changed: %s: %s %s\n", titleWord(domain), target, action)
}

func (r *deploymentReport) markMutationUncertain() {
	r.infrastructureChanged = true
	r.mutationScopeCertain = false
	fmt.Fprintln(r.out, "      Changed: infrastructure mutation scope requires verification")
}

func (r *deploymentReport) setCleanup(attempted, removed bool, err error) {
	r.cleanupAttempted = attempted
	r.cleanupRemoved = removed
	r.cleanupErr = err
	if err != nil {
		// Failed cleanup leaves externally meaningful privileged state
		// unresolved. The report must not imply that the operation was
		// side-effect free merely because the forward path did not record a
		// provider mutation.
		r.infrastructureChanged = true
		r.mutationScopeCertain = false
	}
}

func (r *deploymentReport) finalize(operationErr error) error {
	r.recordFailure(operationErr)
	if r.finishedAt.IsZero() {
		r.finishedAt = time.Now()
	}
	timingErr := r.persistTiming(operationErr)

	fmt.Fprintln(r.out)
	reportedCause := false
	for _, phase := range r.phases {
		result := "PASS"
		if !phase.Completed {
			result = "FAIL"
		}
		fmt.Fprintf(r.out, "%s %s (%s)\n", result, phase.Name, formatOperationDuration(deploymentPhaseDuration(phase, r.finishedAt)))
		if phase.Cause != nil {
			reportedCause = true
			if phase.Component != "" {
				fmt.Fprintf(r.out, "      Component: %s\n", phase.Component)
			}
			fmt.Fprintf(r.out, "      Reason: %s\n", compactError(phase.Cause))
		}
	}
	if operationErr != nil && !reportedCause && r.cleanupErr == nil {
		fmt.Fprintf(r.out, "Reason: %s\n", compactError(operationErr))
	}

	if r.infrastructureChanged {
		fmt.Fprintln(r.out, "Infrastructure changed: YES")
	} else {
		fmt.Fprintln(r.out, "Infrastructure changed: NO")
	}
	fmt.Fprintln(r.out, r.measurements.summaryLine())
	if len(r.mutations) > 0 {
		fmt.Fprintln(r.out, "Changes before failure:")
		for _, mutation := range r.mutations {
			fmt.Fprintf(r.out, "  %s: %s %s\n", titleWord(mutation.Domain), mutation.Target, mutation.Action)
		}
	}
	if !r.mutationScopeCertain {
		fmt.Fprintln(r.out, "Mutation scope: exact scope could not be proven after an operation boundary")
	}
	if r.cleanupAttempted {
		if r.cleanupErr == nil && r.cleanupRemoved {
			fmt.Fprintln(r.out, "Temporary authority removed: YES")
		} else {
			fmt.Fprintf(r.out, "Temporary authority removed: NO (%s)\n", compactError(r.cleanupErr))
		}
	} else {
		fmt.Fprintln(r.out, "Temporary authority: not established")
	}
	if operationErr == nil && r.cleanupErr == nil {
		fmt.Fprintln(r.out, "Deployment: PASS")
		if r.dryRun {
			fmt.Fprintln(r.out, "No infrastructure was changed; static deployment checks passed (dry-run).")
		} else {
			fmt.Fprintln(r.out, "All requested components passed deployment and health checks.")
		}
		r.renderTimingAvailability(timingErr)
		return operationErr
	}
	fmt.Fprintln(r.out, "Deployment: FAIL")
	if r.cleanupErr != nil {
		fmt.Fprintln(r.out, "Failed phase: Temporary authority cleanup")
	} else if r.active >= 0 && r.active < len(r.phases) && !r.phases[r.active].Completed && r.phases[r.active].Cause != nil {
		fmt.Fprintf(r.out, "Failed phase: %s\n", r.phases[r.active].Name)
	}
	fmt.Fprintf(r.out, "Retry: %s\n", deploymentRetryAdvice(operationErr, r.cleanupErr))
	fmt.Fprintf(r.out, "Next action: %s\n", deploymentNextAction(operationErr, r.cleanupErr))
	r.renderTimingAvailability(timingErr)
	return operationErr
}

func (r *deploymentReport) renderTimingAvailability(err error) {
	if r.timingPath == "" {
		return
	}
	if err != nil {
		fmt.Fprintf(r.out, "Timing report: unavailable (%s)\n", compactError(err))
		return
	}
	fmt.Fprintf(r.out, "Timing report: %s\n", r.timingPath)
}

func deploymentPhaseDuration(phase deploymentPhase, finishedAt time.Time) time.Duration {
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

func (r *deploymentReport) persistTiming(operationErr error) error {
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
		Component  string `json:"component,omitempty"`
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
			Component: phase.Component,
		}
		if !finished.IsZero() {
			entry.FinishedAt = finished.UTC().Format(time.RFC3339Nano)
			entry.DurationMS = deploymentPhaseDuration(phase, finished).Milliseconds()
		}
		phases = append(phases, entry)
	}
	document := struct {
		Version               int                   `json:"version"`
		Operation             string                `json:"operation"`
		PlatformVersion       string                `json:"platform_version,omitempty"`
		ModelRevision         string                `json:"model_revision,omitempty"`
		RunID                 string                `json:"run_id"`
		StartedAt             string                `json:"started_at"`
		FinishedAt            string                `json:"finished_at"`
		DurationMS            int64                 `json:"duration_ms"`
		Succeeded             bool                  `json:"succeeded"`
		InfrastructureChanged bool                  `json:"infrastructure_changed"`
		MutationScopeCertain  bool                  `json:"mutation_scope_certain"`
		Mutations             []deploymentMutation  `json:"mutations,omitempty"`
		CleanupAttempted      bool                  `json:"cleanup_attempted"`
		CleanupRemoved        bool                  `json:"cleanup_removed"`
		Phases                []phaseTiming         `json:"phases"`
		Suboperations         []deploymentTiming    `json:"suboperations"`
		Measurements          operationMeasurements `json:"measurements"`
	}{
		Version:               1,
		Operation:             r.operation,
		PlatformVersion:       r.platformVersion,
		ModelRevision:         r.modelRevision,
		RunID:                 r.runID,
		StartedAt:             r.startedAt.UTC().Format(time.RFC3339Nano),
		FinishedAt:            r.finishedAt.UTC().Format(time.RFC3339Nano),
		DurationMS:            r.finishedAt.Sub(r.startedAt).Milliseconds(),
		Succeeded:             operationErr == nil && r.cleanupErr == nil,
		InfrastructureChanged: r.infrastructureChanged,
		MutationScopeCertain:  r.mutationScopeCertain,
		Mutations:             append([]deploymentMutation(nil), r.mutations...),
		CleanupAttempted:      r.cleanupAttempted,
		CleanupRemoved:        r.cleanupRemoved,
		Phases:                phases,
		Suboperations:         append([]deploymentTiming(nil), r.timings...),
		Measurements:          r.measurements,
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode deployment timing report: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.timingPath), 0700); err != nil {
		return fmt.Errorf("create deployment timing directory: %w", err)
	}
	if err := writePrivate(r.timingPath, append(data, '\n')); err != nil {
		return fmt.Errorf("write deployment timing report: %w", err)
	}
	return nil
}

func compactError(err error) string {
	if err == nil {
		return "none"
	}
	message := strings.TrimSpace(err.Error())
	for _, forbidden := range []string{"HOLD:", "NOT TESTED", "NOT VERIFIED", "PARTIAL", "INCONCLUSIVE"} {
		message = strings.ReplaceAll(message, forbidden, "FAIL:")
	}
	return message
}

func titleWord(value string) string {
	if value == "" {
		return "State"
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func deploymentRetryAdvice(operationErr, cleanupErr error) string {
	if cleanupErr != nil {
		return "NO — resolve the temporary-authority cleanup failure and follow the recovery instructions before retrying."
	}
	if operationErr == nil {
		return "YES — the deployment completed successfully."
	}
	message := strings.ToLower(operationErr.Error())
	if strings.Contains(message, "missing") || strings.Contains(message, "invalid") || strings.Contains(message, "cannot") || strings.Contains(message, "preflight") || strings.Contains(message, "artifact") {
		return "NO — correct the reported prerequisite first, then rerun deploy."
	}
	return "YES — rerunning deploy is safe; already-converged resources are retained."
}

func deploymentNextAction(operationErr, cleanupErr error) string {
	if cleanupErr != nil {
		return "Run boetticher doctor --live and complete the temporary-authority recovery procedure."
	}
	if operationErr == nil {
		return "No action required."
	}
	message := strings.ToLower(operationErr.Error())
	if strings.Contains(message, "preflight") || strings.Contains(message, "credential") || strings.Contains(message, "artifact") || strings.Contains(message, "network contract") {
		return "Correct the named prerequisite, then run boetticher deploy --site <site>."
	}
	return "Run boetticher doctor --live, correct the reported failure, then run boetticher deploy --site <site>."
}

func deploymentFailureComponent(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(compactError(err))
	for _, component := range []string{"tailnet-router", "monitoring", "litellm", "aiops", "gatus", "printer", "dns", "logging", "managed gateway", "firewall", "proxmox", "storage", "network", "credentials", "pki"} {
		if strings.Contains(message, component) {
			return component
		}
	}
	return ""
}

func combineDeploymentErrors(operationErr, cleanupErr error) error {
	if cleanupErr == nil {
		return operationErr
	}
	cleanup := fmt.Errorf("temporary root access cleanup failed: %w", cleanupErr)
	if operationErr == nil {
		return cleanup
	}
	return errors.Join(operationErr, cleanup)
}

type deploymentPresentationError struct {
	cause error
}

func (e deploymentPresentationError) Error() string {
	message := e.cause.Error()
	for _, forbidden := range []string{"HOLD:", "HOLD", "NOT TESTED", "NOT VERIFIED", "PARTIAL", "INCONCLUSIVE", "ACTION REQUIRED", "NOT BUILT"} {
		message = strings.ReplaceAll(message, forbidden, "FAIL")
	}
	return message
}

func (e deploymentPresentationError) Unwrap() error { return e.cause }

func deploymentErrorForOperator(err error) error {
	if err == nil {
		return nil
	}
	return deploymentPresentationError{cause: err}
}

func operatorErrorForHuman(err error) error {
	if err == nil {
		return nil
	}
	if _, alreadyPresented := err.(deploymentPresentationError); alreadyPresented {
		return err
	}
	return deploymentPresentationError{cause: err}
}

type deploymentCleanupRegistrar func(func(context.Context) error)
