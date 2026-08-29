package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

const deploymentPhaseCount = 9

type deploymentPhase struct {
	ID        string
	Name      string
	Completed bool
	Component string
	Cause     error
}

type deploymentMutation struct {
	Domain string
	Target string
	Action string
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
}

func newDeploymentReport(out io.Writer) *deploymentReport {
	return &deploymentReport{out: out, active: -1, mutationScopeCertain: true}
}

func (r *deploymentReport) start(id, name string) {
	r.phases = append(r.phases, deploymentPhase{ID: id, Name: name})
	r.active = len(r.phases) - 1
	fmt.Fprintf(r.out, "[%d/%d] %s\n", len(r.phases), deploymentPhaseCount, name)
}

func (r *deploymentReport) complete() {
	if r.active < 0 || r.active >= len(r.phases) || r.phases[r.active].Completed {
		return
	}
	r.phases[r.active].Completed = true
	fmt.Fprintln(r.out, "      PASS")
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
	if component == "" {
		component = phase.Name
	}
	phase.Component = component
	r.failedComponent = component
	fmt.Fprintf(r.out, "      FAIL: %s\n", compactError(err))
}

func (r *deploymentReport) recordMutation(domain, target, action string, changed bool) {
	if !changed {
		return
	}
	r.infrastructureChanged = true
	r.mutations = append(r.mutations, deploymentMutation{Domain: domain, Target: target, Action: action})
}

func (r *deploymentReport) markMutationUncertain() {
	r.infrastructureChanged = true
	r.mutationScopeCertain = false
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

func (r *deploymentReport) finalize(operationErr error) {
	if operationErr != nil && r.active >= 0 && r.active < len(r.phases) && !r.phases[r.active].Completed {
		r.fail(operationErr, deploymentFailureComponent(operationErr))
	}

	fmt.Fprintln(r.out)
	reportedCause := false
	for _, phase := range r.phases {
		result := "PASS"
		if !phase.Completed {
			result = "FAIL"
		}
		fmt.Fprintf(r.out, "%s %s\n", result, phase.Name)
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
		return
	}
	fmt.Fprintln(r.out, "Deployment: FAIL")
	if r.cleanupErr != nil {
		fmt.Fprintln(r.out, "Failed phase: Temporary authority cleanup")
	} else if r.active >= 0 && r.active < len(r.phases) && r.phases[r.active].Name != "" {
		fmt.Fprintf(r.out, "Failed phase: %s\n", r.phases[r.active].Name)
	}
	fmt.Fprintf(r.out, "Retry: %s\n", deploymentRetryAdvice(operationErr, r.cleanupErr))
	fmt.Fprintf(r.out, "Next action: %s\n", deploymentNextAction(operationErr, r.cleanupErr))
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
