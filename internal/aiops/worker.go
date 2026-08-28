package aiops

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type InvestigationResult struct {
	Report Report
	Usage  Usage
}

type Investigator interface {
	Investigate(context.Context, Incident, string) (InvestigationResult, error)
}

type PolicyResolver func(Incident) (EvidencePolicy, error)

type Worker struct {
	Store        *Store
	Capabilities *CapabilityRegistry
	Investigator Investigator
	Policy       PolicyResolver
	Now          func() time.Time
	mu           sync.Mutex
	cancels      map[string]context.CancelFunc
}

func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	if w.Store == nil || w.Capabilities == nil || w.Investigator == nil || w.Policy == nil {
		return false, errors.New("worker dependencies are incomplete")
	}
	now := w.now()
	if _, err := w.Store.PromoteDeferred(ctx, now); err != nil {
		return false, fmt.Errorf("promote deferred incident: %w", err)
	}
	incident, ok, err := w.Store.ClaimNext(ctx, now)
	if err != nil || !ok {
		return ok, err
	}
	policy, err := w.Policy(incident)
	if err != nil {
		return true, w.fail(ctx, incident.ID, "policy_unavailable")
	}
	capability, err := w.Capabilities.Issue(policy, now)
	if err != nil {
		return true, w.fail(ctx, incident.ID, "capability_unavailable")
	}
	defer w.Capabilities.Revoke(capability)
	investigationContext, cancel := context.WithTimeout(ctx, MaxInvestigationTime)
	defer cancel()
	w.mu.Lock()
	if w.cancels == nil {
		w.cancels = map[string]context.CancelFunc{}
	}
	w.cancels[incident.ID] = cancel
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.cancels, incident.ID)
		w.mu.Unlock()
	}()
	result, err := w.Investigator.Investigate(investigationContext, incident, capability)
	if err != nil {
		if state, stateErr := w.Store.IncidentState(ctx, incident.ID); stateErr == nil && state == StateResolved {
			return true, nil
		}
		reason := "investigation_failed"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(investigationContext.Err(), context.DeadlineExceeded) {
			reason = "investigation_timeout"
		}
		return true, w.fail(ctx, incident.ID, reason)
	}
	references, steps, err := w.Capabilities.Snapshot(capability)
	if err != nil {
		return true, w.fail(ctx, incident.ID, "capability_lost")
	}
	result.Usage.HolmesSteps = steps
	if err := w.Store.Complete(ctx, incident.ID, result.Report, result.Usage, references, w.now()); err != nil {
		if state, stateErr := w.Store.IncidentState(ctx, incident.ID); stateErr == nil && state == StateResolved {
			return true, nil
		}
		if failErr := w.fail(ctx, incident.ID, "invalid_report"); failErr != nil {
			return true, fmt.Errorf("complete investigation: %v; mark failed: %w", err, failErr)
		}
		return true, err
	}
	return true, nil
}

func (w *Worker) Cancel(incidentID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cancel := w.cancels[incidentID]; cancel != nil {
		cancel()
	}
}

func (w *Worker) fail(ctx context.Context, incidentID, reason string) error {
	return w.Store.Fail(ctx, incidentID, reason, w.now())
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}
