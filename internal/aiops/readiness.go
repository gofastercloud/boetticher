package aiops

import (
	"context"
	"net/http"
	"net/url"
)

const (
	ReadinessAIOps   = "aiops"
	ReadinessPulse   = "pulse_read"
	ReadinessJournal = "journal_query"
	ReadinessRouter  = "ai_router"
)

type ReadinessStatus struct {
	CheckedAt  string            `json:"checked_at"`
	ModelAlias string            `json:"model_alias"`
	Checks     map[string]string `json:"checks"`
}

func (s ReadinessStatus) Healthy() bool {
	for _, name := range []string{ReadinessAIOps, ReadinessPulse, ReadinessJournal, ReadinessRouter} {
		if s.Checks[name] != "PASS" {
			return false
		}
	}
	return true
}

type ReadinessSource interface {
	CheckPulse(context.Context) error
	CheckJournal(context.Context) error
}

type RuntimeReadiness struct {
	Pulse    PulseClient
	Evidence RemoteEvidence
}

func (r RuntimeReadiness) CheckPulse(ctx context.Context) error {
	_, err := r.Pulse.ActiveAlerts(ctx)
	return err
}

func (r RuntimeReadiness) CheckJournal(ctx context.Context) error {
	endpoint, err := url.Parse(r.Evidence.JournalURL)
	if err != nil {
		return err
	}
	endpoint.Path = "/healthz"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	_, err = boundedResponse(r.Evidence.Journal, request, 4096)
	return err
}
