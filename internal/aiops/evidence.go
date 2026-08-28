package aiops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type RemoteEvidence struct {
	Pulse        *http.Client
	PulseBaseURL string
	PulseToken   string
	Journal      *http.Client
	JournalURL   string
}

func (e RemoteEvidence) Query(ctx context.Context, request EvidenceRequest, policy EvidencePolicy) (json.RawMessage, error) {
	switch request.Operation {
	case OperationAlert:
		return e.pulseGET(ctx, "/api/alerts/events", url.Values{"alert_id": []string{policy.PulseAlertID}})
	case OperationResource:
		return e.pulseGET(ctx, "/api/resources/"+url.PathEscape(request.ResourceID), nil)
	case OperationMetric:
		return e.pulseGET(ctx, "/api/metrics-store/history", url.Values{
			"resource_id": []string{request.ResourceID},
			"metric":      []string{request.Metric},
			"minutes":     []string{strconv.Itoa(request.SinceMinutes)},
		})
	case OperationJournal:
		body, err := json.Marshal(struct {
			Host         string `json:"host"`
			Unit         string `json:"unit,omitempty"`
			Priority     string `json:"priority,omitempty"`
			SinceMinutes int    `json:"since_minutes"`
			Limit        int    `json:"limit"`
		}{request.Host, request.Unit, request.Priority, request.SinceMinutes, request.Limit})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.JournalURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return boundedResponse(e.Journal, req, 32*1024)
	default:
		return nil, errors.New("unknown evidence operation")
	}
}

func (e RemoteEvidence) Validate() error {
	if e.Pulse == nil || e.Journal == nil || e.PulseToken == "" {
		return errors.New("remote evidence requires distinct Pulse and journal clients")
	}
	if err := exactHTTPSBase(e.PulseBaseURL); err != nil {
		return fmt.Errorf("Pulse base URL: %w", err)
	}
	u, err := url.Parse(e.JournalURL)
	if err != nil || u.Scheme != "https" || u.Path != "/v1/query" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("journal URL must be the exact HTTPS query endpoint")
	}
	return nil
}

func (e RemoteEvidence) pulseGET(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	u := strings.TrimSuffix(e.PulseBaseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.PulseToken)
	return boundedResponse(e.Pulse, req, 32*1024)
}

func exactHTTPSBase(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("must be an origin-only HTTPS URL")
	}
	return nil
}

func boundedResponse(client *http.Client, request *http.Request, limit int64) (json.RawMessage, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, errors.New("redirects are forbidden")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("evidence endpoint returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("evidence endpoint response exceeded limit")
	}
	if !json.Valid(data) && !strings.Contains(response.Header.Get("Content-Type"), "application/x-ndjson") {
		return nil, errors.New("evidence endpoint returned invalid JSON")
	}
	if strings.Contains(response.Header.Get("Content-Type"), "application/x-ndjson") {
		encoded, err := json.Marshal(string(data))
		return encoded, err
	}
	return data, nil
}

func NewBoundedHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are forbidden")
		},
	}
}
