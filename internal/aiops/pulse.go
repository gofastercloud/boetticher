package aiops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type PulseClient struct {
	Read      *http.Client
	ReadToken string
	Note      *http.Client
	NoteToken string
	BaseURL   string
}

func (p PulseClient) Validate() error {
	if p.Read == nil || p.Note == nil || len(p.ReadToken) < 32 || len(p.NoteToken) < 32 || p.ReadToken == p.NoteToken {
		return errors.New("Pulse client requires distinct bounded read and note identities")
	}
	return exactHTTPSBase(p.BaseURL)
}

func (p PulseClient) ActiveAlerts(ctx context.Context) ([]Alert, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(p.BaseURL, "/")+"/api/alerts/active", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+p.ReadToken)
	data, err := boundedResponse(p.Read, request, 128*1024)
	if err != nil {
		return nil, err
	}
	var alerts []Alert
	if err := json.Unmarshal(data, &alerts); err != nil || len(alerts) > 1024 {
		return nil, errors.New("Pulse active-alert response is invalid or excessive")
	}
	for _, alert := range alerts {
		if err := alert.Validate(); err != nil {
			return nil, fmt.Errorf("Pulse returned an invalid active alert: %w", err)
		}
	}
	return alerts, nil
}

func (p PulseClient) WriteNote(ctx context.Context, note PendingNote) error {
	body, err := json.Marshal(struct {
		AlertIdentifier string `json:"alertIdentifier"`
		Note            string `json:"note"`
		User            string `json:"user"`
	}{note.PulseAlertID, sanitizeText(note.Text, 4096), "boetticher-aiops"})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(p.BaseURL, "/")+"/api/alerts/incidents/note", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+p.NoteToken)
	response, err := p.Note.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return errors.New("Pulse note redirect is forbidden")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Pulse note endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}
