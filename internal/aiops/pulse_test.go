package aiops

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPulseClientUsesExactReadAndNoteAuthorities(t *testing.T) {
	now := time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
	read := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/alerts/active" || request.Header.Get("Authorization") != "Bearer "+strings.Repeat("r", 32) {
			t.Fatalf("unexpected read authority: %s %s", request.Method, request.URL.String())
		}
		body := `[{"id":"alert-1","type":"cpu","level":"warning","resourceId":"vm:101","message":"CPU high","startTime":"` + now.Format(time.RFC3339) + `","ignoredPulseField":true}]`
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	note := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/alerts/incidents/note" || request.Header.Get("Authorization") != "Bearer "+strings.Repeat("n", 32) {
			t.Fatalf("unexpected note authority: %s %s", request.Method, request.URL.String())
		}
		data, _ := io.ReadAll(request.Body)
		if strings.Contains(string(data), "acknowledge") || !strings.Contains(string(data), `"alertIdentifier":"alert-1"`) {
			t.Fatalf("unsafe note payload: %s", data)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"success":true}`))}, nil
	})
	client := PulseClient{Read: NewBoundedHTTPClient(read), ReadToken: strings.Repeat("r", 32), Note: NewBoundedHTTPClient(note), NoteToken: strings.Repeat("n", 32), BaseURL: "https://monitor.example"}
	alerts, err := client.ActiveAlerts(context.Background())
	if err != nil || len(alerts) != 1 || alerts[0].ResourceID != "vm:101" {
		t.Fatalf("ActiveAlerts()=%#v err=%v", alerts, err)
	}
	if err := client.WriteNote(context.Background(), PendingNote{PulseAlertID: "alert-1", Text: "inconclusive"}); err != nil {
		t.Fatal(err)
	}
}

func TestReconciliationRequiresThreeSuccessfulMissingPolls(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC)
	incident, _, err := store.Admit(context.Background(), Alert{PulseAlertID: "alert-1", StartedAt: now, ResourceID: "vm:101", Kind: "cpu", Severity: "warning", Title: "CPU high"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for poll := 1; poll <= 2; poll++ {
		resolved, err := store.Reconcile(context.Background(), nil, now.Add(time.Duration(poll)*time.Minute))
		if err != nil || len(resolved) != 0 {
			t.Fatalf("poll %d resolved=%v err=%v", poll, resolved, err)
		}
	}
	resolved, err := store.Reconcile(context.Background(), nil, now.Add(3*time.Minute))
	if err != nil || len(resolved) != 1 || resolved[0] != incident.ID {
		t.Fatalf("third poll resolved=%v err=%v", resolved, err)
	}
	state, err := store.IncidentState(context.Background(), incident.ID)
	if err != nil || state != StateResolved {
		t.Fatalf("state=%s err=%v", state, err)
	}
}

func TestPulseNoteIntentIsIdempotentPerTransition(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/incidents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	_, _, err = store.Admit(context.Background(), Alert{PulseAlertID: "alert-1", StartedAt: now, ResourceID: "vm:101", Kind: "cpu", Severity: "warning", Title: "CPU high"}, now)
	if err != nil {
		t.Fatal(err)
	}
	note, ok, err := store.NextPendingNote(context.Background())
	if err != nil || !ok || note.Transition != StateQueued {
		t.Fatalf("note=%#v ok=%v err=%v", note, ok, err)
	}
	if err := store.RecordNoteAttempt(context.Background(), note, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.NextPendingNote(context.Background()); err != nil || ok {
		t.Fatalf("delivered note remained pending: ok=%v err=%v", ok, err)
	}
}
