package incidents

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerIntakesAuthenticatedWebhookAndDeduplicates(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "incidents.db"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := Handler{Store: store, WebhookToken: "webhook-secret", Authorize: func(*http.Request) bool { return true }}
	request := func() *http.Response {
		r := httptest.NewRequest(http.MethodPost, "/webhooks/gatus", strings.NewReader(`{"title":"DNS down","fingerprint":"dns-1"}`))
		r.Header.Set("Authorization", "Bearer webhook-secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result()
	}
	if response := request(); response.StatusCode != http.StatusAccepted {
		t.Fatalf("webhook status=%d", response.StatusCode)
	}
	if response := request(); response.StatusCode != http.StatusAccepted {
		t.Fatalf("duplicate webhook status=%d", response.StatusCode)
	}
	unauthenticated := httptest.NewRecorder()
	h.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "/webhooks/gatus", strings.NewReader(`{}`)))
	if unauthenticated.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated webhook status=%d", unauthenticated.Code)
	}
}

func TestHandlerEscapesReportHTMLAndRequiresCSRF(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "incidents.db"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.Intake(t.Context(), Alert{Source: "gatus", Title: `<script>alert(1)</script>`, Fingerprint: "x"}); err != nil {
		t.Fatal(err)
	}
	h := Handler{Store: store, Authorize: func(*http.Request) bool { return true }, Investigator: &testInvestigator{result: InvestigationResult{State: Completed}}}
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/incidents", nil))
	if page.Code != http.StatusOK || strings.Contains(page.Body.String(), "<script>alert") {
		t.Fatalf("report page was not escaped: %s", page.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/api/incidents/x/investigate", nil)
	blocked := httptest.NewRecorder()
	h.ServeHTTP(blocked, request)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("investigation without csrf status=%d", blocked.Code)
	}
}
