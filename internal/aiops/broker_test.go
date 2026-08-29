package aiops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixedEvidence struct{ data json.RawMessage }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func (f fixedEvidence) Query(context.Context, EvidenceRequest, EvidencePolicy) (json.RawMessage, error) {
	return f.data, nil
}

func TestEvidenceBrokerEnforcesIncidentAuthorityAndBudgets(t *testing.T) {
	now := time.Date(2026, 8, 28, 1, 0, 0, 0, time.UTC)
	registry := NewCapabilityRegistry()
	policy := EvidencePolicy{IncidentID: "incident-1", PulseAlertID: "alert-1", ResourceIDs: map[string]bool{"vm:101": true}, Hosts: map[string]map[string]bool{"lab-dns-01": {"blocky.service": true}}}
	token, err := registry.Issue(policy, now)
	if err != nil {
		t.Fatal(err)
	}
	broker := &Broker{Capabilities: registry, Evidence: fixedEvidence{data: json.RawMessage(`{"ok":true}`)}, Now: func() time.Time { return now }}
	handler := broker.EvidenceHandler()
	for call := 0; call < MaxEvidenceCalls; call++ {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/evidence/query", strings.NewReader(`{"operation":"resource_state","incident_id":"incident-1","resource_id":"vm:101"}`))
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("call %d returned %d: %s", call, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/evidence/query", strings.NewReader(`{"operation":"resource_state","incident_id":"incident-1","resource_id":"vm:101"}`))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("fifth evidence call returned %d", response.Code)
	}
}

func TestCapabilityRegistryAllocatesEvidenceCallsAtomically(t *testing.T) {
	now := time.Now().UTC()
	registry := NewCapabilityRegistry()
	token, err := registry.Issue(EvidencePolicy{IncidentID: "incident-1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		call int
		err  error
	}
	results := make(chan result, MaxEvidenceCalls+1)
	for i := 0; i < MaxEvidenceCalls+1; i++ {
		go func() {
			claim, claimErr := registry.reserveEvidenceCall(token, now)
			results <- result{call: claim.Call, err: claimErr}
		}()
	}
	calls := make(map[int]bool)
	errorsSeen := 0
	for i := 0; i < MaxEvidenceCalls+1; i++ {
		value := <-results
		if value.err != nil {
			errorsSeen++
			continue
		}
		if value.call < 1 || value.call > MaxEvidenceCalls || calls[value.call] {
			t.Fatalf("duplicate or out-of-range evidence call: %d", value.call)
		}
		calls[value.call] = true
	}
	if len(calls) != MaxEvidenceCalls || errorsSeen != 1 {
		t.Fatalf("atomic evidence allocation calls=%v errors=%d", calls, errorsSeen)
	}
}

func TestEvidenceBrokerRejectsSchemaAndNetworkEscalation(t *testing.T) {
	now := time.Now().UTC()
	registry := NewCapabilityRegistry()
	token, err := registry.Issue(EvidencePolicy{IncidentID: "incident-1", PulseAlertID: "alert-1", ResourceIDs: map[string]bool{"vm:101": true}}, now)
	if err != nil {
		t.Fatal(err)
	}
	broker := &Broker{Capabilities: registry, Evidence: fixedEvidence{data: json.RawMessage(`{}`)}, Now: func() time.Time { return now }}
	for _, body := range []string{
		`{"operation":"resource_state","incident_id":"incident-1","resource_id":"vm:999"}`,
		`{"operation":"resource_state","incident_id":"incident-1","resource_id":"vm:101","url":"https://attacker.example"}`,
		`{"operation":"central_journal","incident_id":"incident-1","host":"127.0.0.1","limit":1,"since_minutes":1}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/evidence/query", strings.NewReader(body))
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		broker.EvidenceHandler().ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatalf("hostile evidence accepted: %s", body)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/evidence/query", strings.NewReader(`{"operation":"alert_context","incident_id":"incident-1"}`))
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	broker.EvidenceHandler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-loopback caller returned %d", response.Code)
	}
}

func TestRouterBrokerOverwritesModelAndOutputBudget(t *testing.T) {
	var forwarded completionRequest
	router := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			t.Fatalf("unexpected router request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&forwarded); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"choices":[]}`))}, nil
	})
	now := time.Now().UTC()
	registry := NewCapabilityRegistry()
	_, err := registry.Issue(EvidencePolicy{IncidentID: "incident-1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	routerIdentity := "boetticher-holmes-active-investigation"
	broker := &Broker{Capabilities: registry, Evidence: fixedEvidence{}, Router: NewBoundedHTTPClient(router), RouterURL: "https://router.example/v1/chat/completions", ModelAlias: "operations-investigator", RouterIdentity: routerIdentity, Now: func() time.Time { return now }}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", strings.NewReader(`{"model":"attacker/model","messages":[{"role":"user","content":"x"}],"max_tokens":99999}`))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+routerIdentity)
	response := httptest.NewRecorder()
	broker.RouterHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("router broker returned %d: %s", response.Code, response.Body.String())
	}
	if forwarded.Model != "operations-investigator" || forwarded.MaxTokens != MaxOutputTokens {
		t.Fatalf("forwarded request retained caller authority: %#v", forwarded)
	}
}

func TestRouterBrokerRejectsInputAboveConservativeTokenBudget(t *testing.T) {
	routerCalls := 0
	router := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		routerCalls++
		return nil, errors.New("unexpected router call")
	})
	now := time.Now().UTC()
	registry := NewCapabilityRegistry()
	if _, err := registry.Issue(EvidencePolicy{IncidentID: "incident-1"}, now); err != nil {
		t.Fatal(err)
	}
	identity := "boetticher-holmes-active-investigation"
	broker := &Broker{Capabilities: registry, Router: NewBoundedHTTPClient(router), RouterURL: "https://router.example/v1/chat/completions", ModelAlias: "operations-investigator", RouterIdentity: identity, Now: func() time.Time { return now }}
	body, err := json.Marshal(map[string]any{"model": "operations-investigator", "messages": []map[string]string{{"role": "user", "content": strings.Repeat("x", MaxPromptTokens)}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+identity)
	response := httptest.NewRecorder()
	broker.RouterHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || routerCalls != 0 {
		t.Fatalf("oversized model input status=%d router calls=%d", response.Code, routerCalls)
	}
}
