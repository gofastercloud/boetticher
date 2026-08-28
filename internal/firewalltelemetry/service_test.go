package firewalltelemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestServiceCollectsSnapshotAndExposesBoundedReadOnlyAPI(t *testing.T) {
	store := openTestStore(t)
	base := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	now := base.Add(5 * time.Minute)
	snapshotPath := t.TempDir() + "/ruleset.json"
	if err := os.WriteFile(snapshotPath, []byte(`{"nftables":[
{"table":{"family":"inet","name":"boetticher_filter","handle":1}},
{"chain":{"family":"inet","table":"boetticher_filter","name":"forward","handle":2}},
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","handle":3,"comment":"boetticher:allow:forward-sandbox-internet","expr":[{"counter":{"packets":5,"bytes":50}},{"accept":null}]}},
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","handle":4,"comment":"boetticher:drop:forward-sandbox-trusted","expr":[{"counter":{"packets":2,"bytes":20}},{"drop":null}]}}
]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(snapshotPath, now, now); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{SnapshotPath: snapshotPath, ListenAddress: "127.0.0.1", Port: 9765, Interval: time.Hour, AllowedSources: []string{"127.0.0.1/32"}, Now: func() time.Time { return now }}, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler := service.Handler()
	request := func(method, path string) *httptest.ResponseRecorder {
		record := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, nil)
		request.RemoteAddr = "127.0.0.1:1234"
		handler.ServeHTTP(record, request)
		return record
	}
	health := request(http.MethodGet, "/healthz")
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"healthy"`) {
		t.Fatalf("health = %d %s", health.Code, health.Body.String())
	}
	rules := request(http.MethodGet, "/api/v1/rules?limit=1")
	if rules.Code != http.StatusOK || !strings.Contains(rules.Body.String(), `"limit":1`) {
		t.Fatalf("rules = %d %s", rules.Code, rules.Body.String())
	}
	updated, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	updatedText := strings.Replace(string(updated), `"packets":5`, `"packets":8`, 1)
	updatedText = strings.Replace(updatedText, `"bytes":50`, `"bytes":80`, 1)
	updatedText = strings.Replace(updatedText, `"packets":2`, `"packets":5`, 1)
	updatedText = strings.Replace(updatedText, `"bytes":20`, `"bytes":50`, 1)
	if err := os.WriteFile(snapshotPath, []byte(updatedText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(snapshotPath, now, now); err != nil {
		t.Fatal(err)
	}
	if err := service.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	activity := request(http.MethodGet, "/api/v1/rules/forward-sandbox-internet/activity?window=5m")
	if activity.Code != http.StatusOK || !strings.Contains(activity.Body.String(), `"packet_delta":3`) {
		t.Fatalf("activity = %d %s", activity.Code, activity.Body.String())
	}
	summary := request(http.MethodGet, "/api/v1/summary")
	if summary.Code != http.StatusOK || !strings.Contains(summary.Body.String(), `"accepted_packets":3`) || !strings.Contains(summary.Body.String(), `"dropped_packets":3`) {
		t.Fatalf("summary = %d %s", summary.Code, summary.Body.String())
	}
	if events := request(http.MethodGet, "/api/v1/events?since=2026-08-27T23:00:00Z&limit=1"); events.Code != http.StatusOK {
		t.Fatalf("events = %d %s", events.Code, events.Body.String())
	}
	if method := request(http.MethodPost, "/api/v1/summary"); method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST was not rejected: %d", method.Code)
	}
	for _, path := range []string{"/api/v1/rules/../activity?window=5m", "/api/v1/rules/forward-sandbox-internet/activity?window=999h", "/api/v1/rules?limit=100000", "/api/v1/events?since=not-a-time", "/api/v1/summary?query=unbounded"} {
		if response := request(http.MethodGet, path); response.Code != http.StatusBadRequest && response.Code != http.StatusNotFound {
			t.Fatalf("unsafe/bounded path %q returned %d: %s", path, response.Code, response.Body.String())
		}
	}
	if response := request(http.MethodGet, "/api/v1/rules?limit=1&limit=2"); response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate bounded query returned %d: %s", response.Code, response.Body.String())
	}
}

func TestServiceRejectsUnauthorizedNetworkSourcesAndMissingSnapshotSafely(t *testing.T) {
	store := openTestStore(t)
	service, err := New(Config{SnapshotPath: t.TempDir() + "/missing", ListenAddress: "10.10.10.1", Port: 9765, AllowedSources: []string{"10.10.10.20/32"}}, store)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.RemoteAddr = "10.10.10.21:1234"
	record := httptest.NewRecorder()
	service.Handler().ServeHTTP(record, request)
	if record.Code != http.StatusForbidden {
		t.Fatalf("unauthorized source status = %d", record.Code)
	}
	if err := service.CollectOnce(context.Background()); err == nil {
		t.Fatal("missing nft snapshot was accepted")
	}
	health, err := store.Health(time.Now().UTC())
	if err != nil || health.Status != "degraded" || health.LastError == "" {
		t.Fatalf("missing snapshot health = %#v, %v", health, err)
	}
}

func TestServiceConfigRejectsInvalidAllowedSource(t *testing.T) {
	store := openTestStore(t)
	if _, err := New(Config{SnapshotPath: "/run/boetticher/firewall-ruleset.json", ListenAddress: "10.10.10.1", Port: 9765, AllowedSources: []string{"10.10.10.20/24"}}, store); err == nil {
		t.Fatal("non-canonical allowed source was accepted")
	}
}

func TestServiceMarksStaleSnapshotDegraded(t *testing.T) {
	store := openTestStore(t)
	snapshotPath := t.TempDir() + "/ruleset.json"
	if err := os.WriteFile(snapshotPath, []byte(`{"nftables":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-SnapshotMaxAge - time.Second)
	if err := os.Chtimes(snapshotPath, old, old); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{SnapshotPath: snapshotPath, ListenAddress: "127.0.0.1", Port: 9765, AllowedSources: []string{"127.0.0.1/32"}, Now: func() time.Time { return now }}, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CollectOnce(context.Background()); err == nil {
		t.Fatal("stale nft snapshot was accepted")
	}
	health, err := store.Health(now)
	if err != nil || health.Status != "degraded" || !strings.Contains(health.LastError, "stale") {
		t.Fatalf("stale snapshot health = %#v, %v", health, err)
	}
}
