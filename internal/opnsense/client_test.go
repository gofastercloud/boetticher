package opnsense

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) *http.Response

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request), nil
}

func TestClientUsesBasicAuthAndJSON(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		user, secret, ok := r.BasicAuth()
		if !ok || user != "automation" || secret != "opaque" {
			t.Errorf("unexpected Basic auth: %q %q %v", user, secret, ok)
		}
		if r.URL.Path != "/api/kea/service/reconfigure" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		return opnsenseResponse(`{"status":"ok","result":"reconfigured"}`)
	})
	client := &Client{BaseURL: "https://fw.example", User: "automation", Secret: "opaque", HTTP: &http.Client{Transport: transport}}
	if err := client.Post(context.Background(), DHCPv4Reconfigure, map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsUnmodelledEndpoint(t *testing.T) {
	client := &Client{BaseURL: "https://fw.example", User: "automation", Secret: "opaque", HTTP: http.DefaultClient}
	if err := client.Get(context.Background(), "/api/core/system/status", nil); err != nil {
		// This endpoint is still an API path; the transport may fail, but the
		// client must not reject it merely because it is a read operation.
		if strings.Contains(err.Error(), "must be an /api/") {
			t.Fatal(err)
		}
	}
	if err := client.Get(context.Background(), "/core/system/status", nil); err == nil || !strings.Contains(err.Error(), "must be an /api/") {
		t.Fatalf("expected path contract error, got %v", err)
	}
}

func opnsenseResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
