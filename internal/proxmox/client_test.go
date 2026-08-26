package proxmox

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

func TestClientUsesTokenAndDecodesEnvelope(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Header.Get("Authorization") != "PVEAPIToken=labadmin@pve!labinabox=secret" {
			t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api2/json/version" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		data, _ := json.Marshal(map[string]any{"data": map[string]string{"version": "8.4"}})
		return response(data)
	})
	client, err := NewClient(Config{BaseURL: "http://127.0.0.1:8006", User: "labadmin@pve", TokenID: "labinabox", TokenSecret: "secret"})
	if err == nil {
		t.Fatal("insecure HTTP base URL was accepted")
	}
	client = &Client{BaseURL: "https://127.0.0.1:8006/api2/json", Token: "PVEAPIToken=labadmin@pve!labinabox=secret", HTTP: &http.Client{Transport: transport}}
	version, err := client.Version(context.Background())
	if err != nil || version != "8.4" {
		t.Fatalf("Version() = %q, %v", version, err)
	}
}

func TestCreateTokenUsesFormEncoding(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("privsep") != "1" {
			t.Errorf("unexpected form: %v", r.Form)
		}
		data, _ := json.Marshal(map[string]any{"data": map[string]string{"value": "token-secret"}})
		return response(data)
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	secret, err := client.CreateToken(context.Background(), "labadmin@pve", "labinabox")
	if err != nil || secret != "token-secret" {
		t.Fatalf("CreateToken() = %q, %v", secret, err)
	}
}

func response(data []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}
}
