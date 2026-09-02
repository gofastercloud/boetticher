package airvpn

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/telemetry"
)

type eventObserver struct {
	events []telemetry.Event
}

func (o *eventObserver) Observe(event telemetry.Event) {
	o.events = append(o.events, event)
}

func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(value), 32)))
}

func testProfile() string {
	return "[Interface]\nPrivateKey = " + testKey('p') + "\nAddress = 10.64.12.3/32\nDNS = 10.10.10.10\nMTU = 1320\n\n[Peer]\nPublicKey = " + testKey('u') + "\nPresharedKey = " + testKey('s') + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.44:1637\nPersistentKeepalive = 25\n"
}

func TestGenerateBuildsBoundedAirVPNRequestAndRedactsFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/generator/" || r.Header.Get("Api-Key") != "controller-key" || r.Header.Get("Accept") != "text/plain" {
			t.Fatalf("unexpected generator request: path=%q api-key=%q accept=%q", r.URL.Path, r.Header.Get("Api-Key"), r.Header.Get("Accept"))
		}
		want := map[string]string{
			"protocols":                      "wireguard_1_udp_1637",
			"servers":                        "europe",
			"device":                         "default",
			"system":                         "other",
			"resolve":                        "on",
			"iplayer_exit":                   "ipv4",
			"wireguard_mtu":                  "0",
			"wireguard_persistent_keepalive": "25",
		}
		for key, value := range want {
			if r.URL.Query().Get(key) != value {
				t.Fatalf("query %s=%q, want %q", key, r.URL.Query().Get(key), value)
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(testProfile()))
	}))
	defer server.Close()

	observer := &eventObserver{}
	ctx := telemetry.WithObserver(context.Background(), observer)
	profile, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(ctx, "controller-key", "europe")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Metadata.EndpointHost != "198.51.100.44" || profile.Metadata.EndpointPort != DefaultPort || profile.Metadata.TunnelAddress != "10.64.12.3/32" || len(profile.Metadata.SHA256) != 64 {
		t.Fatalf("unexpected public profile metadata: %#v", profile.Metadata)
	}
	if strings.Contains(profile.Config, "DNS") || !strings.Contains(profile.Config, "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("profile was not normalized: %q", profile.Config)
	}
	if len(observer.events) != 1 {
		t.Fatalf("provider API measurements = %+v, want one event", observer.events)
	}
	event := observer.events[0]
	if event.Category != "provider_api" || event.Operation != "generate_profile" || event.Target != "airvpn-generator" || event.Method != http.MethodGet || event.Status != http.StatusOK || !event.Success || event.Duration < 0 {
		t.Fatalf("unexpected provider API measurement: %+v", event)
	}
}

func TestGenerateDoesNotIncludeProviderResponseInError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("secret-provider-response"))
	}))
	defer server.Close()
	observer := &eventObserver{}
	ctx := telemetry.WithObserver(context.Background(), observer)
	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(ctx, "controller-key", "europe")
	if err == nil || strings.Contains(err.Error(), "secret-provider-response") || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("unexpected redaction result: %v", err)
	}
	if len(observer.events) != 1 || observer.events[0].Status != http.StatusUnauthorized || observer.events[0].Success {
		t.Fatalf("unexpected failed provider API measurement: %+v", observer.events)
	}
}

func TestGenerateDescribesInvalidProviderResponseWithoutLeakingIt(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>secret-provider-response</html>"))
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "europe")
	if err == nil || !strings.Contains(err.Error(), "content_type=text/html") || !strings.Contains(err.Error(), "shape=markup") || strings.Contains(err.Error(), "secret-provider-response") || strings.Contains(err.Error(), "controller-key") {
		t.Fatalf("invalid provider response was not safely described: %v", err)
	}
}

func TestGenerateClassifiesJSONProviderErrorWithoutLeakingIt(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"device default is unavailable for controller-key"}`))
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "europe")
	if err == nil || !strings.Contains(err.Error(), "content_type=application/json") || !strings.Contains(err.Error(), "shape=json-device") || strings.Contains(err.Error(), "device default") || strings.Contains(err.Error(), "controller-key") {
		t.Fatalf("JSON provider error was not safely classified: %v", err)
	}
}

func TestGenerateClassifiesNestedJSONProviderErrorWithoutLeakingIt(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":{"detail":"server selector is unavailable for controller-key"}}`))
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "europe")
	if err == nil || !strings.Contains(err.Error(), "shape=json-server-selector") || strings.Contains(err.Error(), "server selector") || strings.Contains(err.Error(), "controller-key") {
		t.Fatalf("nested JSON provider error was not safely classified: %v", err)
	}
}

func TestGenerateDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/leak", http.StatusFound)
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "europe")
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("unexpected redirect result: %v", err)
	}
}

func TestParseProfileRejectsUnsafeOrIncompleteProfiles(t *testing.T) {
	cases := []string{
		strings.Replace(testProfile(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0", 1),
		strings.Replace(testProfile(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, 10.10.0.0/16", 1),
		strings.Replace(testProfile(), "Endpoint = 198.51.100.44:1637", "Endpoint = 198.51.100.44:51820", 1),
		strings.Replace(testProfile(), "Endpoint = 198.51.100.44:1637", "Endpoint = [2001:db8::1]:1637", 1),
		strings.Replace(testProfile(), "MTU = 1320", "Hooks = unsafe", 1),
		strings.Replace(testProfile(), "PrivateKey = "+testKey('p'), "PrivateKey = not-a-key", 1),
	}
	for _, value := range cases {
		if _, err := ParseProfile([]byte(value)); err == nil {
			t.Fatalf("unsafe profile was accepted: %q", value)
		}
	}
}

func TestParseProfileAcceptsUTF8BOM(t *testing.T) {
	profile, err := ParseProfile(append([]byte{0xef, 0xbb, 0xbf}, []byte(testProfile())...))
	if err != nil {
		t.Fatalf("UTF-8 BOM-prefixed WireGuard profile was rejected: %v", err)
	}
	if profile.Metadata.EndpointHost != "198.51.100.44" {
		t.Fatalf("unexpected parsed profile metadata: %#v", profile.Metadata)
	}
}

func TestGenerateRejectsOversizedProviderResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxProfileBytes+1)))
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "europe")
	if err == nil || !strings.Contains(err.Error(), "exceeds the safe size limit") {
		t.Fatalf("unexpected oversized response result: %v", err)
	}
}
