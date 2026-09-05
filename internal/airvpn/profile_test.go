package airvpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
		if r.URL.Path != "/generator/" || r.Header.Get("Api-Key") != "controller-key" || r.Header.Get("Accept") != "" {
			t.Fatalf("unexpected generator request: path=%q api-key=%q accept=%q", r.URL.Path, r.Header.Get("Api-Key"), r.Header.Get("Accept"))
		}
		want := map[string]string{
			"protocols":     "wireguard_1_udp_1637",
			"servers":       "europe",
			"device":        "default",
			"resolve":       "on",
			"iplayer_entry": "ipv4",
		}
		for key, value := range want {
			if r.URL.Query().Get(key) != value {
				t.Fatalf("query %s=%q, want %q", key, r.URL.Query().Get(key), value)
			}
		}
		for _, key := range []string{"system", "wireguard_mtu", "wireguard_persistent_keepalive"} {
			if value := r.URL.Query().Get(key); value != "" {
				t.Fatalf("query %s=%q, want it omitted", key, value)
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

func TestGenerateDownloadsFirstProfileFromProviderManifest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/generator/" || r.Header.Get("Api-Key") != "controller-key" {
			t.Fatalf("unexpected generator request: path=%q api-key=%q", r.URL.Path, r.Header.Get("Api-Key"))
		}
		if r.URL.Query().Get("protocols") != "wireguard_1_udp_1637" || r.URL.Query().Get("servers") != "japan" || r.URL.Query().Get("device") != "default" {
			t.Fatalf("unexpected generator query: %q", r.URL.RawQuery)
		}
		requests++
		switch r.URL.Query().Get("download") {
		case "":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":"ok","files":["provider-private.conf"],"options":{"protocols":"wireguard_1_udp_1637","servers":"japan","device":"default"}}`))
		case "0":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(testProfile()))
		default:
			t.Fatalf("unexpected manifest download index: %q", r.URL.Query().Get("download"))
		}
	}))
	defer server.Close()

	observer := &eventObserver{}
	ctx := telemetry.WithObserver(context.Background(), observer)
	profile, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(ctx, "controller-key", "japan")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || profile.Metadata.EndpointPort != DefaultPort || strings.Contains(profile.Config, "provider-private") {
		t.Fatalf("manifest profile was not fetched safely: requests=%d profile=%#v", requests, profile.Metadata)
	}
	operations := map[string]bool{}
	for _, event := range observer.events {
		operations[event.Operation] = event.Success
	}
	if len(observer.events) != 2 || !operations["generate_profile"] || !operations["download_profile"] {
		t.Fatalf("unexpected provider telemetry: %+v", observer.events)
	}
}

func TestGenerateRetriesOpaqueProviderErrorWithManagedAirVPNDevice(t *testing.T) {
	deviceLists := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generator/":
			switch r.URL.Query().Get("device") {
			case defaultDeviceName:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"error":"device default is unavailable"}`))
			case managedDeviceName:
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(testProfile()))
			default:
				t.Fatalf("unexpected AirVPN device selector: %q", r.URL.Query().Get("device"))
			}
		case "/status/":
			_, _ = w.Write([]byte(`{"servers":[{"public_name":"Ainalrami","country_name":"Japan","country_code":"jp","continent":"Asia","health":"ok"}]}`))
		case "/userinfo/":
			_, _ = w.Write([]byte(`{"user":{"premium":true}}`))
		case "/devices/":
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["action"] != "list" {
				t.Fatalf("unexpected AirVPN device request: request=%v error=%v", request, err)
			}
			deviceLists++
			if deviceLists == 1 {
				_, _ = w.Write([]byte(`{"devices":[{"status":"ready"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"devices":[{"name":"boetticher-airvpn","description":"Boetticher AirVPN transit","status":"ready"}]}`))
		default:
			t.Fatalf("unexpected AirVPN request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	profile, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "japan")
	if err != nil || deviceLists != 2 || profile.Metadata.EndpointPort != DefaultPort {
		t.Fatalf("managed AirVPN retry failed: profile=%#v device-lists=%d error=%v", profile.Metadata, deviceLists, err)
	}
}

func TestGenerateExplainsLegacyGeneratorAuthorizationWithoutCreatingAirVPNDevice(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/generator/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"Authorization required"}`))
		case "/userinfo/":
			_, _ = w.Write([]byte(`{"user":null}`))
		case "/devices/", "/status/":
			t.Fatalf("authorization failure must not inspect devices or public status: %s", r.URL.Path)
		default:
			t.Fatalf("unexpected AirVPN request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "japan")
	if err == nil || !strings.Contains(err.Error(), "did not authorize the controller API key") || strings.Contains(err.Error(), "Authorization required") || strings.Contains(err.Error(), "controller-key") || requests != 2 {
		t.Fatalf("generator authorization was not safely explained: requests=%d error=%v", requests, err)
	}
}

func TestGenerateDoesNotCreateAirVPNDeviceForUnclassifiedProviderJSON(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/generator/" {
			t.Fatalf("unclassified provider result must not trigger follow-up requests: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"provider-private-condition"}`))
	}))
	defer server.Close()

	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "japan")
	if err == nil || !strings.Contains(err.Error(), "unclassified provider result") || strings.Contains(err.Error(), "provider-private-condition") || strings.Contains(err.Error(), "controller-key") || requests != 1 {
		t.Fatalf("unclassified provider result was not safely contained: requests=%d error=%v", requests, err)
	}
}

func TestEnsureManagedAirVPNDeviceCreatesOnlyItsOwnDevice(t *testing.T) {
	deviceLists := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/devices/" || r.Method != http.MethodPost || r.Header.Get("Api-Key") != "controller-key" {
			t.Fatalf("unexpected AirVPN device request: path=%q method=%q api-key=%q", r.URL.Path, r.Method, r.Header.Get("Api-Key"))
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode AirVPN device request: %v", err)
		}
		switch request["action"] {
		case "list":
			deviceLists++
			if deviceLists == 1 {
				_, _ = w.Write([]byte(`{"devices":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"devices":[{"id":"private-id","name":"boetticher-airvpn","description":"Boetticher AirVPN transit","status":"ready"}]}`))
		case "add":
			_, _ = w.Write([]byte(`{"id":"private-id"}`))
		case "modify":
			if request["id"] != "private-id" || request["name"] != managedDeviceName || request["description"] != managedDeviceNote {
				t.Fatalf("unexpected managed-device mutation: %v", request)
			}
			_, _ = w.Write([]byte(`{"result":"ok"}`))
		default:
			t.Fatalf("unexpected AirVPN device action: %q", request["action"])
		}
	}))
	defer server.Close()

	device, err := (Client{}).ensureManagedDevice(context.Background(), server.URL, "controller-key", server.Client())
	if err != nil || device != managedDeviceName || deviceLists != 2 {
		t.Fatalf("managed AirVPN device was not created safely: device=%q lists=%d error=%v", device, deviceLists, err)
	}
}

func TestEnsureManagedAirVPNDeviceReadinessWaitRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("cancelled readiness wait must not call AirVPN")
	}))
	defer server.Close()

	_, err := (Client{}).waitForManagedDevice(ctx, server.URL, "controller-key", server.Client())
	if err != context.Canceled {
		t.Fatalf("managed AirVPN readiness cancellation = error %v", err)
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

func TestProviderResponseSummaryClassifiesJSONProviderErrorWithoutLeakingIt(t *testing.T) {
	summary := providerResponseSummary("application/json", []byte(`{"message":"device default is unavailable for controller-key"}`))
	if !strings.Contains(summary, "content_type=application/json") || !strings.Contains(summary, "shape=json-device") || strings.Contains(summary, "device default") || strings.Contains(summary, "controller-key") {
		t.Fatalf("JSON provider error was not safely classified: %q", summary)
	}
}

func TestProviderResponseSummaryClassifiesNestedJSONProviderErrorWithoutLeakingIt(t *testing.T) {
	summary := providerResponseSummary("application/json", []byte(`{"error":{"detail":"server selector is unavailable for controller-key"}}`))
	if !strings.Contains(summary, "shape=json-server-selector") || strings.Contains(summary, "server selector") || strings.Contains(summary, "controller-key") {
		t.Fatalf("nested JSON provider error was not safely classified: %q", summary)
	}
}

func TestProviderJSONErrorCategoryRecognizesOpaqueProviderPrerequisites(t *testing.T) {
	cases := map[string]string{
		`{"error":"invalid key"}`:                      "api-key",
		`{"error":"invalid generator parameter"}`:      "request",
		`{"error":"active access is required"}`:        "account",
		`{"error":"selected user key is unavailable"}`: "device",
	}
	for response, want := range cases {
		if got := providerJSONErrorCategory([]byte(response)); got != want {
			t.Fatalf("provider error category for %s = %q, want %q", response, got, want)
		}
	}
}

func TestProviderUserinfoStatusRequiresAnAuthenticatedUserObject(t *testing.T) {
	cases := []struct {
		response                                             string
		authenticated, subscriptionKnown, subscriptionActive bool
	}{
		{response: `{"user":{"connected":false}}`, authenticated: true},
		{response: `{"user":{"premium":true}}`, authenticated: true, subscriptionKnown: true, subscriptionActive: true},
		{response: `{"user":{"premium":false}}`, authenticated: true, subscriptionKnown: true},
		{response: `{"user":null}`},
		{response: `{"user":"private-data"}`},
		{response: `{"status":"ok"}`},
	}
	for _, test := range cases {
		authenticated, subscriptionKnown, subscriptionActive := providerUserinfoStatus([]byte(test.response))
		if authenticated != test.authenticated || subscriptionKnown != test.subscriptionKnown || subscriptionActive != test.subscriptionActive {
			t.Fatalf("userinfo status for %s = %t, %t, %t; want %t, %t, %t", test.response, authenticated, subscriptionKnown, subscriptionActive, test.authenticated, test.subscriptionKnown, test.subscriptionActive)
		}
	}
}

func TestProviderReadinessRejectsAnonymousUserinfoWithoutListingDevices(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo/":
			if r.Header.Get("Api-Key") != "controller-key" {
				t.Fatalf("userinfo missed API key")
			}
			_, _ = w.Write([]byte(`{"user":null}`))
		case "/devices/":
			t.Fatal("AirVPN devices must not be listed for anonymous userinfo")
		default:
			t.Fatalf("unexpected AirVPN readiness request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	readiness, err := (Client{}).providerReadiness(context.Background(), server.URL, "controller-key", server.Client())
	if err != nil || readiness.APIKeyAccepted || readiness.DeviceCount != 0 {
		t.Fatalf("anonymous userinfo readiness = %#v, %v", readiness, err)
	}
}

func TestProviderReadinessSeparatesReadyDevicesFromDeviceCount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo/":
			_, _ = w.Write([]byte(`{"user":{"premium":true}}`))
		case "/devices/":
			_, _ = w.Write([]byte(`{"devices":[{"status":"pending"}]}`))
		default:
			t.Fatalf("unexpected AirVPN readiness request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	readiness, err := (Client{}).providerReadiness(context.Background(), server.URL, "controller-key", server.Client())
	if err != nil || !readiness.APIKeyAccepted || !readiness.SubscriptionKnown || !readiness.SubscriptionActive || readiness.DeviceCount != 1 || readiness.HasReadyDevice {
		t.Fatalf("unexpected AirVPN readiness: %#v, %v", readiness, err)
	}
}

func TestGenerateExplainsInactiveAirVPNSubscriptionWithoutLeakingProviderData(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generator/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider-private-error"}`))
		case "/status/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"servers":[{"public_name":"Ainalrami","country_name":"Japan","country_code":"jp","continent":"Asia","health":"ok"}]}`))
		case "/userinfo/":
			_, _ = w.Write([]byte(`{"user":{"premium":false,"private":"provider-private-data"}}`))
		case "/devices/":
			_, _ = w.Write([]byte(`{"devices":[{"status":"ready"}]}`))
		default:
			t.Fatalf("unexpected AirVPN readiness request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "japan")
	if err == nil || !strings.Contains(err.Error(), "account has no active premium access") || strings.Contains(err.Error(), "provider-private") || strings.Contains(err.Error(), "controller-key") {
		t.Fatalf("inactive AirVPN subscription was not safely explained: %v", err)
	}
}

func TestGenerateExplainsUnreadableAirVPNDeviceReadinessWithoutLeakingProviderData(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generator/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider-private-error"}`))
		case "/status/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"servers":[{"public_name":"Ainalrami","country_name":"Japan","country_code":"jp","continent":"Asia","health":"ok"}]}`))
		case "/userinfo/":
			_, _ = w.Write([]byte(`{"user":{"premium":true,"private":"provider-private-data"}}`))
		case "/devices/":
			_, _ = w.Write([]byte(`{"devices":"provider-private-data"}`))
		default:
			t.Fatalf("unexpected AirVPN readiness request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "japan")
	if err == nil || !strings.Contains(err.Error(), "account readiness check failed") || !strings.Contains(err.Error(), "parse AirVPN devices") || strings.Contains(err.Error(), "provider-private") || strings.Contains(err.Error(), "controller-key") {
		t.Fatalf("unreadable AirVPN device readiness was not safely explained: %v", err)
	}
}

func TestGenerateExplainsUnavailableSelectorAgainstLiveStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generator/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"selection unavailable"}`))
		case "/status/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"servers":[{"public_name":"Ainalrami","country_name":"Japan","country_code":"jp","continent":"Asia","health":"ok"}]}`))
		default:
			t.Fatalf("unexpected AirVPN status request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "australia")
	if err == nil || !strings.Contains(err.Error(), `selector "australia" currently has no live provider servers`) || strings.Contains(err.Error(), "selection unavailable") {
		t.Fatalf("unavailable AirVPN selector was not safely explained: %v", err)
	}
}

func TestGenerateExplainsMissingAirVPNDevicesWithoutLeakingProviderData(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generator/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider-private-error"}`))
		case "/status/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"servers":[{"public_name":"Ainalrami","country_name":"Japan","country_code":"jp","continent":"Asia","health":"ok"}]}`))
		case "/userinfo/":
			if r.Method != http.MethodGet || r.Header.Get("Api-Key") != "controller-key" || r.URL.Query().Get("format") != "json" {
				t.Fatalf("unexpected AirVPN userinfo request: method=%s api-key=%q query=%q", r.Method, r.Header.Get("Api-Key"), r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"user":{"private":"provider-private-data"}}`))
		case "/devices/":
			if r.Method != http.MethodPost || r.Header.Get("Api-Key") != "controller-key" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected AirVPN devices request: method=%s api-key=%q content-type=%q", r.Method, r.Header.Get("Api-Key"), r.Header.Get("Content-Type"))
			}
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["action"] != "list" || request["format"] != "json" {
				t.Fatalf("unexpected AirVPN devices body: request=%v error=%v", request, err)
			}
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			t.Fatalf("unexpected AirVPN readiness request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "japan")
	if err == nil || !strings.Contains(err.Error(), "API key is accepted but the account has no AirVPN devices") || strings.Contains(err.Error(), "provider-private") || strings.Contains(err.Error(), "controller-key") {
		t.Fatalf("missing AirVPN device diagnostic was not safely explained: %v", err)
	}
}

func TestGenerateExplainsRejectedAirVPNAPIKeyWithoutCallingDevices(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generator/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider-private-error"}`))
		case "/status/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"servers":[{"public_name":"Ainalrami","country_name":"Japan","country_code":"jp","continent":"Asia","health":"ok"}]}`))
		case "/userinfo/":
			if r.Method != http.MethodGet || r.Header.Get("Api-Key") != "controller-key" || r.URL.Query().Get("format") != "json" {
				t.Fatalf("unexpected AirVPN userinfo request: method=%s api-key=%q query=%q", r.Method, r.Header.Get("Api-Key"), r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"provider-private-error"}`))
		case "/devices/":
			t.Fatal("AirVPN device list must not run after a rejected API key")
		default:
			t.Fatalf("unexpected AirVPN readiness request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := (Client{BaseURL: server.URL, HTTPClient: server.Client()}).Generate(context.Background(), "controller-key", "japan")
	if err == nil || !strings.Contains(err.Error(), "AirVPN API key was not accepted") || strings.Contains(err.Error(), "provider-private") || strings.Contains(err.Error(), "controller-key") {
		t.Fatalf("rejected AirVPN API key was not safely explained: %v", err)
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

func TestParseProfileNormalizesDualStackInterfaceToIPv4(t *testing.T) {
	value := strings.Replace(testProfile(), "Address = 10.64.12.3/32", "Address = 10.64.12.3/32, fd7d::1234/128", 1)
	profile, err := ParseProfile([]byte(value))
	if err != nil {
		t.Fatalf("dual-stack AirVPN profile was rejected: %v", err)
	}
	if !strings.Contains(profile.Config, "Address = 10.64.12.3/32\n") || strings.Contains(profile.Config, "fd7d::1234") {
		t.Fatalf("normalized profile retained an IPv6 interface address: %s", profile.Config)
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
