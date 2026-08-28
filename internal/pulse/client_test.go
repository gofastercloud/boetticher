package pulse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func fakeResponse(request *http.Request, status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header, len(headers))
	for key, value := range headers {
		if key == "Set-Cookie" && strings.Contains(value, ", ") {
			for _, cookie := range strings.Split(value, ", ") {
				header.Add(key, cookie)
			}
			continue
		}
		header.Set(key, value)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func TestPlanPreservesCoreMonitoringIdentityAndGenericProjection(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	var monitor model.Component
	for _, component := range plan.Components {
		if component.Name == "lab-monitor-01" {
			monitor = component
		}
	}
	if monitor.Name == "" {
		t.Fatalf("monitoring component is absent: %#v", plan.Components)
	}
	if monitor.VMID != model.MonitorVMID || monitor.Address != "10.10.10.20" || !monitor.ProductOwned {
		t.Fatalf("monitoring ownership/network identity changed: %#v", monitor)
	}
	if len(plan.AvailabilityChecks) != 2 || plan.AvailabilityChecks[0].Name != "dns01-authoritative" || plan.AvailabilityChecks[1].Name != "dns02-authoritative" {
		t.Fatalf("unexpected bounded availability projection: %#v", plan.AvailabilityChecks)
	}
	for _, check := range plan.AvailabilityChecks {
		if check.Name == "portal" || check.Name == "monitoring" {
			t.Fatalf("mTLS endpoint availability check was projected: %#v", check)
		}
	}
}

func TestReadAPIUsesMonitoringTokenAndParsesBoundedEndpoints(t *testing.T) {
	transport := fakeTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-API-Token") != "read-token" {
			return fakeResponse(r, http.StatusUnauthorized, "missing token", nil), nil
		}
		switch r.URL.Path {
		case "/api/health":
			return fakeResponse(r, http.StatusOK, `{"status":"healthy"}`, nil), nil
		case "/api/state/summary":
			return fakeResponse(r, http.StatusOK, `{"activeAlerts":2,"nodes":1,"vms":2,"containers":3,"dockerHosts":[],"lastUpdate":"2026-08-28T00:00:00Z"}`, nil), nil
		case "/api/resources":
			if r.URL.Query().Get("source") != "proxmox" || r.URL.Query().Get("limit") != "100" {
				return fakeResponse(r, http.StatusBadRequest, "unexpected query", nil), nil
			}
			return fakeResponse(r, http.StatusOK, `{"data":[{"id":"node/pve","type":"node","name":"pve","source":"proxmox","status":"online"},{"id":"vm/120","type":"vm","name":"lab-monitor-01","source":"proxmox","status":"running"}]}`, nil), nil
		default:
			return fakeResponse(r, http.StatusNotFound, "not found", nil), nil
		}
	})
	client, err := NewReadClient(ClientConfig{BaseURL: "https://monitor.example.test", APIToken: "read-token", HTTP: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	health, err := client.Health(context.Background())
	if err != nil || health.Status != "healthy" {
		t.Fatalf("Health() = %#v, %v", health, err)
	}
	summary, err := client.StateSummary(context.Background())
	if err != nil || summary.VMs != 2 || summary.LastUpdate.IsZero() {
		t.Fatalf("StateSummary() = %#v, %v", summary, err)
	}
	resources, err := client.Resources(context.Background())
	if err != nil || len(resources.Data) != 2 || resources.Data[1].Name != "lab-monitor-01" {
		t.Fatalf("Resources() = %#v, %v", resources, err)
	}
}

func TestReadAPIRejectsMissingTokenAndMalformedResponses(t *testing.T) {
	if _, err := NewReadClient(ClientConfig{BaseURL: "https://monitor.example.test"}); err == nil {
		t.Fatal("read client accepted a missing token")
	}
	client, err := NewReadClient(ClientConfig{
		BaseURL: "https://monitor.example.test", APIToken: "read-token",
		HTTP: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
			return fakeResponse(r, http.StatusOK, "{malformed", nil), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "decode Pulse response") {
		t.Fatalf("malformed health response was accepted: %v", err)
	}
}

func TestAPIErrorDoesNotEchoConfiguredToken(t *testing.T) {
	client, err := NewReadClient(ClientConfig{
		BaseURL: "https://monitor.example.test", APIToken: "read-token",
		HTTP: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
			return fakeResponse(r, http.StatusUnauthorized, `{"echo":"read-token"}`, nil), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Health(context.Background())
	if err == nil || strings.Contains(err.Error(), "read-token") {
		t.Fatalf("API error exposed the configured token: %v", err)
	}
}

func TestIsUnauthorizedRecognizesWrappedAPIError(t *testing.T) {
	if !IsUnauthorized(fmt.Errorf("state check: %w", &apiError{Status: http.StatusUnauthorized})) {
		t.Fatal("wrapped unauthorized Pulse API error was not recognized")
	}
	if IsUnauthorized(fmt.Errorf("state check: %w", &apiError{Status: http.StatusForbidden})) {
		t.Fatal("forbidden Pulse API error was classified as unauthorized")
	}
}

func TestAdminConfiguresPVEThroughAuthenticatedAPIAndCreatesReadToken(t *testing.T) {
	configured := false
	transport := fakeTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/login":
			return fakeResponse(r, http.StatusOK, `{"authenticated":true}`, map[string]string{"Set-Cookie": "pulse_session=session; Path=/, pulse_csrf=csrf; Path=/"}), nil
		case "/api/config/nodes":
			if r.Method == http.MethodGet {
				if !configured {
					return fakeResponse(r, http.StatusOK, `[]`, nil), nil
				}
				return fakeResponse(r, http.StatusOK, `[{"type":"pve","name":"lab-proxmox-01","host":"https://pve.example.test:8006","verifySSL":true,"monitorPhysicalDisks":false,"temperatureMonitoringEnabled":false}]`, nil), nil
			}
			if r.Header.Get("X-CSRF-Token") != "csrf" {
				return fakeResponse(r, http.StatusForbidden, "missing csrf", nil), nil
			}
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				return fakeResponse(r, http.StatusBadRequest, "bad body", nil), nil
			}
			if request["type"] != "pve" || request["tokenId"] != "pulse-monitor@pve!boetticher-monitoring" || request["tokenSecret"] != "proxmox-token" || request["verifySSL"] != true || request["temperatureMonitoringEnabled"] != false {
				return fakeResponse(r, http.StatusBadRequest, "unexpected config", nil), nil
			}
			if _, present := request["monitorTemperatures"]; present {
				return fakeResponse(r, http.StatusBadRequest, "unsupported temperature field", nil), nil
			}
			configured = true
			return fakeResponse(r, http.StatusCreated, `{}`, nil), nil
		case "/api/security/tokens":
			if r.Header.Get("X-CSRF-Token") != "csrf" {
				return fakeResponse(r, http.StatusForbidden, "missing csrf", nil), nil
			}
			var request struct {
				Name   string   `json:"name"`
				Scopes []string `json:"scopes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Scopes) != 1 {
				return fakeResponse(r, http.StatusBadRequest, "unexpected token scope", nil), nil
			}
			switch request.Name {
			case "boetticher monitoring read":
				if request.Scopes[0] != "monitoring:read" {
					return fakeResponse(r, http.StatusBadRequest, "unexpected read scope", nil), nil
				}
				return fakeResponse(r, http.StatusOK, `{"token":"read-token","record":{"scopes":["monitoring:read"]}}`, nil), nil
			case "boetticher monitoring agent":
				if request.Scopes[0] != "agent:report" {
					return fakeResponse(r, http.StatusBadRequest, "unexpected agent scope", nil), nil
				}
				return fakeResponse(r, http.StatusOK, `{"token":"agent-token","record":{"scopes":["agent:report"]}}`, nil), nil
			default:
				return fakeResponse(r, http.StatusBadRequest, "unexpected token name", nil), nil
			}
		default:
			return fakeResponse(r, http.StatusNotFound, "not found", nil), nil
		}
	})
	client, err := NewAdminClient(ClientConfig{BaseURL: "https://monitor.example.test", AdminUser: "admin", AdminPassword: "admin-pass", HTTP: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigureProxmox(context.Background(), PVEConfig{
		Name: "lab-proxmox-01", Host: "https://pve.example.test:8006", TokenID: "pulse-monitor@pve!boetticher-monitoring", TokenSecret: "proxmox-token", VerifySSL: true,
		MonitorVMs: true, MonitorContainers: true, MonitorStorage: true, MonitorBackups: true,
	}); err != nil {
		t.Fatal(err)
	}
	token, err := client.CreateReadToken(context.Background(), "boetticher monitoring read")
	if err != nil || token != "read-token" {
		t.Fatalf("CreateReadToken() = %q, %v", token, err)
	}
	agentToken, err := client.CreateAgentReportToken(context.Background(), "boetticher monitoring agent")
	if err != nil || agentToken != "agent-token" {
		t.Fatalf("CreateAgentReportToken() = %q, %v", agentToken, err)
	}
}

func TestAdminRefusesWrongExistingPVEEndpoint(t *testing.T) {
	client, err := NewAdminClient(ClientConfig{
		BaseURL: "https://monitor.example.test", AdminUser: "admin", AdminPassword: "admin-pass",
		HTTP: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/api/login" {
				return fakeResponse(r, http.StatusOK, `{}`, map[string]string{"Set-Cookie": "pulse_csrf=csrf; Path=/"}), nil
			}
			return fakeResponse(r, http.StatusOK, `[{"type":"pve","name":"lab-proxmox-01","host":"https://wrong.example.test:8006","verifySSL":true}]`, nil), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.ConfigureProxmox(context.Background(), PVEConfig{Name: "lab-proxmox-01", Host: "https://pve.example.test:8006", TokenID: "id", TokenSecret: "secret", VerifySSL: true})
	if err == nil || !strings.Contains(err.Error(), "different Proxmox endpoint") {
		t.Fatalf("wrong Proxmox endpoint was accepted: %v", err)
	}
}
