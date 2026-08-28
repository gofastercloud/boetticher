package pulse

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	readScope        = "monitoring:read"
	writeScope       = "monitoring:write"
	agentReportScope = "agent:report"
	maxResponseSize  = 4 << 20
)

type ClientConfig struct {
	BaseURL       string
	APIToken      string
	AdminUser     string
	AdminPassword string
	CAFile        string
	CAPEM         string
	ClientCertPEM string
	ClientKeyPEM  string
	ServerName    string
	Insecure      bool
	Timeout       time.Duration
	HTTP          *http.Client
}

type Client struct {
	baseURL       string
	apiToken      string
	adminUser     string
	adminPassword string
	http          *http.Client
	admin         bool
	loggedIn      bool
	csrfToken     string
}

type PVEConfig struct {
	Name                 string
	Host                 string
	TokenID              string
	TokenSecret          string
	VerifySSL            bool
	MonitorVMs           bool
	MonitorContainers    bool
	MonitorStorage       bool
	MonitorBackups       bool
	MonitorPhysicalDisks bool
	MonitorTemperatures  bool
}

type HealthStatus struct {
	Status string `json:"status"`
}

type StateSummary struct {
	ActiveAlerts int                 `json:"activeAlerts"`
	Nodes        int                 `json:"nodes"`
	VMs          int                 `json:"vms"`
	Containers   int                 `json:"containers"`
	DockerHosts  []DockerHostSummary `json:"dockerHosts"`
	LastUpdate   time.Time           `json:"lastUpdate"`
}

type DockerHostSummary struct {
	Name       string `json:"name"`
	Containers int    `json:"containers"`
}

type Resource struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Source string `json:"source"`
	Status string `json:"status"`
}

type ResourcesResponse struct {
	Data []Resource `json:"data"`
}

type apiError struct {
	Status int
}

func (e *apiError) Error() string {
	return fmt.Sprintf("Pulse API returned HTTP %d", e.Status)
}

func NewReadClient(config ClientConfig) (*Client, error) {
	if strings.TrimSpace(config.APIToken) == "" {
		return nil, errors.New("Pulse read client requires an API token")
	}
	client, err := newClient(config)
	if err != nil {
		return nil, err
	}
	client.apiToken = config.APIToken
	return client, nil
}

func NewAdminClient(config ClientConfig) (*Client, error) {
	if strings.TrimSpace(config.AdminUser) == "" || config.AdminPassword == "" {
		return nil, errors.New("Pulse admin client requires a username and password")
	}
	client, err := newClient(config)
	if err != nil {
		return nil, err
	}
	client.admin = true
	client.adminUser = config.AdminUser
	client.adminPassword = config.AdminPassword
	return client, nil
}

func newClient(config ClientConfig) (*Client, error) {
	if config.Insecure {
		return nil, errors.New("Pulse client refuses disabled TLS verification")
	}
	baseURL, err := normalizeBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Pulse base URL: %w", err)
	}
	if parsedBaseURL.Scheme != "https" && config.HTTP == nil {
		return nil, errors.New("Pulse production client requires an HTTPS base URL")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: config.ServerName,
	}
	if config.CAFile != "" {
		data, readErr := os.ReadFile(config.CAFile)
		if readErr != nil {
			return nil, fmt.Errorf("read Pulse CA file: %w", readErr)
		}
		if err := appendCA(transport.TLSClientConfig, data); err != nil {
			return nil, fmt.Errorf("load Pulse CA file: %w", err)
		}
	}
	if config.CAPEM != "" {
		if err := appendCA(transport.TLSClientConfig, []byte(config.CAPEM)); err != nil {
			return nil, fmt.Errorf("load Pulse CA PEM: %w", err)
		}
	}
	if config.ClientCertPEM != "" || config.ClientKeyPEM != "" {
		certificate, certErr := tls.X509KeyPair([]byte(config.ClientCertPEM), []byte(config.ClientKeyPEM))
		if certErr != nil {
			return nil, fmt.Errorf("load Pulse client certificate: %w", certErr)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	}
	httpClient := config.HTTP
	if httpClient == nil {
		timeout := config.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		httpClient = &http.Client{Transport: transport, Timeout: timeout}
	}
	if httpClient.Jar == nil {
		jar, jarErr := cookiejar.New(nil)
		if jarErr != nil {
			return nil, fmt.Errorf("create Pulse cookie jar: %w", jarErr)
		}
		httpClient.Jar = jar
	}
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

func normalizeBaseURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(value), "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("Pulse base URL must be an absolute URL")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/api"
	} else if strings.TrimRight(parsed.Path, "/") != "/api" {
		return "", errors.New("Pulse base URL must point to the Pulse endpoint or /api")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func appendCA(config *tls.Config, pemData []byte) error {
	if config.RootCAs == nil {
		config.RootCAs = x509.NewCertPool()
	}
	if !config.RootCAs.AppendCertsFromPEM(pemData) {
		return errors.New("PEM contains no certificates")
	}
	return nil
}

func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	var health HealthStatus
	if err := c.getJSON(ctx, "/health", &health); err != nil {
		return HealthStatus{}, fmt.Errorf("read Pulse health: %w", err)
	}
	if strings.TrimSpace(health.Status) == "" {
		return HealthStatus{}, errors.New("Pulse health response has no status")
	}
	return health, nil
}

func (c *Client) StateSummary(ctx context.Context) (StateSummary, error) {
	var summary StateSummary
	if err := c.getJSON(ctx, "/state/summary", &summary); err != nil {
		return StateSummary{}, fmt.Errorf("read Pulse state summary: %w", err)
	}
	if summary.LastUpdate.IsZero() {
		return StateSummary{}, errors.New("Pulse state summary has no lastUpdate")
	}
	return summary, nil
}

func (c *Client) Resources(ctx context.Context) (ResourcesResponse, error) {
	var resources ResourcesResponse
	if err := c.getJSON(ctx, "/resources?source=proxmox&limit=100", &resources); err != nil {
		return ResourcesResponse{}, fmt.Errorf("read Pulse resources: %w", err)
	}
	if resources.Data == nil {
		return ResourcesResponse{}, errors.New("Pulse resources response has no data")
	}
	return resources, nil
}

func (c *Client) ConfigureProxmox(ctx context.Context, config PVEConfig) error {
	if !c.admin {
		return errors.New("Pulse Proxmox configuration requires the admin client")
	}
	if config.Name == "" || config.Host == "" || config.TokenID == "" || config.TokenSecret == "" || !config.VerifySSL {
		return errors.New("Pulse Proxmox configuration requires a named endpoint, token, and verified TLS")
	}
	proxmoxURL, err := url.Parse(config.Host)
	if err != nil || proxmoxURL.Scheme != "https" || proxmoxURL.Host == "" || proxmoxURL.RawQuery != "" || proxmoxURL.Fragment != "" {
		return errors.New("Pulse Proxmox configuration requires an HTTPS API endpoint")
	}
	var nodes []struct {
		Type                         string `json:"type"`
		Name                         string `json:"name"`
		Host                         string `json:"host"`
		VerifySSL                    bool   `json:"verifySSL"`
		MonitorPhysicalDisks         *bool  `json:"monitorPhysicalDisks"`
		TemperatureMonitoringEnabled *bool  `json:"temperatureMonitoringEnabled"`
	}
	if err := c.adminJSON(ctx, http.MethodGet, "/config/nodes", nil, &nodes); err != nil {
		return fmt.Errorf("inspect Pulse Proxmox connections: %w", err)
	}
	for _, node := range nodes {
		if node.Name == config.Name && (node.Host != config.Host || node.Type != "pve") {
			return fmt.Errorf("refusing to reuse Pulse node name %q for a different Proxmox endpoint", config.Name)
		}
		if node.Type == "pve" && node.Name == config.Name && node.Host == config.Host && !node.VerifySSL {
			return errors.New("Pulse Proxmox connection is not configured for verified TLS")
		}
		if node.Type == "pve" && node.Name == config.Name && node.Host == config.Host {
			if node.MonitorPhysicalDisks == nil || *node.MonitorPhysicalDisks || node.TemperatureMonitoringEnabled == nil || *node.TemperatureMonitoringEnabled {
				return errors.New("Pulse Proxmox connection does not prove physical-disk and SSH temperature monitoring are disabled")
			}
			return nil
		}
	}
	request := map[string]any{
		"type":                         "pve",
		"name":                         config.Name,
		"host":                         config.Host,
		"tokenId":                      config.TokenID,
		"tokenSecret":                  config.TokenSecret,
		"verifySSL":                    true,
		"monitorVMs":                   config.MonitorVMs,
		"monitorContainers":            config.MonitorContainers,
		"monitorStorage":               config.MonitorStorage,
		"monitorBackups":               config.MonitorBackups,
		"monitorPhysicalDisks":         config.MonitorPhysicalDisks,
		"temperatureMonitoringEnabled": config.MonitorTemperatures,
	}
	var response json.RawMessage
	if err := c.adminJSON(ctx, http.MethodPost, "/config/nodes", request, &response); err != nil {
		return fmt.Errorf("configure Pulse Proxmox connection: %w", err)
	}
	var configured []struct {
		Type                         string `json:"type"`
		Name                         string `json:"name"`
		Host                         string `json:"host"`
		VerifySSL                    bool   `json:"verifySSL"`
		MonitorPhysicalDisks         *bool  `json:"monitorPhysicalDisks"`
		TemperatureMonitoringEnabled *bool  `json:"temperatureMonitoringEnabled"`
	}
	if err := c.adminJSON(ctx, http.MethodGet, "/config/nodes", nil, &configured); err != nil {
		return fmt.Errorf("verify Pulse Proxmox connection: %w", err)
	}
	for _, node := range configured {
		if node.Type == "pve" && node.Name == config.Name && node.Host == config.Host && node.VerifySSL && node.MonitorPhysicalDisks != nil && !*node.MonitorPhysicalDisks && node.TemperatureMonitoringEnabled != nil && !*node.TemperatureMonitoringEnabled {
			return nil
		}
	}
	return errors.New("Pulse did not confirm the intended Proxmox connection after configuration")
}

func (c *Client) CreateReadToken(ctx context.Context, name string) (string, error) {
	return c.createScopedToken(ctx, name, readScope, "monitoring-read")
}

// CreateIncidentNoteToken creates the write-scoped token whose effective
// authority is further restricted to the exact incident-note path by Pulse's
// mTLS frontend.
func (c *Client) CreateIncidentNoteToken(ctx context.Context, name string) (string, error) {
	return c.createScopedToken(ctx, name, writeScope, "incident-note")
}

func (c *Client) createScopedToken(ctx context.Context, name, scope, purpose string) (string, error) {
	if !c.admin || strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("Pulse %s token creation requires the admin client and a name", purpose)
	}
	request := map[string]any{"name": name, "scopes": []string{scope}}
	var response struct {
		Token  string `json:"token"`
		Record struct {
			Scopes []string `json:"scopes"`
		} `json:"record"`
	}
	if err := c.adminJSON(ctx, http.MethodPost, "/security/tokens", request, &response); err != nil {
		return "", fmt.Errorf("create Pulse %s token: %w", purpose, err)
	}
	if response.Token == "" || len(response.Record.Scopes) != 1 || response.Record.Scopes[0] != scope {
		return "", fmt.Errorf("Pulse token response did not prove the %s scope", purpose)
	}
	return response.Token, nil
}

const aiopsWebhookTemplate = `{"id":"{{jsonString .ID}}","startTime":"{{jsonString .StartTime}}","resourceId":"{{jsonString .ResourceID}}","type":"{{jsonString .Type}}","level":"{{jsonString .Level}}","message":"{{jsonString .Message}}","status":"{{if eq .Event \"resolved\"}}resolved{{else}}firing{{end}}"}`

// ConfigureAIOpsWebhook reconciles the one Boetticher-owned Pulse webhook.
// Pulse's own SSRF policy is narrowed to the single AIOps address before the
// destination and bearer header are stored in Pulse's encrypted state.
func (c *Client) ConfigureAIOpsWebhook(ctx context.Context, targetURL, bearerSecret, allowedCIDR string) error {
	if !c.admin || len(bearerSecret) < 32 || allowedCIDR != "10.10.20.70/32" {
		return errors.New("Pulse AIOps webhook requires admin authority, a bounded secret, and the exact AIOps CIDR")
	}
	target, err := url.Parse(targetURL)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.Path != "/v1/pulse/events" || target.RawQuery != "" || target.Fragment != "" || target.User != nil {
		return errors.New("Pulse AIOps webhook target must be an exact HTTPS event endpoint")
	}
	if err := c.adminJSON(ctx, http.MethodPost, "/system/settings/update", map[string]string{"webhookAllowedPrivateCIDRs": allowedCIDR}, nil); err != nil {
		return fmt.Errorf("restrict Pulse AIOps webhook destination: %w", err)
	}
	type webhook struct {
		ID       string            `json:"id,omitempty"`
		Name     string            `json:"name"`
		URL      string            `json:"url"`
		Method   string            `json:"method"`
		Headers  map[string]string `json:"headers"`
		Enabled  bool              `json:"enabled"`
		Service  string            `json:"service"`
		Template string            `json:"template"`
	}
	var existing []webhook
	if err := c.adminJSON(ctx, http.MethodGet, "/notifications/webhooks", nil, &existing); err != nil {
		return fmt.Errorf("inspect Pulse AIOps webhook: %w", err)
	}
	desired := webhook{Name: "boetticher aiops incidents", URL: targetURL, Method: http.MethodPost, Headers: map[string]string{"Authorization": "Bearer " + bearerSecret}, Enabled: true, Service: "generic", Template: aiopsWebhookTemplate}
	path := "/notifications/webhooks"
	for _, configured := range existing {
		if configured.Name != desired.Name {
			continue
		}
		if configured.ID == "" || strings.ContainsAny(configured.ID, "/?#") {
			return errors.New("Pulse AIOps webhook has an unsafe existing identity")
		}
		desired.ID = configured.ID
		path += "/" + url.PathEscape(configured.ID)
		break
	}
	method := http.MethodPost
	if desired.ID != "" {
		method = http.MethodPut
	}
	if err := c.adminJSON(ctx, method, path, desired, nil); err != nil {
		return fmt.Errorf("reconcile Pulse AIOps webhook: %w", err)
	}
	return nil
}

// CreateAgentReportToken creates the least-privilege token used by tagged
// Pulse host agents. It deliberately does not grant monitoring-read,
// settings-write, agent-management, or command scopes.
func (c *Client) CreateAgentReportToken(ctx context.Context, name string) (string, error) {
	if !c.admin || strings.TrimSpace(name) == "" {
		return "", errors.New("Pulse agent-token creation requires the admin client and a name")
	}
	request := map[string]any{"name": name, "scopes": []string{agentReportScope}}
	var response struct {
		Token  string `json:"token"`
		Record struct {
			Scopes []string `json:"scopes"`
		} `json:"record"`
	}
	if err := c.adminJSON(ctx, http.MethodPost, "/security/tokens", request, &response); err != nil {
		return "", fmt.Errorf("create Pulse agent-report token: %w", err)
	}
	if response.Token == "" || len(response.Record.Scopes) != 1 || response.Record.Scopes[0] != agentReportScope {
		return "", errors.New("Pulse token response did not prove the agent-report scope")
	}
	return response.Token, nil
}

func (c *Client) adminJSON(ctx context.Context, method, path string, body any, destination any) error {
	if err := c.ensureLogin(ctx); err != nil {
		return err
	}
	return c.requestJSON(ctx, method, path, body, destination, true)
}

func (c *Client) getJSON(ctx context.Context, path string, destination any) error {
	return c.requestJSON(ctx, http.MethodGet, path, nil, destination, false)
}

func (c *Client) ensureLogin(ctx context.Context) error {
	if c.loggedIn {
		return nil
	}
	request := map[string]any{"username": c.adminUser, "password": c.adminPassword, "rememberMe": true}
	if err := c.requestJSON(ctx, http.MethodPost, "/login", request, nil, false); err != nil {
		return fmt.Errorf("authenticate to Pulse: %w", err)
	}
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("parse Pulse URL after login: %w", err)
	}
	for _, cookie := range c.http.Jar.Cookies(parsed) {
		if cookie.Name == "pulse_csrf" && cookie.Value != "" {
			c.csrfToken = cookie.Value
			break
		}
	}
	if c.csrfToken == "" {
		return errors.New("Pulse login did not return the CSRF cookie")
	}
	c.loggedIn = true
	return nil
}

func (c *Client) requestJSON(ctx context.Context, method, path string, body any, destination any, adminWrite bool) error {
	requestURL, err := url.Parse(c.baseURL + "/" + strings.TrimLeft(path, "/"))
	if err != nil {
		return fmt.Errorf("build Pulse request URL: %w", err)
	}
	var reader io.Reader
	if body != nil {
		data, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return fmt.Errorf("encode Pulse request: %w", marshalErr)
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return fmt.Errorf("create Pulse request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.apiToken != "" {
		request.Header.Set("X-API-Token", c.apiToken)
	}
	if adminWrite && c.csrfToken != "" {
		request.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("request Pulse %s: %w", method, err)
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("read Pulse response: %w", err)
	}
	if len(bodyBytes) > maxResponseSize {
		return errors.New("Pulse response exceeded the bounded size")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &apiError{Status: response.StatusCode}
	}
	if destination == nil || len(bytes.TrimSpace(bodyBytes)) == 0 {
		return nil
	}
	if err := json.Unmarshal(bodyBytes, destination); err != nil {
		return fmt.Errorf("decode Pulse response: %w", err)
	}
	return nil
}
