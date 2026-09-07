// Package openwrt contains the deliberately small management surface used by
// the firewall capability. It is not a general OpenWrt SDK.
package openwrt

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
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	ubusProtocolVersion = 2
	loginSession        = "00000000000000000000000000000000"
)

// Config describes the Controller-side trust and credential binding for the
// provider. TrustPEM must contain the pinned provider certificate or its
// private CA; no insecure mode is available.
type Config struct {
	BaseURL  string
	Username string
	Password string
	TrustPEM []byte
	// ServerName is normally omitted when the pinned certificate contains the
	// provider management IP in its SANs. It exists for a site-local DNS name.
	ServerName string
	HTTP       *http.Client
	Timeout    time.Duration
}

// Client is a session-bound, HTTPS-only ubus client.
type Client struct {
	baseURL string
	user    string
	pass    string
	http    *http.Client
	session atomic.Value // string
	request uint64
}

func NewClient(config Config) (*Client, error) {
	if config.Username == "" || config.Password == "" {
		return nil, errors.New("provider credentials are required")
	}
	parsed, err := url.Parse(strings.TrimRight(config.BaseURL, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("provider management URL must be an https URL without credentials or query parameters")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.ServerName}
	if len(config.TrustPEM) == 0 {
		return nil, errors.New("pinned provider TLS trust is required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.TrustPEM) {
		return nil, errors.New("pinned provider TLS trust contains no certificates")
	}
	transport.TLSClientConfig.RootCAs = roots
	client := config.HTTP
	if client == nil {
		timeout := config.Timeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		client = &http.Client{Transport: transport, Timeout: timeout}
	}
	return &Client{baseURL: parsed.String() + "/ubus", user: config.Username, pass: config.Password, http: client}, nil
}

// Authenticate establishes a fresh ubus session. The password is never
// included in an error or request diagnostic.
func (c *Client) Authenticate(ctx context.Context) error {
	if c == nil || c.http == nil {
		return errors.New("provider client is required")
	}
	result, err := c.call(ctx, loginSession, "session", "login", map[string]any{
		"username": c.user,
		"password": c.pass,
		"timeout":  300,
	})
	if err != nil {
		return fmt.Errorf("provider authentication failed: %w", err)
	}
	var payload struct {
		Session string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(result, &payload); err != nil || payload.Session == "" {
		return errors.New("provider authentication response did not contain a session")
	}
	c.session.Store(payload.Session)
	return nil
}

// UCISection is the small desired/readback shape needed by firewall state.
// Values are strings because OpenWrt UCI has separate scalar and list calls.
type UCISection struct {
	Type    string
	Options map[string]string
	Lists   map[string][]string
}

// UCIGet reads one complete UCI package. It does not mutate provider state.
func (c *Client) UCIGet(ctx context.Context, config string) (map[string]UCISection, error) {
	if config == "" {
		return nil, errors.New("UCI config name is required")
	}
	result, err := c.callWithSession(ctx, "uci", "get", map[string]any{"config": config})
	if err != nil {
		return nil, fmt.Errorf("read provider UCI %s: %w", config, err)
	}
	var payload struct {
		Values map[string]any `json:"values"`
	}
	if err := json.Unmarshal(result, &payload); err != nil || payload.Values == nil {
		return nil, errors.New("provider UCI response is malformed")
	}
	sections := make(map[string]UCISection, len(payload.Values))
	if section, ok := decodeSection("", payload.Values); ok {
		name := sectionName(payload.Values)
		if name == "" {
			return nil, errors.New("provider UCI response omitted section name")
		}
		sections[name] = section
		return sections, nil
	}
	for name, value := range payload.Values {
		raw, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("provider UCI section is malformed")
		}
		section, ok := decodeSection(name, raw)
		if !ok {
			return nil, errors.New("provider UCI section is malformed")
		}
		sections[name] = section
	}
	return sections, nil
}

func decodeSection(name string, raw map[string]any) (UCISection, bool) {
	if _, hasType := raw[".type"]; !hasType {
		return UCISection{}, false
	}
	section := UCISection{Options: map[string]string{}, Lists: map[string][]string{}}
	for key, value := range raw {
		switch typed := value.(type) {
		case string:
			if key == ".type" {
				section.Type = typed
			} else if !strings.HasPrefix(key, ".") {
				section.Options[key] = typed
			}
		case []any:
			if strings.HasPrefix(key, ".") {
				continue
			}
			for _, item := range typed {
				if text, ok := item.(string); ok {
					section.Lists[key] = append(section.Lists[key], text)
				}
			}
		}
	}
	return section, section.Type != ""
}

func sectionName(raw map[string]any) string {
	name, _ := raw[".name"].(string)
	return name
}

func (c *Client) UCISet(ctx context.Context, config, section, option, value string) error {
	if config == "" || section == "" || option == "" {
		return errors.New("UCI config, section, and option are required")
	}
	_, err := c.callWithSession(ctx, "uci", "set", map[string]any{"config": config, "section": section, "values": map[string]string{option: value}})
	if err != nil {
		return fmt.Errorf("set provider UCI %s.%s.%s: %w", config, section, option, err)
	}
	return nil
}

func (c *Client) UCIAddList(ctx context.Context, config, section, option, value string) error {
	return c.UCISetList(ctx, config, section, option, []string{value})
}

func (c *Client) UCISetList(ctx context.Context, config, section, option string, values []string) error {
	if config == "" || section == "" || option == "" {
		return errors.New("UCI config, section, and option are required")
	}
	_, err := c.callWithSession(ctx, "uci", "set", map[string]any{"config": config, "section": section, "values": map[string]any{option: values}})
	if err != nil {
		return fmt.Errorf("set provider UCI list %s.%s.%s: %w", config, section, option, err)
	}
	return nil
}

func (c *Client) UCIAdd(ctx context.Context, config, sectionType string) (string, error) {
	return c.UCIAddNamed(ctx, config, sectionType, "")
}

func (c *Client) UCIAddNamed(ctx context.Context, config, sectionType, sectionName string) (string, error) {
	if config == "" || sectionType == "" {
		return "", errors.New("UCI config and section type are required")
	}
	params := map[string]any{"config": config, "type": sectionType}
	if sectionName != "" {
		params["name"] = sectionName
	}
	result, err := c.callWithSession(ctx, "uci", "add", params)
	if err != nil {
		return "", fmt.Errorf("add provider UCI section: %w", err)
	}
	var payload struct {
		Section string `json:"section"`
	}
	if err := json.Unmarshal(result, &payload); err != nil || payload.Section == "" {
		return "", errors.New("provider UCI add response did not contain a section name")
	}
	return payload.Section, nil
}

func (c *Client) UCIDelete(ctx context.Context, config, section, option string) error {
	if config == "" || section == "" {
		return errors.New("UCI config and section are required")
	}
	params := map[string]any{"config": config, "section": section}
	if option != "" {
		params["option"] = option
	}
	if _, err := c.callWithSession(ctx, "uci", "delete", params); err != nil {
		return fmt.Errorf("delete provider UCI section: %w", err)
	}
	return nil
}

// UCIApply commits the staged UCI changes and asks OpenWrt to reload the
// affected services. The caller still decides which packages need applying.
func (c *Client) UCIApply(ctx context.Context, timeout int) error {
	if timeout <= 0 {
		timeout = 30
	}
	if _, err := c.callWithSession(ctx, "uci", "apply", map[string]any{"timeout": timeout, "rollback": false}); err != nil {
		return fmt.Errorf("apply provider UCI changes: %w", err)
	}
	return nil
}

// InterfaceDump returns native runtime interface state for the cheap status
// view. The shape intentionally remains opaque to avoid a broad SDK.
func (c *Client) InterfaceDump(ctx context.Context) (json.RawMessage, error) {
	result, err := c.callWithSession(ctx, "network.interface", "dump", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("read provider interface status: %w", err)
	}
	return append(json.RawMessage(nil), result...), nil
}

// DefaultRouteActive reports whether the provider's native IPv4 interface
// dump contains a routed default via a non-empty next hop.
func DefaultRouteActive(runtime json.RawMessage) (bool, error) {
	return defaultRouteCheck(runtime, "")
}

// DefaultRouteVia verifies the IPv4 default route uses the expected next hop.
func DefaultRouteVia(runtime json.RawMessage, expectedGateway string) (bool, error) {
	if expectedGateway == "" {
		return false, errors.New("expected provider default-route gateway is required")
	}
	return defaultRouteCheck(runtime, expectedGateway)
}

func defaultRouteCheck(runtime json.RawMessage, expectedGateway string) (bool, error) {
	var payload any
	if err := json.Unmarshal(runtime, &payload); err != nil {
		return false, errors.New("provider interface response is malformed")
	}
	return defaultRouteValue(payload, expectedGateway), nil
}

func defaultRouteValue(value any, expectedGateway string) bool {
	switch typed := value.(type) {
	case map[string]any:
		target, _ := typed["target"].(string)
		if target == "0.0.0.0" {
			mask, _ := typed["mask"].(float64)
			if mask == 0 {
				if nextHop, ok := typed["nexthop"].(string); ok && nextHop != "" {
					return expectedGateway == "" || nextHop == expectedGateway
				}
				if gateway, ok := typed["gateway"].(string); ok && gateway != "" {
					return expectedGateway == "" || gateway == expectedGateway
				}
			}
		}
		for _, item := range typed {
			if defaultRouteValue(item, expectedGateway) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if defaultRouteValue(item, expectedGateway) {
				return true
			}
		}
	}
	return false
}

func (c *Client) callWithSession(ctx context.Context, object, method string, params map[string]any) (json.RawMessage, error) {
	value := c.session.Load()
	session, _ := value.(string)
	if session == "" {
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
		value = c.session.Load()
		session, _ = value.(string)
	}
	return c.call(ctx, session, object, method, params)
}

func (c *Client) call(ctx context.Context, session, object, method string, params map[string]any) (json.RawMessage, error) {
	id := atomic.AddUint64(&c.request, 1)
	body, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      uint64 `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{JSONRPC: "2.0", ID: id, Method: "call", Params: []any{session, object, method, params}})
	if err != nil {
		return nil, errors.New("encode provider request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create provider request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("provider request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("provider request returned HTTP %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, errors.New("read provider response")
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.JSONRPC != "2.0" || len(envelope.Result) == 0 {
		return nil, errors.New("provider response is malformed")
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return nil, errors.New("provider JSON-RPC operation failed")
	}
	var result []json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil || len(result) == 0 {
		return nil, errors.New("provider result is malformed")
	}
	var code int
	if err := json.Unmarshal(result[0], &code); err != nil {
		return nil, errors.New("provider response status is malformed")
	}
	if code != 0 {
		return nil, fmt.Errorf("provider operation failed with status %d", code)
	}
	if len(result) == 1 {
		return json.RawMessage(`{}`), nil
	}
	return result[1], nil
}
