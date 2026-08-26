package opnsense

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
	"os"
	"path"
	"strings"
	"time"
)

// Client is the small OPNsense API surface used by the V1 controller. The
// client deliberately accepts endpoint paths instead of exposing a generic
// arbitrary-command CLI: callers can only reach the modelled API methods in
// the convergence code.
type Client struct {
	BaseURL string
	User    string
	Secret  string
	HTTP    *http.Client
}

type Config struct {
	BaseURL  string
	User     string
	Secret   string
	CAFile   string
	Insecure bool
	Timeout  time.Duration
}

type APIError struct {
	StatusCode int
	Status     string
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("OPNsense API: %s", e.Status)
	}
	return fmt.Sprintf("OPNsense API: %s: %s", e.Status, e.Message)
}

func NewClient(config Config) (*Client, error) {
	if config.BaseURL == "" {
		return nil, errors.New("OPNsense API base URL is required")
	}
	parsed, err := url.Parse(strings.TrimRight(config.BaseURL, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("OPNsense API base URL must be an https URL")
	}
	if config.User == "" || config.Secret == "" {
		return nil, errors.New("OPNsense API key and secret are required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: config.Insecure} // #nosec G402 -- only enabled by explicit operator choice.
	if config.CAFile != "" {
		data, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read OPNsense CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("OPNsense CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		BaseURL: strings.TrimRight(config.BaseURL, "/"),
		User:    config.User,
		Secret:  config.Secret,
		HTTP:    &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

func (c *Client) Get(ctx context.Context, endpoint string, out any) error {
	return c.request(ctx, http.MethodGet, endpoint, nil, out)
}

func (c *Client) Post(ctx context.Context, endpoint string, payload any, out any) error {
	return c.request(ctx, http.MethodPost, endpoint, payload, out)
}

func (c *Client) FirmwareStatus(ctx context.Context, out any) error {
	return c.Get(ctx, "/api/core/firmware/status", out)
}

func (c *Client) request(ctx context.Context, method, endpoint string, payload any, out any) error {
	if !strings.HasPrefix(endpoint, "/api/") {
		return fmt.Errorf("OPNsense endpoint must be an /api/ path")
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	base.Path = path.Join(base.Path, endpoint)
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode OPNsense request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, base.String(), body)
	if err != nil {
		return err
	}
	request.SetBasicAuth(c.User, c.Secret)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	var envelope map[string]any
	if len(data) > 0 {
		_ = json.Unmarshal(data, &envelope)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{StatusCode: response.StatusCode, Status: response.Status, Message: responseMessage(envelope, data)}
	}
	if status, ok := envelope["status"].(string); ok && strings.EqualFold(status, "failed") {
		return &APIError{StatusCode: response.StatusCode, Status: response.Status, Message: responseMessage(envelope, data)}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode OPNsense API response: %w", err)
		}
	}
	return nil
}

func responseMessage(envelope map[string]any, data []byte) string {
	for _, key := range []string{"message", "error", "validations"} {
		if value, ok := envelope[key]; ok {
			encoded, err := json.Marshal(value)
			if err == nil {
				return string(encoded)
			}
		}
	}
	return strings.TrimSpace(string(data))
}
