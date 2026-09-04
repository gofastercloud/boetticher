package streamdeck

import (
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
	"strconv"
	"strings"
	"time"
)

const (
	maxPulseResponse = 4 << 20
	maxResources     = 400
	pageSize         = 100
	requestTimeout   = 3 * time.Second
)

type Resource struct {
	Name           string
	Kind           string
	PlatformType   string
	Sources        []string
	PlatformScopes []string
	Status         string
	CPU            *float64
	Memory         *float64

	sourceMetadata bool
}

type State struct {
	Status     string
	Resources  []Resource
	ReceivedAt time.Time
	Stale      string
}

type PulseClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewPulseClient(config Config, token string) (*PulseClient, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("StreamDeck Pulse client requires a credential")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(config.CACertificate)
	if err != nil {
		return nil, fmt.Errorf("read StreamDeck Pulse CA: %w", err)
	}
	roots, err := privateCAPool(caPEM)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	return newPulseClient(config.PulseURL, token, &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	})
}

func privateCAPool(caPEM []byte) (*x509.CertPool, error) {
	// The companion talks to one private Pulse endpoint. Trusting the host's
	// public roots here would allow a public certificate to satisfy the same
	// connection contract if DNS or routing is ever misdirected.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("load StreamDeck Pulse CA: no certificates found")
	}
	return roots, nil
}

func newPulseClient(baseURL, token string, client *http.Client) (*PulseClient, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("StreamDeck Pulse URL must be an HTTPS origin without query or fragment")
	}
	if client == nil {
		return nil, errors.New("StreamDeck Pulse client requires an HTTP client")
	}
	return &PulseClient{baseURL: parsed.String(), token: token, http: client}, nil
}

func (c *PulseClient) Fetch(ctx context.Context) (State, error) {
	healthBody, err := c.json(ctx, "/api/health")
	if err != nil {
		return State{}, err
	}
	var health struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(healthBody, &health); err != nil {
		return State{}, fmt.Errorf("decode Pulse health: %w", err)
	}

	summaryBody, err := c.json(ctx, "/api/state/summary")
	if err != nil {
		return State{}, err
	}
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(summaryBody, &summary); err != nil {
		return State{}, fmt.Errorf("decode Pulse summary: %w", err)
	}

	resources := make([]Resource, 0, pageSize)
	for pageNumber := 1; len(resources) < maxResources; pageNumber++ {
		path := "/api/resources?limit=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(pageNumber) + "&sort=name&order=asc"
		body, err := c.json(ctx, path)
		if err != nil {
			return State{}, err
		}
		var page struct {
			Resources []json.RawMessage `json:"resources"`
			Data      []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return State{}, fmt.Errorf("decode Pulse resources: %w", err)
		}
		items := page.Resources
		if items == nil {
			items = page.Data
		}
		for _, item := range items {
			if len(resources) == maxResources {
				break
			}
			resource, err := decodeResource(item)
			if err != nil {
				return State{}, err
			}
			resources = append(resources, resource)
		}
		if len(items) < pageSize {
			break
		}
	}
	return State{Status: health.Status, Resources: resources, ReceivedAt: time.Now().UTC()}, nil
}

func (c *PulseClient) json(ctx context.Context, path string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create Pulse request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-API-Token", c.token)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request Pulse: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Pulse returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPulseResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read Pulse response: %w", err)
	}
	if len(body) > maxPulseResponse {
		return nil, errors.New("Pulse response exceeds 4 MiB")
	}
	return body, nil
}

func decodeResource(raw json.RawMessage) (Resource, error) {
	var value struct {
		Name           string          `json:"name"`
		Kind           string          `json:"type"`
		PlatformType   string          `json:"platformType"`
		Sources        json.RawMessage `json:"sources"`
		PlatformScopes json.RawMessage `json:"platformScopes"`
		Status         string          `json:"status"`
		Metrics        map[string]any  `json:"metrics"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return Resource{}, fmt.Errorf("decode Pulse resource: %w", err)
	}
	if value.Name == "" {
		return Resource{}, errors.New("malformed Pulse resource")
	}
	resource := Resource{
		Name:           value.Name,
		Kind:           defaultString(value.Kind, "guest"),
		PlatformType:   value.PlatformType,
		Status:         defaultString(value.Status, "unknown"),
		CPU:            optionalPercent(value.Metrics["cpu"]),
		Memory:         optionalPercent(value.Metrics["memory"]),
		sourceMetadata: value.Sources != nil || value.PlatformScopes != nil,
	}
	if value.Sources != nil && string(value.Sources) != "null" {
		if err := json.Unmarshal(value.Sources, &resource.Sources); err != nil {
			return Resource{}, fmt.Errorf("decode Pulse resource sources: %w", err)
		}
	}
	if value.PlatformScopes != nil && string(value.PlatformScopes) != "null" {
		if err := json.Unmarshal(value.PlatformScopes, &resource.PlatformScopes); err != nil {
			return Resource{}, fmt.Errorf("decode Pulse resource platform scopes: %w", err)
		}
	}
	return resource, nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func optionalPercent(value any) *float64 {
	switch value := value.(type) {
	case float64:
		return boundedPercent(value)
	case map[string]any:
		if percent, ok := value["percent"].(float64); ok {
			return boundedPercent(percent)
		}
		unit, _ := value["unit"].(string)
		if strings.EqualFold(strings.TrimSpace(unit), "percent") {
			if percent, ok := value["value"].(float64); ok {
				return boundedPercent(percent)
			}
		}
	}
	return nil
}

func boundedPercent(value float64) *float64 {
	if value < 0 || value > 100 {
		return nil
	}
	return &value
}
