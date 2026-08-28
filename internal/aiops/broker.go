package aiops

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxBrokerRequestBytes  = 512 * 1024
	maxBrokerResponseBytes = 256 * 1024
)

type EvidenceSource interface {
	Query(context.Context, EvidenceRequest, EvidencePolicy) (json.RawMessage, error)
}

type Capability struct {
	Token          string
	IncidentID     string
	ExpiresAt      time.Time
	Policy         EvidencePolicy
	EvidenceCalls  int
	EvidenceBytes  int
	Issued         map[string]bool
	RouterRequests int
}

type CapabilityRegistry struct {
	mu   sync.Mutex
	caps map[string]*Capability
}

func NewCapabilityRegistry() *CapabilityRegistry {
	return &CapabilityRegistry{caps: make(map[string]*Capability)}
}

func (r *CapabilityRegistry) Issue(policy EvidencePolicy, now time.Time) (string, error) {
	if !safeIdentifier(policy.IncidentID) {
		return "", errors.New("capability requires a bounded incident")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate capability: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.caps[token] = &Capability{Token: token, IncidentID: policy.IncidentID, ExpiresAt: now.UTC().Add(MaxInvestigationTime), Policy: policy, Issued: map[string]bool{}}
	return token, nil
}

func (r *CapabilityRegistry) Revoke(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.caps, token)
}

func (r *CapabilityRegistry) use(token string, now time.Time, evidence bool) (*Capability, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	capability, ok := r.caps[token]
	if !ok || now.After(capability.ExpiresAt) {
		delete(r.caps, token)
		return nil, errors.New("invalid or expired capability")
	}
	if evidence {
		if capability.EvidenceCalls >= MaxEvidenceCalls {
			return nil, errors.New("evidence call budget exhausted")
		}
		capability.EvidenceCalls++
	} else {
		capability.RouterRequests++
		if capability.RouterRequests > MaxHolmesSteps {
			return nil, errors.New("Holmes step budget exhausted")
		}
	}
	return capability, nil
}

func (r *CapabilityRegistry) record(token, reference string, size int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	capability, ok := r.caps[token]
	if !ok {
		return errors.New("capability was revoked")
	}
	if size < 0 || capability.EvidenceBytes+size > MaxEvidenceBytes {
		return errors.New("evidence byte budget exhausted")
	}
	capability.EvidenceBytes += size
	capability.Issued[reference] = true
	return nil
}

type Broker struct {
	Capabilities *CapabilityRegistry
	Evidence     EvidenceSource
	Router       *http.Client
	RouterURL    string
	ModelAlias   string
	Now          func() time.Time
}

func (b *Broker) EvidenceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/evidence/query", b.queryEvidence)
	return loopbackOnly(mux)
}

func (b *Broker) RouterHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", b.routeCompletion)
	return loopbackOnly(mux)
}

func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.RemoteAddr
		if index := strings.LastIndex(host, ":"); index >= 0 {
			host = strings.Trim(host[:index], "[]")
		}
		if host != "127.0.0.1" && host != "::1" {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (b *Broker) queryEvidence(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	capability, err := b.Capabilities.use(token, b.now(), true)
	if err != nil {
		http.Error(w, "capability denied", http.StatusForbidden)
		return
	}
	var request EvidenceRequest
	if r.Header.Get("Content-Type") != "application/json" || strictDecode(http.MaxBytesReader(w, r.Body, MaxWebhookBytes), &request) != nil {
		http.Error(w, "invalid evidence request", http.StatusBadRequest)
		return
	}
	if err := capability.Policy.Validate(request); err != nil {
		http.Error(w, "evidence authority denied", http.StatusForbidden)
		return
	}
	data, err := b.Evidence.Query(r.Context(), request, capability.Policy)
	if err != nil {
		http.Error(w, "evidence unavailable", http.StatusBadGateway)
		return
	}
	if len(data) > MaxEvidenceBytes {
		http.Error(w, "evidence response too large", http.StatusBadGateway)
		return
	}
	digest := sha256.Sum256(data)
	reference := request.IncidentID + ":" + fmt.Sprint(capability.EvidenceCalls)
	if err := b.Capabilities.record(token, reference, len(data)); err != nil {
		http.Error(w, "evidence budget exhausted", http.StatusTooManyRequests)
		return
	}
	writeJSON(w, http.StatusOK, Evidence{Reference: reference, Source: request.Operation, CollectedAt: b.now(), SHA256: hex.EncodeToString(digest[:]), Data: data})
}

type completionRequest struct {
	Model          string          `json:"model"`
	Messages       json.RawMessage `json:"messages"`
	Tools          json.RawMessage `json:"tools,omitempty"`
	ToolChoice     json.RawMessage `json:"tool_choice,omitempty"`
	ResponseFormat json.RawMessage `json:"response_format,omitempty"`
	Temperature    *float64        `json:"temperature,omitempty"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	MaxCompletion  int             `json:"max_completion_tokens,omitempty"`
	Stream         bool            `json:"stream,omitempty"`
}

func (b *Broker) routeCompletion(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if _, err := b.Capabilities.use(token, b.now(), false); err != nil {
		http.Error(w, "capability denied", http.StatusForbidden)
		return
	}
	var request completionRequest
	if r.Header.Get("Content-Type") != "application/json" || strictDecode(http.MaxBytesReader(w, r.Body, maxBrokerRequestBytes), &request) != nil || len(request.Messages) == 0 || request.Stream {
		http.Error(w, "invalid completion request", http.StatusBadRequest)
		return
	}
	request.Model = b.ModelAlias
	request.MaxTokens = MaxOutputTokens
	request.MaxCompletion = 0
	body, err := json.Marshal(request)
	if err != nil {
		http.Error(w, "invalid completion request", http.StatusBadRequest)
		return
	}
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodPost, b.RouterURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "router request unavailable", http.StatusBadGateway)
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	response, err := b.Router.Do(upstream)
	if err != nil {
		http.Error(w, "AI Router unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBrokerResponseBytes+1))
	if err != nil || len(data) > maxBrokerResponseBytes {
		http.Error(w, "AI Router response exceeded bounds", http.StatusBadGateway)
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		http.Error(w, "AI Router rejected request", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (b *Broker) Validate() error {
	if b.Capabilities == nil || b.Evidence == nil || b.Router == nil || !safeToken(b.ModelAlias) {
		return errors.New("broker requires capabilities, evidence, router, and a safe model alias")
	}
	u, err := url.Parse(b.RouterURL)
	if err != nil || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" || u.Path != "/v1/chat/completions" {
		return errors.New("AI Router URL must be the fixed HTTPS chat-completions path")
	}
	return nil
}

func (b *Broker) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

func bearer(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimPrefix(header, prefix)
	if len(token) < 32 || len(token) > 128 {
		return "", false
	}
	// Touch every byte before registry lookup so malformed token lengths are the
	// only authentication distinction exposed at this boundary.
	_ = subtle.ConstantTimeCompare([]byte(token), []byte(token))
	return token, true
}
