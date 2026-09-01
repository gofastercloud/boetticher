package bifrost

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultListen           = "127.0.0.1:4000"
	DefaultConfigPath       = "/etc/boetticher/litellm/config.json"
	DefaultCredentialDirEnv = "CREDENTIALS_DIRECTORY"
	MaxRequestBytes         = 2 * 1024 * 1024
	MaxResponseBytes        = 4 * 1024 * 1024
	MaxCredentialBytes      = 4096
	MaxModels               = 32
)

type Config struct {
	Listen    string     `json:"listen"`
	Upstreams []Upstream `json:"upstreams"`
	Models    []Model    `json:"models"`
}

type Upstream struct {
	Name       string `json:"name"`
	BaseURL    string `json:"base_url"`
	Credential string `json:"credential"`
}

type Model struct {
	Alias    string `json:"alias"`
	Upstream string `json:"upstream"`
	Model    string `json:"model"`
}

type ModelCapabilities struct {
	Mode                    string `json:"mode"`
	SupportsFunctionCalling bool   `json:"supports_function_calling"`
	SupportsResponseSchema  bool   `json:"supports_response_schema"`
	MaxInputTokens          int    `json:"max_input_tokens"`
	MaxOutputTokens         int    `json:"max_output_tokens"`
}

type Router struct {
	models map[string]route
	client *http.Client
}

type route struct {
	alias          string
	providerModel  string
	chatEndpoint   string
	modelsEndpoint string
	apiKey         string
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read Bifrost configuration: %w", err)
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode Bifrost configuration: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return Config{}, errors.New("Bifrost configuration contains trailing data")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	if config.Listen == "" {
		config.Listen = DefaultListen
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Listen != DefaultListen {
		return fmt.Errorf("Bifrost listen address must be %s", DefaultListen)
	}
	if len(c.Upstreams) == 0 || len(c.Upstreams) > 16 {
		return errors.New("Bifrost requires 1-16 configured upstreams")
	}
	if len(c.Models) == 0 || len(c.Models) > MaxModels {
		return errors.New("Bifrost requires 1-32 configured model aliases")
	}
	upstreams := make(map[string]struct{}, len(c.Upstreams))
	credentials := make(map[string]string, len(c.Upstreams))
	for _, upstream := range c.Upstreams {
		if !safeToken(upstream.Name) || upstream.Name == "dns" {
			return fmt.Errorf("Bifrost upstream name %q is invalid", upstream.Name)
		}
		if _, exists := upstreams[upstream.Name]; exists {
			return fmt.Errorf("Bifrost has duplicate upstream %q", upstream.Name)
		}
		upstreams[upstream.Name] = struct{}{}
		parsed, err := url.Parse(upstream.BaseURL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("Bifrost upstream %s requires a valid HTTPS base URL", upstream.Name)
		}
		if !safeCredentialName(upstream.Credential) {
			return fmt.Errorf("Bifrost upstream %s has an invalid credential name", upstream.Name)
		}
		if previous, exists := credentials[upstream.Credential]; exists && previous != upstream.Name {
			return fmt.Errorf("Bifrost credential %q is shared by multiple upstreams", upstream.Credential)
		}
		credentials[upstream.Credential] = upstream.Name
	}
	aliases := make(map[string]struct{}, len(c.Models))
	for _, model := range c.Models {
		if !safeToken(model.Alias) || model.Alias == "health" {
			return fmt.Errorf("Bifrost model alias %q is invalid", model.Alias)
		}
		if _, exists := aliases[model.Alias]; exists {
			return fmt.Errorf("Bifrost has duplicate model alias %q", model.Alias)
		}
		aliases[model.Alias] = struct{}{}
		if _, exists := upstreams[model.Upstream]; !exists {
			return fmt.Errorf("Bifrost model alias %s references unknown upstream %q", model.Alias, model.Upstream)
		}
		if !safeProviderModel(model.Model) {
			return fmt.Errorf("Bifrost model alias %s has an invalid provider model", model.Alias)
		}
	}
	return nil
}

func NewRouter(config Config, credentialDir string) (*Router, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Listen == "" {
		config.Listen = DefaultListen
	}
	if credentialDir == "" || !filepath.IsAbs(credentialDir) {
		return nil, errors.New("Bifrost requires an absolute systemd credential directory")
	}
	upstreams := make(map[string]Upstream, len(config.Upstreams))
	for _, upstream := range config.Upstreams {
		upstreams[upstream.Name] = upstream
	}
	models := make(map[string]route, len(config.Models))
	keys := make(map[string]string, len(config.Upstreams))
	for _, upstream := range config.Upstreams {
		key, err := readCredential(filepath.Join(credentialDir, upstream.Credential))
		if err != nil {
			return nil, fmt.Errorf("load Bifrost credential for upstream %s: %w", upstream.Name, err)
		}
		keys[upstream.Name] = key
	}
	for _, model := range config.Models {
		upstream := upstreams[model.Upstream]
		base := strings.TrimRight(upstream.BaseURL, "/")
		models[model.Alias] = route{
			alias:          model.Alias,
			providerModel:  model.Model,
			chatEndpoint:   base + "/chat/completions",
			modelsEndpoint: base + "/models",
			apiKey:         keys[model.Upstream],
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Router{
		models: models,
		client: &http.Client{Transport: transport, Timeout: 120 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (r *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		writeError(writer, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	switch {
	case request.URL.Path == "/health" && request.Method == http.MethodGet:
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok"}`))
	case request.URL.Path == "/v1/models" && request.Method == http.MethodGet:
		r.handleModels(writer)
	case strings.HasPrefix(request.URL.Path, "/internal/model-capabilities/") && request.Method == http.MethodGet:
		r.handleCapabilities(writer, request.Context(), strings.TrimPrefix(request.URL.Path, "/internal/model-capabilities/"))
	case request.URL.Path == "/v1/chat/completions" && request.Method == http.MethodPost:
		r.handleChat(writer, request)
	default:
		writeError(writer, http.StatusNotFound, "route is not supported")
	}
}

func (r *Router) handleCapabilities(writer http.ResponseWriter, ctx context.Context, alias string) {
	if !safeToken(alias) {
		writeError(writer, http.StatusBadRequest, "model alias is invalid")
		return
	}
	capabilities, err := r.ModelCapabilities(ctx, alias)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "model capabilities are unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, capabilities)
}

func (r *Router) handleModels(writer http.ResponseWriter) {
	data := struct {
		Object string         `json:"object"`
		Data   []modelSummary `json:"data"`
	}{Object: "list", Data: make([]modelSummary, 0, len(r.models))}
	for alias := range r.models {
		data.Data = append(data.Data, modelSummary{ID: alias, Object: "model", OwnedBy: "bifrost"})
	}
	// Config order is not semantically meaningful, but deterministic output is
	// useful for operators and consumers that compare model discovery results.
	for i := 0; i < len(data.Data); i++ {
		for j := i + 1; j < len(data.Data); j++ {
			if data.Data[j].ID < data.Data[i].ID {
				data.Data[i], data.Data[j] = data.Data[j], data.Data[i]
			}
		}
	}
	writeJSON(writer, http.StatusOK, data)
}

type modelSummary struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

func (r *Router) handleChat(writer http.ResponseWriter, request *http.Request) {
	if request.ContentLength > MaxRequestBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "request exceeds the Bifrost request bound")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
	if err != nil || len(body) > MaxRequestBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "request exceeds the Bifrost request bound")
		return
	}
	var payload map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil || payload == nil {
		writeError(writer, http.StatusBadRequest, "request must be a JSON object")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		writeError(writer, http.StatusBadRequest, "request contains trailing data")
		return
	}
	var alias string
	if raw, ok := payload["model"]; !ok || json.Unmarshal(raw, &alias) != nil || !safeToken(alias) {
		writeError(writer, http.StatusBadRequest, "request model must be a declared alias")
		return
	}
	route, ok := r.models[alias]
	if !ok {
		writeError(writer, http.StatusNotFound, "model alias is not declared")
		return
	}
	rewritten, err := json.Marshal(route.providerModel)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "request model is invalid")
		return
	}
	payload["model"] = rewritten
	upstreamBody, err := json.Marshal(payload)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "request could not be encoded")
		return
	}
	upstreamRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, route.chatEndpoint, bytes.NewReader(upstreamBody))
	if err != nil {
		writeError(writer, http.StatusBadGateway, "upstream request could not be created")
		return
	}
	upstreamRequest.Header.Set("Content-Type", "application/json")
	upstreamRequest.Header.Set("Accept", "application/json")
	upstreamRequest.Header.Set("Authorization", "Bearer "+route.apiKey)
	for _, name := range []string{"HTTP-Referer", "X-Title"} {
		if value := request.Header.Get(name); value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\r\n") {
			upstreamRequest.Header.Set(name, value)
		}
	}
	response, err := r.client.Do(upstreamRequest)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "upstream AI provider is unavailable")
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(data) > MaxResponseBytes {
		writeError(writer, http.StatusBadGateway, "upstream response exceeded the Bifrost response bound")
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		writeError(writer, http.StatusBadGateway, fmt.Sprintf("upstream AI provider returned HTTP %d", response.StatusCode))
		return
	}
	var streaming bool
	if raw, exists := payload["stream"]; exists {
		_ = json.Unmarshal(raw, &streaming)
	}
	if !streaming {
		data = rewriteCompletionModel(data, alias)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "" && !strings.ContainsAny(contentType, "\r\n") {
		writer.Header().Set("Content-Type", contentType)
	} else {
		writer.Header().Set("Content-Type", "application/json")
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = writer.Write(data)
}

func rewriteCompletionModel(data []byte, alias string) []byte {
	var completion map[string]json.RawMessage
	if json.Unmarshal(data, &completion) != nil || completion == nil {
		return data
	}
	rewritten, err := json.Marshal(alias)
	if err != nil {
		return data
	}
	completion["model"] = rewritten
	result, err := json.Marshal(completion)
	if err != nil {
		return data
	}
	return result
}

func (r *Router) ModelCapabilities(ctx context.Context, alias string) (ModelCapabilities, error) {
	route, ok := r.models[alias]
	if !ok {
		return ModelCapabilities{}, errors.New("model alias is not declared")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, route.modelsEndpoint, nil)
	if err != nil {
		return ModelCapabilities{}, errors.New("OpenRouter models request could not be created")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+route.apiKey)
	response, err := r.client.Do(request)
	if err != nil {
		return ModelCapabilities{}, errors.New("OpenRouter models request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(data) > MaxResponseBytes || response.StatusCode < 200 || response.StatusCode >= 300 {
		return ModelCapabilities{}, errors.New("OpenRouter models response is unavailable")
	}
	var catalog struct {
		Data []struct {
			ID            string `json:"id"`
			ContextLength int    `json:"context_length"`
			Architecture  struct {
				InputModalities  []string `json:"input_modalities"`
				OutputModalities []string `json:"output_modalities"`
			} `json:"architecture"`
			TopProvider struct {
				MaxCompletionTokens int `json:"max_completion_tokens"`
			} `json:"top_provider"`
			SupportedParameters []string `json:"supported_parameters"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return ModelCapabilities{}, errors.New("OpenRouter models response is invalid")
	}
	for _, item := range catalog.Data {
		if item.ID != route.providerModel {
			continue
		}
		capabilities := ModelCapabilities{Mode: "chat", MaxInputTokens: item.ContextLength, MaxOutputTokens: item.TopProvider.MaxCompletionTokens}
		var hasTools, hasToolChoice bool
		for _, parameter := range item.SupportedParameters {
			if parameter == "tools" {
				hasTools = true
			}
			if parameter == "tool_choice" {
				hasToolChoice = true
			}
			if parameter == "response_format" || parameter == "structured_outputs" {
				capabilities.SupportsResponseSchema = true
			}
		}
		capabilities.SupportsFunctionCalling = hasTools && hasToolChoice
		if capabilities.MaxInputTokens < 1 || capabilities.MaxOutputTokens < 1 {
			return ModelCapabilities{}, errors.New("OpenRouter model capabilities are incomplete")
		}
		return capabilities, nil
	}
	return ModelCapabilities{}, errors.New("provider model is absent from OpenRouter catalog")
}

func readCredential(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", errors.New("credential is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("credential file is not a protected regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > MaxCredentialBytes {
		return "", errors.New("credential is unavailable")
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n\t ") {
		return "", errors.New("credential has invalid format")
	}
	return value, nil
}

func safeToken(value string) bool {
	if value == "" || len(value) > 254 {
		return false
	}
	for index, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || (index > 0 && (character == '-' || character == '_' || character == '.'))) {
			return false
		}
	}
	return true
}

func safeCredentialName(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." || strings.Contains(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	return safeToken(value)
}

func safeProviderModel(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("._:/-", character)) {
			return false
		}
	}
	return true
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]any{"message": message, "type": "bifrost_error", "code": status}})
}
