package bifrost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouterPreservesOpenAIRequestContractAndRewritesOnlyModel(t *testing.T) {
	credentials := t.TempDir()
	credentialPath := filepath.Join(credentials, "openrouter-api-key")
	if err := os.WriteFile(credentialPath, []byte("test-openrouter-key"), 0o400); err != nil {
		t.Fatal(err)
	}
	var received map[string]any
	provider := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/chat/completions" || request.Header.Get("Authorization") != "Bearer test-openrouter-key" {
			t.Fatalf("provider request = %s %s auth=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"completion-1","object":"chat.completion","model":"openai/gpt-4o-mini","choices":[]}`))
	}))
	defer provider.Close()
	config := Config{Listen: DefaultListen, Upstreams: []Upstream{{Name: "openrouter", BaseURL: provider.URL + "/api/v1", Credential: "openrouter-api-key"}}, Models: []Model{{Alias: "operations", Upstream: "openrouter", Model: "openai/gpt-4o-mini"}}}
	router, err := NewRouter(config, credentials)
	if err != nil {
		t.Fatal(err)
	}
	router.client = provider.Client()
	requestBody := []byte(`{"model":"operations","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function"}],"response_format":{"type":"json_schema"},"max_tokens":32}`)
	request := httptest.NewRequest(http.MethodPost, "http://router/v1/chat/completions", bytes.NewReader(requestBody))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "completion-1") || !strings.Contains(response.Body.String(), `"model":"operations"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if received["model"] != "openai/gpt-4o-mini" || received["tools"] == nil || received["response_format"] == nil {
		t.Fatalf("provider payload lost compatibility fields: %#v", received)
	}
}

func TestRouterRejectsUndeclaredModelsAndUnsupportedRoutes(t *testing.T) {
	credentials := t.TempDir()
	if err := os.WriteFile(filepath.Join(credentials, "key"), []byte("test-key"), 0o400); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(Config{Upstreams: []Upstream{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", Credential: "key"}}, Models: []Model{{Alias: "operations", Upstream: "openrouter", Model: "openai/gpt-4o-mini"}}}, credentials)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body string
		path string
		want int
	}{
		{name: "unknown model", body: `{"model":"other","messages":[]}`, path: "/v1/chat/completions", want: http.StatusNotFound},
		{name: "provider model is not an alias", body: `{"model":"openai/gpt-4o-mini","messages":[]}`, path: "/v1/chat/completions", want: http.StatusBadRequest},
		{name: "unsupported route", body: `{}`, path: "/v1/embeddings", want: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://router"+test.path, strings.NewReader(test.body))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestRouterModelDiscoveryIsDeterministic(t *testing.T) {
	credentials := t.TempDir()
	if err := os.WriteFile(filepath.Join(credentials, "key"), []byte("test-key"), 0o400); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(Config{Upstreams: []Upstream{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", Credential: "key"}}, Models: []Model{{Alias: "zeta", Upstream: "openrouter", Model: "z"}, {Alias: "alpha", Upstream: "openrouter", Model: "a"}}}, credentials)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://router/v1/models", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"id":"alpha"`)) || bytes.Index(data, []byte(`"id":"alpha"`)) > bytes.Index(data, []byte(`"id":"zeta"`)) {
		t.Fatalf("model discovery is not ordered: %s", data)
	}
}

func TestConfigRejectsUnsafeCredentialAndProviderURLs(t *testing.T) {
	for name, config := range map[string]Config{
		"credential traversal": {Upstreams: []Upstream{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", Credential: "../key"}}, Models: []Model{{Alias: "operations", Upstream: "openrouter", Model: "openai/model"}}},
		"http provider":        {Upstreams: []Upstream{{Name: "openrouter", BaseURL: "http://openrouter.ai/api/v1", Credential: "key"}}, Models: []Model{{Alias: "operations", Upstream: "openrouter", Model: "openai/model"}}},
		"redirect query":       {Upstreams: []Upstream{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1?next=evil", Credential: "key"}}, Models: []Model{{Alias: "operations", Upstream: "openrouter", Model: "openai/model"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := config.Validate(); err == nil {
				t.Fatal("unsafe config was accepted")
			}
		})
	}
}

func TestRouterRejectsSymlinkedCredential(t *testing.T) {
	credentials := t.TempDir()
	target := filepath.Join(credentials, "target")
	if err := os.WriteFile(target, []byte("test-key"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(credentials, "key")); err != nil {
		t.Fatal(err)
	}
	config := Config{Upstreams: []Upstream{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", Credential: "key"}}, Models: []Model{{Alias: "operations", Upstream: "openrouter", Model: "openai/model"}}}
	if _, err := NewRouter(config, credentials); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("symlinked credential was accepted: %v", err)
	}
}

func TestModelCapabilitiesAreReadFromTheConfiguredProvider(t *testing.T) {
	credentials := t.TempDir()
	if err := os.WriteFile(filepath.Join(credentials, "key"), []byte("test-key"), 0o400); err != nil {
		t.Fatal(err)
	}
	provider := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/models" || request.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("models request = %s auth=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		_, _ = writer.Write([]byte(`{"data":[{"id":"openai/gpt-4o-mini","context_length":128000,"top_provider":{"max_completion_tokens":4096},"supported_parameters":["tools","tool_choice","response_format"]}]}`))
	}))
	defer provider.Close()
	config := Config{Upstreams: []Upstream{{Name: "openrouter", BaseURL: provider.URL + "/api/v1", Credential: "key"}}, Models: []Model{{Alias: "operations", Upstream: "openrouter", Model: "openai/gpt-4o-mini"}}}
	router, err := NewRouter(config, credentials)
	if err != nil {
		t.Fatal(err)
	}
	router.client = provider.Client()
	capabilities, err := router.ModelCapabilities(context.Background(), "operations")
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.Mode != "chat" || !capabilities.SupportsFunctionCalling || !capabilities.SupportsResponseSchema || capabilities.MaxInputTokens != 128000 || capabilities.MaxOutputTokens != 4096 {
		t.Fatalf("provider capabilities = %#v", capabilities)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://router/internal/model-capabilities/operations", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"max_output_tokens":4096`) {
		t.Fatalf("loopback capabilities response = %d %s", response.Code, response.Body.String())
	}
}

func TestLoadConfigDefaultsToLoopbackListenAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	contents := `{"upstreams":[{"name":"openrouter","base_url":"https://openrouter.ai/api/v1","credential":"key"}],"models":[{"alias":"operations","upstream":"openrouter","model":"openai/model"}]}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Listen != DefaultListen {
		t.Fatalf("listen = %q, want %q", config.Listen, DefaultListen)
	}
}
