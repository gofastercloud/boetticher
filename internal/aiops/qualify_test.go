package aiops

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type qualifyTransport func(*http.Request) (*http.Response, error)

func (f qualifyTransport) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestModelCapabilitiesFailClosedOnUnknownMetadata(t *testing.T) {
	if _, err := DecodeModelCapabilities([]byte(`{"mode":"chat","supports_function_calling":true,"supports_response_schema":null,"max_input_tokens":32768,"max_output_tokens":1200}`)); err == nil {
		t.Fatal("unknown response-schema metadata was accepted")
	}
	capabilities, err := DecodeModelCapabilities([]byte(`{"mode":"chat","supports_function_calling":true,"supports_response_schema":true,"max_input_tokens":32768,"max_output_tokens":1200}`))
	if err != nil || capabilities.MaxInputTokens == nil || *capabilities.MaxInputTokens != 32768 {
		t.Fatalf("valid model metadata = %#v err=%v", capabilities, err)
	}
}

func TestModelCanaryRequiresExactToolAndResponseSchema(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: qualifyTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		data, _ := io.ReadAll(request.Body)
		body := ""
		if requests == 1 {
			if !strings.Contains(string(data), `"tool_choice"`) || strings.Contains(string(data), `"response_format"`) {
				t.Fatalf("first canary request did not isolate tool calling: %s", data)
			}
			body = `{"choices":[{"message":{"content":"","tool_calls":[{"id":"call-1","type":"function","function":{"name":"qualification_probe","arguments":"{\"nonce\":\"boetticher-aiops-v1\"}"}}]}}]}`
		} else {
			if !strings.Contains(string(data), `"response_format"`) || strings.Contains(string(data), `"tool_choice"`) {
				t.Fatalf("second canary request did not isolate response schema: %s", data)
			}
			body = `{"choices":[{"message":{"content":"{\"status\":\"qualified\"}"}}]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
	})}
	if err := QualifyModelAlias(context.Background(), client, "https://ai.example.test/v1/chat/completions", "operations-investigator"); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("canary requests = %d", requests)
	}
}

func TestModelCanaryRejectsAliasSubstitutionAndDynamicEndpoint(t *testing.T) {
	client := &http.Client{Transport: qualifyTransport(func(request *http.Request) (*http.Response, error) {
		return nil, nil
	})}
	if err := QualifyModelAlias(context.Background(), client, "https://attacker.example.test/v1/chat/completions", "operations-investigator"); err == nil {
		t.Fatal("dynamic endpoint was accepted")
	}
	if err := QualifyModelAlias(context.Background(), client, "https://ai.example.test/v1/chat/completions", "provider/model"); err == nil {
		t.Fatal("provider model substitution was accepted")
	}
}
