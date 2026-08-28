package aiops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type ModelCapabilities struct {
	Mode                    string `json:"mode"`
	SupportsFunctionCalling *bool  `json:"supports_function_calling"`
	SupportsResponseSchema  *bool  `json:"supports_response_schema"`
	MaxInputTokens          *int   `json:"max_input_tokens"`
	MaxOutputTokens         *int   `json:"max_output_tokens"`
}

func (c ModelCapabilities) Validate() error {
	if c.Mode != "chat" || c.SupportsFunctionCalling == nil || !*c.SupportsFunctionCalling || c.SupportsResponseSchema == nil || !*c.SupportsResponseSchema || c.MaxInputTokens == nil || *c.MaxInputTokens < 32768 || c.MaxOutputTokens == nil || *c.MaxOutputTokens < MaxOutputTokens {
		return errors.New("model metadata does not prove the Holmes capability requirements")
	}
	return nil
}

func DecodeModelCapabilities(data []byte) (ModelCapabilities, error) {
	var capabilities ModelCapabilities
	if len(data) == 0 || len(data) > 4096 || strictDecode(bytes.NewReader(data), &capabilities) != nil {
		return capabilities, errors.New("AI Router model metadata is invalid or unbounded")
	}
	return capabilities, capabilities.Validate()
}

// QualifyModelAlias performs a two-turn live canary. The first response must
// produce the exact strict tool call; the second must satisfy the requested
// JSON response schema. No provider name, model identifier, or credential is
// accepted from AIOps configuration.
func QualifyModelAlias(ctx context.Context, client *http.Client, endpoint, alias string) error {
	if client == nil || !safeToken(alias) {
		return errors.New("model canary requires a bounded alias and mTLS client")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || !strings.HasPrefix(parsed.Hostname(), "ai.") || parsed.Port() != "" || parsed.Path != "/v1/chat/completions" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("model canary requires the exact AI Router chat endpoint")
	}
	tool := map[string]any{"type": "function", "function": map[string]any{"name": "qualification_probe", "description": "Return the supplied qualification nonce", "strict": true, "parameters": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"nonce": map[string]any{"type": "string", "enum": []string{"boetticher-aiops-v1"}}}, "required": []string{"nonce"}}}}
	messages := []map[string]any{{"role": "system", "content": "Call qualification_probe exactly once with the required nonce, then return only the requested JSON result after the tool response."}, {"role": "user", "content": "Run the qualification probe."}}
	first, err := modelCanaryRequest(ctx, client, endpoint, alias, messages, []any{tool}, map[string]any{"type": "function", "function": map[string]any{"name": "qualification_probe"}})
	if err != nil {
		return fmt.Errorf("strict tool canary: %w", err)
	}
	if len(first.ToolCalls) != 1 || first.ToolCalls[0].Function.Name != "qualification_probe" {
		return errors.New("strict tool canary did not return the one authorized tool")
	}
	var arguments struct {
		Nonce string `json:"nonce"`
	}
	if strictDecode(bytes.NewBufferString(first.ToolCalls[0].Function.Arguments), &arguments) != nil || arguments.Nonce != "boetticher-aiops-v1" {
		return errors.New("strict tool canary returned invalid arguments")
	}
	messages = append(messages, map[string]any{"role": "assistant", "tool_calls": first.ToolCalls}, map[string]any{"role": "tool", "tool_call_id": first.ToolCalls[0].ID, "content": `{"accepted":true}`})
	second, err := modelCanaryRequest(ctx, client, endpoint, alias, messages, nil, nil)
	if err != nil {
		return fmt.Errorf("response-schema canary: %w", err)
	}
	var result struct {
		Status string `json:"status"`
	}
	if strictDecode(bytes.NewBufferString(second.Content), &result) != nil || result.Status != "qualified" {
		return errors.New("response-schema canary did not return the qualified contract")
	}
	return nil
}

type canaryMessage struct {
	Content   string `json:"content"`
	ToolCalls []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

func modelCanaryRequest(ctx context.Context, client *http.Client, endpoint, alias string, messages []map[string]any, tools []any, toolChoice any) (canaryMessage, error) {
	request := map[string]any{
		"model": alias, "messages": messages, "max_tokens": 32,
	}
	if len(tools) > 0 {
		request["tools"] = tools
		request["tool_choice"] = toolChoice
	} else {
		request["response_format"] = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name": "BoetticherAIOpsQualification", "strict": true,
				"schema": map[string]any{
					"type": "object", "additionalProperties": false,
					"properties": map[string]any{"status": map[string]any{"type": "string", "enum": []string{"qualified"}}},
					"required":   []string{"status"},
				},
			},
		}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return canaryMessage{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return canaryMessage{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return canaryMessage{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return canaryMessage{}, errors.New("model canary response exceeded its bound")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return canaryMessage{}, fmt.Errorf("AI Router returned HTTP %d", response.StatusCode)
	}
	var completion struct {
		Choices []struct {
			Message canaryMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &completion); err != nil || len(completion.Choices) != 1 {
		return canaryMessage{}, errors.New("model canary returned an invalid completion")
	}
	return completion.Choices[0].Message, nil
}
