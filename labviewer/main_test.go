package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactHidesSecretShapedFields(t *testing.T) {
	input := map[string]any{"token": "do-not-leak", "nested": map[string]any{"api_key": "also-secret", "label": "visible"}}
	output := redact(input)
	b, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "do-not-leak") || strings.Contains(string(b), "also-secret") {
		t.Fatalf("secret leaked in %s", b)
	}
	if !strings.Contains(string(b), "visible") {
		t.Fatalf("non-secret value was removed: %s", b)
	}
}
