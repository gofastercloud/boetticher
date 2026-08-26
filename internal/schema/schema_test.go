package schema

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEmbeddedSchemaMatchesAuthoritativeGenerator(t *testing.T) {
	generated, err := GenerateSiteSchema()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, SiteSchema) {
		t.Fatal("embedded site schema is stale; run make schema")
	}
}

func TestEmbeddedSchemaProjectsTypedModuleConstraints(t *testing.T) {
	var document struct {
		Properties map[string]struct {
			Const any `json:"const"`
		} `json:"properties"`
		Definitions map[string]struct {
			AdditionalProperties bool                       `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(SiteSchema, &document); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]any{
		"api_version":      "boetticher/v3",
		"platform_version": "0.3.1",
		"schema_version":   float64(3),
	} {
		if got := document.Properties[field].Const; got != want {
			t.Fatalf("schema %s const = %#v, want %#v", field, got, want)
		}
	}
	modules, ok := document.Definitions["ModulesConfig"]
	if !ok || modules.AdditionalProperties {
		t.Fatal("module configuration is not a closed typed object")
	}
	dns, ok := document.Definitions["DNSModuleConfig"]
	if !ok {
		t.Fatal("DNS module definition is absent from schema")
	}
	for _, field := range []string{"provider", "enabled"} {
		if _, ok := dns.Properties[field]; !ok {
			t.Fatalf("DNS module schema omitted %s", field)
		}
	}
}
