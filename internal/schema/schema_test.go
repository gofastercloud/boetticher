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
		"platform_version": "0.3.29",
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
	if _, ok := dns.Properties["provider"]; !ok {
		t.Fatal("DNS module schema omitted provider")
	}
	if _, ok := dns.Properties["enabled"]; ok {
		t.Fatal("DNS module schema exposes forbidden enabled field")
	}
	for _, name := range []string{"DNSModuleConfig", "MandatoryModuleConfig"} {
		definition, ok := document.Definitions[name]
		if !ok {
			t.Fatalf("schema definition %s is missing", name)
		}
		if _, ok := definition.Properties["enabled"]; ok {
			t.Fatalf("schema definition %s exposes forbidden enabled field", name)
		}
	}

	logging, ok := modules.Properties["logging"]
	if !ok {
		t.Fatal("logging module schema property is absent")
	}
	var loggingRef struct {
		Ref string `json:"$ref"`
	}
	if err := json.Unmarshal(logging, &loggingRef); err != nil {
		t.Fatal(err)
	}
	if loggingRef.Ref != "#/$defs/MandatoryModuleConfig" {
		t.Fatalf("logging module schema ref = %q", loggingRef.Ref)
	}
}
