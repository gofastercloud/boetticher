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
		"platform_version": "0.5.0",
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
	if len(dns.Properties) != 0 {
		t.Fatalf("DNS module schema exposes non-default settings: %#v", dns.Properties)
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
	for _, name := range []string{"monitoring", "firewall", "tailnet-router"} {
		var ref struct {
			Ref string `json:"$ref"`
		}
		if err := json.Unmarshal(modules.Properties[name], &ref); err != nil {
			t.Fatalf("decode %s module schema ref: %v", name, err)
		}
		if ref.Ref != "#/$defs/ToggleModuleConfig" {
			t.Fatalf("%s module schema ref = %q", name, ref.Ref)
		}
	}
	for _, name := range []string{"printer", "gatus"} {
		var ref struct {
			Ref string `json:"$ref"`
		}
		if err := json.Unmarshal(modules.Properties[name], &ref); err != nil {
			t.Fatalf("decode %s module schema ref: %v", name, err)
		}
		if ref.Ref != "#/$defs/NetworkToggleModuleConfig" {
			t.Fatalf("%s module schema ref = %q", name, ref.Ref)
		}
	}
	var arrRef struct {
		Ref string `json:"$ref"`
	}
	if err := json.Unmarshal(modules.Properties["arr"], &arrRef); err != nil {
		t.Fatalf("decode arr module schema ref: %v", err)
	}
	if arrRef.Ref != "#/$defs/ArrModuleConfig" {
		t.Fatalf("arr module schema ref = %q", arrRef.Ref)
	}
	if _, ok := document.Definitions["ToggleModuleConfig"].Properties["network"]; ok {
		t.Fatal("non-network toggle schema exposes network")
	}
	var arrNetwork struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(document.Definitions["ArrModuleConfig"].Properties["network"], &arrNetwork); err != nil {
		t.Fatalf("decode arr network schema: %v", err)
	}
	if len(arrNetwork.Enum) != 1 || arrNetwork.Enum[0] != "airvpn" {
		t.Fatalf("arr network schema = %#v, want only airvpn", arrNetwork.Enum)
	}
}
