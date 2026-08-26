package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/model"
)

// This small generator keeps the checked-in editor contract tied to the
// exported configuration vocabulary. Runtime YAML validation remains the
// authority for cross-field and dependency invariants.
func main() {
	output := flag.String("output", "schemas/site.schema.json", "generated schema output path")
	flag.Parse()
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     "https://boetticher.dev/schemas/site.schema.json",
		"title":   "boetticher v3 SiteConfig", "type": "object", "additionalProperties": false,
		"required": []string{"api_version"},
		"properties": map[string]any{
			"api_version":      map[string]any{"const": model.APIVersion},
			"platform_version": map[string]any{"const": model.PlatformVersion},
			"schema_version":   map[string]any{"const": model.SchemaVersion},
			"storage_profile":  map[string]any{"enum": []string{"single-disk", "dedicated-data-disk"}},
			"storage_device":   map[string]any{"type": "string"},
			"gateway":          map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"mode": map[string]any{"enum": []string{"managed", "external"}}}},
			"proxmox_node":     map[string]any{"type": "string"}, "bootstrap_address": map[string]any{"type": "string"}, "ssh_identity_file": map[string]any{"type": "string"},
			"physical_network": map[string]any{"type": "object"}, "tested_versions": map[string]any{"type": "object"}, "network": map[string]any{"type": "object"}, "pki": map[string]any{"type": "object"}, "secret_metadata": map[string]any{"type": "object"}, "ownership": map[string]any{"type": "object"},
			"modules": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
				"dns":        map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"provider": map[string]any{"enum": []string{"blocky", "adguard"}}}},
				"monitoring": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"enabled": map[string]any{"type": "boolean"}}},
				"firewall":   map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"enabled": map[string]any{"type": "boolean"}}},
			}},
		},
	}
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*output, append(data, '\n'), 0o644); err != nil {
		panic(fmt.Errorf("write schema: %w", err))
	}
}
