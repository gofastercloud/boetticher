package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/invopop/jsonschema"
)

// SiteSchema is the checked-in schema shipped with the boetticher binary.
// It is generated from model.SiteConfig; runtime validation remains the
// authority for semantic and dependency invariants.
//
//go:embed site.schema.json
var SiteSchema []byte

func GenerateSiteSchema() ([]byte, error) {
	reflector := &jsonschema.Reflector{
		BaseSchemaID:   "https://boetticher.dev/schemas",
		ExpandedStruct: true,
	}
	document := reflector.Reflect(model.SiteConfig{})
	document.ID = "https://boetticher.dev/schemas/site.schema.json"
	document.Title = "boetticher v3 SiteConfig"
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SiteConfig schema: %w", err)
	}
	// The generator reflects Go structure and field constraints. Version
	// constants are semantic defaults of the platform contract, so add them to
	// the generated projection explicitly rather than duplicating SiteConfig.
	var projection map[string]any
	if err := json.Unmarshal(data, &projection); err != nil {
		return nil, fmt.Errorf("decode generated SiteConfig schema: %w", err)
	}
	properties, ok := projection["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("generated SiteConfig schema has no root properties")
	}
	for field, value := range map[string]any{
		"api_version":      model.APIVersion,
		"platform_version": model.PlatformVersion,
		"schema_version":   model.SchemaVersion,
	} {
		property, ok := properties[field].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("generated SiteConfig schema has no %s property", field)
		}
		property["const"] = value
	}
	data, err = json.MarshalIndent(projection, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SiteConfig schema projection: %w", err)
	}
	return append(data, '\n'), nil
}

func Data() []byte {
	return append([]byte(nil), SiteSchema...)
}
