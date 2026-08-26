package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/schema"
)

// This small generator keeps the checked-in editor contract tied to the
// exported configuration vocabulary. Runtime YAML validation remains the
// authority for cross-field and dependency invariants.
func main() {
	output := flag.String("output", "schemas/site.schema.json", "generated schema output path")
	embeddedOutput := flag.String("embedded-output", "", "optional embedded schema output path")
	flag.Parse()
	data, err := schema.GenerateSiteSchema()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		panic(fmt.Errorf("write schema: %w", err))
	}
	if *embeddedOutput != "" {
		if err := os.WriteFile(*embeddedOutput, data, 0o644); err != nil {
			panic(fmt.Errorf("write embedded schema: %w", err))
		}
	}
}
