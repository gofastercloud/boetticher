package main

import (
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
)

// This build helper keeps artifact qualification on the canonical Go
// renderer rather than duplicating provider configuration in shell or YAML.
func main() {
	plan, err := dns.PlanFromSite(model.NewDefaultSite("artifact-qualification", "age1artifactqualification"))
	if err != nil {
		fatal(err)
	}
	config, err := dns.RenderBlockyConfig(plan)
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stdout.Write(config); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "render Blocky configuration: %v\n", err)
	os.Exit(1)
}
