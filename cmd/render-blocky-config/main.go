package main

import (
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

// This build helper keeps artifact qualification on the canonical Go
// renderer rather than duplicating provider configuration in shell or YAML.
func main() {
	siteConfig := model.ConfigFromSite(model.NewSite("artifact-qualification", "age1artifactqualification", model.GatewayModeManaged))
	site, _, err := modules.Compose(siteConfig)
	if err != nil {
		fatal(err)
	}
	plan, err := dns.PlanFromSite(site)
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
