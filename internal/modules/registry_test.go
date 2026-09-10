package modules

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func testConfig(mode string) model.SiteConfig {
	return model.ConfigFromSite(model.NewSite("installation", "age1example", mode))
}

func TestRegistryExcludesRetiredRuntimeModules(t *testing.T) {
	registry := FirstPartyRegistry()
	for _, name := range []string{"airvpn", "aiops", "logging", "gatus", "printer"} {
		if _, ok := registry.Definition(name); ok {
			t.Fatalf("retired runtime module %q remains registered", name)
		}
	}
	if _, ok := registry.Definition("monitoring"); !ok {
		t.Fatal("unified monitoring capability disappeared")
	}
	if _, ok := registry.Definition("tailnet-router"); !ok {
		t.Fatal("Tailnet capability disappeared")
	}
}

func TestRegistryStillComposesCoreAndCurrentOptionalCapabilities(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled := true
	config.Modules.TailnetRouter = &model.TailnetRouterConfig{Enabled: &enabled}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &enabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, resolved, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) == 0 || !IsEnabled(site, "dns") || !IsEnabled(site, "firewall") {
		t.Fatalf("core capabilities did not compose: %#v", resolved)
	}
	if !IsEnabled(site, "tailnet-router") || !IsEnabled(site, "bifrost") {
		t.Fatalf("current optional capabilities did not compose: %#v", resolved)
	}
}
