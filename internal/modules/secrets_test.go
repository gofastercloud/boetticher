package modules

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestSecretDeclarationsReconstructDisabledTailnet(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	falseValue := false
	if err := config.Modules.Set("tailnet-router", model.ModuleConfig{Enabled: &falseValue}); err != nil {
		t.Fatal(err)
	}
	declarations, err := SecretDeclarations(config, "tailnet-router")
	if err != nil {
		t.Fatal(err)
	}
	if len(declarations) != 1 || declarations[0].Name != "tailscale_auth_key" || declarations[0].Generation != "operator-supplied" || declarations[0].Lifecycle != model.SecretLifecycleBootstrap {
		t.Fatalf("unexpected disabled Tailnet secret contract: %#v", declarations)
	}
}

func TestSecretDeclarationsDeduplicateLiteLLMReferences(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	trueValue := true
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled: &trueValue,
		Upstreams: []model.LiteLLMUpstreamConfig{
			{Name: "one", BaseURL: "https://one.example.test/api", APIKeySecret: "shared_key"},
			{Name: "two", BaseURL: "https://two.example.test/api", APIKeySecret: "shared_key"},
		},
		Models: []model.LiteLLMModelConfig{{Alias: "one", Upstream: "one", Model: "provider/model"}},
	}
	declarations, err := SecretDeclarations(config, "litellm")
	if err != nil {
		t.Fatal(err)
	}
	if len(declarations) != 1 || declarations[0].Name != "shared_key" {
		t.Fatalf("LiteLLM secret references were not deduplicated: %#v", declarations)
	}
}

func TestSecretDeclarationsRejectUnconfiguredLiteLLM(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	if _, err := SecretDeclarations(config, "litellm"); err == nil {
		t.Fatal("unconfigured LiteLLM secret contract was accepted")
	}
}
