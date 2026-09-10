package cli

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestPrepareObservabilityApplyRequiresExplicitDomainAndLeavesHolmesOff(t *testing.T) {
	config := controllerhost.LabConfig{Name: "lab", Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}}
	if _, err := prepareObservabilityApplyConfig(config, "", ""); err == nil || !strings.Contains(err.Error(), "--public-domain") {
		t.Fatalf("missing public domain was not rejected: %v", err)
	}
	prepared, err := prepareObservabilityApplyConfig(config, "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Modules.Observability == nil || prepared.Modules.Observability.PublicDomain != "example.com" || prepared.Modules.Observability.Monitoring.Holmes != nil {
		t.Fatalf("fresh apply implicitly changed Holmes monitoring: %#v", prepared.Modules)
	}
	if config.Modules.Observability != nil {
		t.Fatal("preparation mutated the input configuration")
	}
}

func TestPrepareObservabilityApplyExplicitHolmesModelPreservesExistingSettings(t *testing.T) {
	enabled := true
	config := controllerhost.LabConfig{Name: "lab", Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}, Modules: clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, PublicDomain: "example.com"}}}
	prepared, err := prepareObservabilityApplyConfig(config, "", "openai/gpt-4.1-mini")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Modules.Observability == nil || prepared.Modules.Observability.Monitoring.Holmes == nil || prepared.Modules.Observability.Monitoring.Holmes.ModelAlias != "operations" || !clientservices.Enabled(prepared.Modules.Observability.Monitoring.Holmes.Enabled) {
		t.Fatalf("explicit Holmes route was not prepared: %#v", prepared.Modules.Observability)
	}
	model := prepared.Modules.Observability.Monitoring.Holmes.Bifrost.Models[0]
	if model.Upstream != "openrouter" || model.Model != "openai/gpt-4.1-mini" || prepared.Modules.Observability.Monitoring.Holmes.Bifrost.ClientCredential != "holmes-client-token" {
		t.Fatalf("explicit Bifrost route = %#v", prepared.Modules.Observability.Monitoring.Holmes.Bifrost)
	}
	if config.Modules.Observability == nil || config.Modules.Observability.Monitoring.Holmes != nil || config.Modules.Observability.PublicDomain != "example.com" {
		t.Fatal("explicit preparation mutated the input configuration")
	}
}

func TestMissingObservabilitySecretsListsRequiredNamesWithoutValues(t *testing.T) {
	enabled := true
	modules := clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, PublicDomain: "example.com"}}
	missing := missingObservabilitySecrets(modules, map[string][]byte{})
	if strings.Join(missing, ",") != "cloudflare-dns-token,grafana-admin-password" {
		t.Fatalf("missing secret set = %#v", missing)
	}
}
