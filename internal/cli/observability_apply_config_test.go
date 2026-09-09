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
	prepared, err := prepareObservabilityApplyConfig(config, "davebarton.cc", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Modules.Observability == nil || prepared.Modules.Observability.PublicDomain != "davebarton.cc" || prepared.Modules.AIOps != nil {
		t.Fatalf("fresh apply implicitly changed Holmes/AIOps: %#v", prepared.Modules)
	}
	if config.Modules.Observability != nil || config.Modules.AIOps != nil {
		t.Fatal("preparation mutated the input configuration")
	}
}

func TestPrepareObservabilityApplyExplicitHolmesModelPreservesExistingSettings(t *testing.T) {
	enabled := true
	config := controllerhost.LabConfig{Name: "lab", Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}, Modules: clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, PublicDomain: "davebarton.cc"}}}
	prepared, err := prepareObservabilityApplyConfig(config, "", "openai/gpt-4.1-mini")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Modules.AIOps == nil || prepared.Modules.AIOps.Holmes == nil || prepared.Modules.AIOps.Holmes.ModelAlias != "operations" || !clientservices.Enabled(prepared.Modules.AIOps.Holmes.Enabled) {
		t.Fatalf("explicit Holmes route was not prepared: %#v", prepared.Modules.AIOps)
	}
	model := prepared.Modules.AIOps.Holmes.Bifrost.Models[0]
	if model.Upstream != "openrouter" || model.Model != "openai/gpt-4.1-mini" || prepared.Modules.AIOps.Holmes.Bifrost.ClientCredential != "holmes-client-token" {
		t.Fatalf("explicit Bifrost route = %#v", prepared.Modules.AIOps.Holmes.Bifrost)
	}
	if config.Modules.AIOps != nil {
		t.Fatal("explicit preparation mutated the input configuration")
	}
}

func TestMissingObservabilitySecretsListsRequiredNamesWithoutValues(t *testing.T) {
	enabled := true
	modules := clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, PublicDomain: "davebarton.cc"}}
	missing := missingObservabilitySecrets(modules, map[string][]byte{})
	if strings.Join(missing, ",") != "cloudflare-dns-token,grafana-admin-password" {
		t.Fatalf("missing secret set = %#v", missing)
	}
}
