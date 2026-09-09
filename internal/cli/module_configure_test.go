package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

func writeConfigureSite(t *testing.T, dir string, config model.SiteConfig) {
	t.Helper()
	data, err := model.RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "site.yml"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureBifrostWithARRKeepsOwnedReservationUnique(t *testing.T) {
	dir := t.TempDir()
	identityPath, recipient := writeTestAgeIdentity(t)
	config := model.ConfigFromSite(model.NewSite("installation", recipient, model.GatewayModeManaged))
	enabled := true
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "australia"}
	config.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	writeConfigureSite(t, dir, config)
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := site.StoreEncryptedDocument(dir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"placeholder": "present"}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := RunWithInput([]string{
		"module", "bifrost", "configure", "--site", dir, "--age-identity", identityPath,
		"--non-interactive", "--enabled", "true", "--set", "network=direct",
		"--set", `upstreams=[{"name":"openrouter","base_url":"https://openrouter.ai/api/v1","api_key_secret":"openrouter_api_key"}]`,
		"--set", `models=[{"alias":"operations-investigator","upstream":"openrouter","model":"openai/gpt-5-mini"}]`,
		"--secret", "openrouter_api_key", "--confirm",
	}, strings.NewReader("test-openrouter-key\n"), &output, &output)
	if err != nil {
		t.Fatalf("configure Bifrost alongside ARR: %v\n%s", err, output.String())
	}
	loaded, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _, err := modules.Compose(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.DHCPReservations) != 1 || resolved.DHCPReservations[0].Address != model.ArrGuestAddress {
		t.Fatalf("ARR reservation was duplicated or missing: %#v", resolved.DHCPReservations)
	}
}

func TestConfigureAIOpsNonInteractiveHoldsForMissingAlias(t *testing.T) {
	dir := t.TempDir()
	writeConfigureSite(t, dir, model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged)))
	var output bytes.Buffer
	err := Run([]string{"module", "aiops", "configure", "--site", dir, "--enabled", "true", "--json"}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "lifecycle is owned by module observability") {
		t.Fatalf("AIOps configure escaped the observability lifecycle boundary: %v; output=%s", err, output.String())
	}
}

func TestConfigureRejectsObjectListAboveSchemaMaximum(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value any
		want  string
	}{
		{
			name:  "upstreams",
			field: "upstreams",
			value: func() []model.BifrostUpstreamConfig {
				values := make([]model.BifrostUpstreamConfig, 17)
				for index := range values {
					values[index] = model.BifrostUpstreamConfig{Name: fmt.Sprintf("provider-%d", index), BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}
				}
				return values
			}(),
			want: "upstreams requires between 1 and 16 entries",
		},
		{
			name:  "models",
			field: "models",
			value: func() []model.BifrostModelConfig {
				values := make([]model.BifrostModelConfig, 33)
				for index := range values {
					values[index] = model.BifrostModelConfig{Alias: fmt.Sprintf("model-%d", index), Upstream: "provider", Model: "provider/model"}
				}
				return values
			}(),
			want: "models requires between 1 and 32 entries",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeConfigureSite(t, dir, model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged)))
			value, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = Run([]string{"module", "bifrost", "configure", "--site", dir, "--enabled", "true", "--set", tc.field + "=" + string(value), "--json"}, &output, &output)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("oversized %s was accepted: %v; output=%s", tc.field, err, output.String())
			}
		})
	}
}

func TestConfigureAIOpsIsRejectedOutsideObservabilityLifecycle(t *testing.T) {
	dir := t.TempDir()
	identityPath, recipient := writeTestAgeIdentity(t)
	config := model.ConfigFromSite(model.NewSite("installation", recipient, model.GatewayModeManaged))
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	writeConfigureSite(t, dir, config)
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := site.StoreEncryptedDocument(dir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"provider_key": "present"}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := Run([]string{"module", "aiops", "configure", "--site", dir, "--enabled", "true", "--set", "model_alias=operations", "--json", "--age-identity", identityPath}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "lifecycle is owned by module observability") {
		t.Fatalf("AIOps configure escaped lifecycle boundary: %v", err)
	}
}

func TestConfigureConfirmationRefusalLeavesConfigurationUnchanged(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	writeConfigureSite(t, dir, config)
	var output bytes.Buffer
	err := RunWithInput([]string{"module", "monitoring", "configure", "--site", dir}, strings.NewReader("n\nn\n"), &output, &output)
	if err == nil || !strings.Contains(err.Error(), "lifecycle is owned by module observability") {
		t.Fatalf("monitoring configure escaped lifecycle boundary: %v", err)
	}
	loaded, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Modules.Monitoring != nil && loaded.Modules.Monitoring.Enabled != nil && !*loaded.Modules.Monitoring.Enabled {
		t.Fatal("confirmation refusal persisted disablement")
	}
}

func TestConfigureDependencyPlanUsesRegistryDependencies(t *testing.T) {
	current, _, err := modules.Compose(model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged)))
	if err != nil {
		t.Fatal(err)
	}
	config := model.ConfigFromSite(current)
	enabled := true
	config.Modules.AIOps = &model.AIOpsModuleConfig{Enabled: &enabled, ModelAlias: "operations"}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	proposed, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := newlyEnabledDependencies(current, proposed, "aiops")
	for _, wanted := range []string{"bifrost"} {
		found := false
		for _, dependency := range dependencies {
			found = found || dependency == wanted
		}
		if !found {
			t.Fatalf("dependency %s missing from %v", wanted, dependencies)
		}
	}
}

func TestConfigureUSBObservationRejectsAmbiguousPort(t *testing.T) {
	if _, err := parseConfigureUSBObservation("1-2.3 1a86:7523 one\n1-2.3 1a86:7523 two\n"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous USB observation was accepted: %v", err)
	}
	devices, err := parseConfigureUSBObservation("1-2.3 1a86:7523 serial\n1-2.4 2341:0043 other\n")
	if err != nil || len(devices) != 2 || devices[0].Port != "1-2.3" {
		t.Fatalf("valid USB observation was not parsed: %#v, %v", devices, err)
	}
}

func TestConfigureSensitiveFieldIsStructurallyRedacted(t *testing.T) {
	before := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	after := before
	after.Modules.Bifrost = &model.BifrostModuleConfig{Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "super-secret"}}, Models: []model.BifrostModelConfig{{Alias: "ops", Upstream: "provider", Model: "provider/model"}}}
	fields, err := modules.FirstPartyRegistry().ConfigurationFields("bifrost", after)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := modules.Compose(before)
	if err != nil {
		t.Fatal(err)
	}
	proposed, _, err := modules.Compose(after)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := configureChanges("bifrost", before, after, current, proposed, fields, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(changes)
	if strings.Contains(string(data), "super-secret") {
		t.Fatalf("sensitive field leaked into change report: %s", data)
	}
}

func TestConfigureRejectsPlatformOwnedSecretReference(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	enabled := true
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &enabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "root_key_pem_b64"}},
		Models:    []model.BifrostModelConfig{{Alias: "ops", Upstream: "provider", Model: "provider/model"}},
	}
	proposed, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = configureSecrets(t.TempDir(), proposed, proposed, "identity", "bifrost", nil, strings.NewReader(""), &bytes.Buffer{}, true, nil)
	if err == nil || !strings.Contains(err.Error(), "platform-owned") {
		t.Fatalf("platform-owned secret reference was accepted: %v", err)
	}
}

func TestConfigureSecretsIgnoreUnrelatedModuleSecrets(t *testing.T) {
	dir := t.TempDir()
	identityPath, recipient := writeTestAgeIdentity(t)
	config := model.ConfigFromSite(model.NewSite("installation", recipient, model.GatewayModeManaged))
	enabled := true
	config.Modules.Monitoring = &model.ToggleModuleConfig{Enabled: &enabled}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &enabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	current, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := site.StoreEncryptedDocument(dir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"unrelated": "keep", "pulse_proxy_auth_secret": "test-only"}); err != nil {
		t.Fatal(err)
	}
	updates, missing, err := configureSecrets(dir, current, current, identityPath, "monitoring", nil, strings.NewReader(""), &bytes.Buffer{}, true, nil)
	if err != nil {
		t.Fatalf("unrelated Bifrost secret blocked monitoring configure: %v", err)
	}
	if len(updates) != 0 || len(missing) != 0 {
		t.Fatalf("unrelated module secret was included: updates=%v missing=%v", updates, missing)
	}
}
