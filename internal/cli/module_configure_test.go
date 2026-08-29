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

func TestConfigureJSONDryRunIsRedactedAndDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	disabled := false
	config.Modules.Printer = &model.ToggleModuleConfig{Enabled: &disabled}
	config.USBExports = []model.USBExportBinding{{Module: "printer", Requirement: "serial", Port: "1-2.3", VendorID: "1a86", ProductID: "7523"}}
	writeConfigureSite(t, dir, config)
	original, err := os.ReadFile(filepath.Join(dir, "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run([]string{"module", "configure", "printer", "--site", dir, "--enabled", "true", "--dry-run", "--json"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	var report moduleConfigureReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("configure JSON is invalid: %v: %s", err, output.String())
	}
	if report.Status != "DRY_RUN" || !report.ProposedEnabled || len(report.Changes) == 0 {
		t.Fatalf("unexpected configure report: %#v", report)
	}
	current, err := os.ReadFile(filepath.Join(dir, "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, current) {
		t.Fatal("dry-run changed site.yml")
	}
}

func TestConfigureJSONApplyIsDesiredStateOnlyAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	disabled := false
	config.Modules.Printer = &model.ToggleModuleConfig{Enabled: &disabled}
	config.USBExports = []model.USBExportBinding{{Module: "printer", Requirement: "serial", Port: "1-2.3", VendorID: "1a86", ProductID: "7523"}}
	writeConfigureSite(t, dir, config)
	var output bytes.Buffer
	if err := Run([]string{"module", "configure", "printer", "--site", dir, "--enabled", "true", "--json", "--confirm"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	var report moduleConfigureReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Status != "APPLIED" {
		t.Fatalf("unexpected apply report: %v %#v", err, report)
	}
	loaded, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Modules.Printer == nil || loaded.Modules.Printer.Enabled == nil || !*loaded.Modules.Printer.Enabled {
		t.Fatal("configure did not persist desired printer enablement")
	}
	output.Reset()
	if err := Run([]string{"module", "configure", "printer", "--site", dir, "--enabled", "true", "--json", "--confirm"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"status":"NO_CHANGES"`) {
		t.Fatalf("configure rerun was not idempotent: %s", output.String())
	}
}

func TestConfigureFirewallBackendPersistsBeforeBootstrap(t *testing.T) {
	dir := t.TempDir()
	writeConfigureSite(t, dir, model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged)))
	var output bytes.Buffer
	if err := Run([]string{"module", "configure", "firewall", "--site", dir, "--enabled", "true", "--set", "backend=lxc", "--json", "--confirm"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	loaded, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Modules.Firewall == nil || loaded.Modules.Firewall.Backend != model.FirewallBackendLXC {
		t.Fatalf("pre-bootstrap configure did not persist typed LXC backend: %#v", loaded.Modules.Firewall)
	}
	if !strings.Contains(output.String(), `"status":"APPLIED"`) {
		t.Fatalf("unexpected configure result: %s", output.String())
	}
}

func TestConfigureFirewallRejectsUnvalidatedBackend(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	writeConfigureSite(t, dir, config)
	var output bytes.Buffer
	if err := Run([]string{"module", "configure", "firewall", "--site", dir, "--enabled", "true", "--set", "backend=privileged-lxc", "--json"}, &output, &output); err == nil || !strings.Contains(err.Error(), "allowed values") {
		t.Fatalf("invalid backend was accepted: %v; output=%s", err, output.String())
	}
	loaded, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Modules.Firewall != nil && loaded.Modules.Firewall.Backend != "" {
		t.Fatalf("invalid backend changed desired state: %#v", loaded.Modules.Firewall)
	}
}

func TestConfigureNonInteractiveHoldsForMissingUSB(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	writeConfigureSite(t, dir, config)
	var output bytes.Buffer
	err := Run([]string{"module", "configure", "printer", "--site", dir, "--enabled", "true", "--json"}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "required USB printer/serial is not configured") {
		t.Fatalf("missing USB was not held: %v; output=%s", err, output.String())
	}
	if strings.Contains(output.String(), "super-secret") {
		t.Fatal("secret value appeared in configure output")
	}
	var report moduleConfigureReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("HOLD JSON is invalid: %v: %s", err, output.String())
	}
	if report.Status != "HOLD" {
		t.Fatalf("unexpected HOLD report: %#v", report)
	}
}

func TestConfigureAIOpsNonInteractiveHoldsForMissingAlias(t *testing.T) {
	dir := t.TempDir()
	writeConfigureSite(t, dir, model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged)))
	var output bytes.Buffer
	err := Run([]string{"module", "configure", "aiops", "--site", dir, "--enabled", "true", "--json"}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "required module configuration model_alias") {
		t.Fatalf("missing AIOps alias was not held: %v; output=%s", err, output.String())
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
			value: func() []model.LiteLLMUpstreamConfig {
				values := make([]model.LiteLLMUpstreamConfig, 17)
				for index := range values {
					values[index] = model.LiteLLMUpstreamConfig{Name: fmt.Sprintf("provider-%d", index), BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}
				}
				return values
			}(),
			want: "upstreams requires between 1 and 16 entries",
		},
		{
			name:  "models",
			field: "models",
			value: func() []model.LiteLLMModelConfig {
				values := make([]model.LiteLLMModelConfig, 33)
				for index := range values {
					values[index] = model.LiteLLMModelConfig{Alias: fmt.Sprintf("model-%d", index), Upstream: "provider", Model: "provider/model"}
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
			err = Run([]string{"module", "configure", "litellm", "--site", dir, "--enabled", "true", "--set", tc.field + "=" + string(value), "--json"}, &output, &output)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("oversized %s was accepted: %v; output=%s", tc.field, err, output.String())
			}
		})
	}
}

func TestConfigureAIOpsUsesOnlyDeclaredRouterAlias(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	writeConfigureSite(t, dir, config)
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "boetticher.sops.yaml"), []byte("provider_key: present\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "sops"), []byte("#!/bin/sh\nlast=\"\"\nfor arg do last=\"$arg\"; done\nif [ \"$1\" = \"--decrypt\" ]; then cat \"$last\"; else cat; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	if err := Run([]string{"module", "configure", "aiops", "--site", dir, "--enabled", "true", "--set", "model_alias=operations", "--json", "--age-identity", "identity"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	var report moduleConfigureReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("AIOps configure JSON is invalid: %v: %s", err, output.String())
	}
	if report.Status != "PLAN_ONLY" || len(report.Dependencies) != 1 || report.Dependencies[0] != "litellm" {
		t.Fatalf("unexpected AIOps configure report: %#v", report)
	}
	if strings.Contains(output.String(), "present") {
		t.Fatal("secret value leaked from AIOps configure output")
	}
}

func TestConfigureConfirmationRefusalLeavesConfigurationUnchanged(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	writeConfigureSite(t, dir, config)
	var output bytes.Buffer
	if err := RunWithInput([]string{"module", "configure", "monitoring", "--site", dir}, strings.NewReader("n\nn\n"), &output, &output); err != nil {
		t.Fatal(err)
	}
	loaded, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Modules.Monitoring != nil && loaded.Modules.Monitoring.Enabled != nil && !*loaded.Modules.Monitoring.Enabled {
		t.Fatal("confirmation refusal persisted disablement")
	}
	if !strings.Contains(output.String(), "Configuration not changed") {
		t.Fatalf("refusal was not reported: %s", output.String())
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
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	proposed, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := newlyEnabledDependencies(current, proposed, "aiops")
	for _, wanted := range []string{"litellm"} {
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
	after.Modules.LiteLLM = &model.LiteLLMModuleConfig{Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "super-secret"}}, Models: []model.LiteLLMModelConfig{{Alias: "ops", Upstream: "provider", Model: "provider/model"}}}
	fields, err := modules.FirstPartyRegistry().ConfigurationFields("litellm", after)
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
	changes := configureChanges("litellm", before, after, current, proposed, fields, nil)
	data, _ := json.Marshal(changes)
	if strings.Contains(string(data), "super-secret") {
		t.Fatalf("sensitive field leaked into change report: %s", data)
	}
}

func TestConfigureRejectsPlatformOwnedSecretReference(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	enabled := true
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &enabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "root_key_pem_b64"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "ops", Upstream: "provider", Model: "provider/model"}},
	}
	proposed, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = configureSecrets(t.TempDir(), proposed, proposed, "identity", "litellm", nil, strings.NewReader(""), &bytes.Buffer{}, true, nil)
	if err == nil || !strings.Contains(err.Error(), "platform-owned") {
		t.Fatalf("platform-owned secret reference was accepted: %v", err)
	}
}

func TestConfigureSecretsIgnoreUnrelatedModuleSecrets(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	enabled := true
	config.Modules.Monitoring = &model.ToggleModuleConfig{Enabled: &enabled}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &enabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	current, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "boetticher.sops.yaml"), []byte("unrelated: keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "sops"), []byte("#!/bin/sh\nlast=\"\"\nfor arg do last=\"$arg\"; done\nif [ \"$1\" = \"--decrypt\" ]; then cat \"$last\"; else cat; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	updates, missing, err := configureSecrets(dir, current, current, "identity", "monitoring", nil, strings.NewReader(""), &bytes.Buffer{}, true, nil)
	if err != nil {
		t.Fatalf("unrelated LiteLLM secret blocked monitoring configure: %v", err)
	}
	if len(updates) != 0 || len(missing) != 0 {
		t.Fatalf("unrelated module secret was included: updates=%v missing=%v", updates, missing)
	}
}
