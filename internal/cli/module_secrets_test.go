package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func TestModuleSecretMutationRejectsPlatformAndSharedNames(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	bifrostEnabled, tailnetEnabled := true, true
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &bifrostEnabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "root_key_pem_b64"}},
		Models:    []model.BifrostModelConfig{{Alias: "qwen", Upstream: "openrouter", Model: "some/model"}},
	}
	config.Modules.TailnetRouter = &model.TailnetRouterConfig{Enabled: &tailnetEnabled}
	if err := validateModuleSecretMutation(config, "bifrost", "root_key_pem_b64"); err == nil || !strings.Contains(err.Error(), "platform-owned") {
		t.Fatalf("platform-owned module secret was accepted: %v", err)
	}
	config.Modules.Bifrost.Upstreams[0].APIKeySecret = "tailscale_auth_key"
	if err := validateModuleSecretMutation(config, "bifrost", "tailscale_auth_key"); err == nil || !strings.Contains(err.Error(), "tailnet-router") {
		t.Fatalf("shared module secret was accepted: %v", err)
	}
}

func TestBootstrapSecretRequirementIsSkippedForRetainedModuleState(t *testing.T) {
	retained := []model.RetainedModule{{Module: "tailnet-router", Disposition: "retained"}}
	if !hasRetainedModuleState(retained, "tailnet-router") {
		t.Fatal("retained module state was not recognized")
	}
	if hasRetainedModuleState(retained, "bifrost") {
		t.Fatal("unrelated retained module state was accepted")
	}
}

func TestReadOperatorSecretFromPipeRemovesOneTrailingLineEnding(t *testing.T) {
	value, err := readOperatorSecret(strings.NewReader("secret-value\r\n"), &bytes.Buffer{}, "example")
	if err != nil {
		t.Fatal(err)
	}
	if value != "secret-value" {
		t.Fatalf("readOperatorSecret() = %q", value)
	}
}

func TestReadOperatorSecretRejectsEmptyOversizedAndNULValues(t *testing.T) {
	cases := []string{"", strings.Repeat("x", maxOperatorSecretBytes+1), "bad\x00value", string([]byte{0xff})}
	for _, input := range cases {
		if _, err := readOperatorSecret(strings.NewReader(input), &bytes.Buffer{}, "example"); err == nil {
			t.Fatalf("readOperatorSecret accepted invalid input %q", input[:min(len(input), 12)])
		}
	}
}

func TestReadOperatorSecretDoesNotWritePipedValueToPromptOutput(t *testing.T) {
	var output bytes.Buffer
	if _, err := readOperatorSecret(strings.NewReader("super-secret"), &output, "example"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "super-secret") {
		t.Fatalf("secret value appeared in output: %q", output.String())
	}
}

func TestModuleSecretCLIListSetAndRemoveNeverPrintsValue(t *testing.T) {
	siteDir := t.TempDir()
	identityPath, recipient := writeTestAgeIdentity(t)
	config := model.ConfigFromSite(model.NewSite("installation", recipient, model.GatewayModeManaged))
	falseValue := false
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &falseValue,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "qwen", Upstream: "openrouter", Model: "some/model"}},
	}
	data, err := model.RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "site.yml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := site.StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"unrelated": "keep"}); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := Run([]string{"module", "secrets", "bifrost", "list", "--site", siteDir, "--age-identity", identityPath}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "openrouter_api_key\t runtime") && !strings.Contains(output.String(), "openrouter_api_key\truntime") {
		t.Fatalf("secret list omitted declaration: %q", output.String())
	}
	output.Reset()
	secret := "super-secret-value"
	if err := RunWithInput([]string{"module", "secrets", "bifrost", "set", "openrouter_api_key", "--site", siteDir, "--age-identity", identityPath}, strings.NewReader(secret+"\n"), &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("secret value leaked from set output: %q", output.String())
	}
	output.Reset()
	if err := Run([]string{"module", "secrets", "bifrost", "list", "--site", siteDir, "--age-identity", identityPath}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "openrouter_api_key\truntime\toperator-supplied\tPASS present") || strings.Contains(output.String(), secret) {
		t.Fatalf("status did not report redacted secret presence: %q", output.String())
	}
	output.Reset()
	if err := Run([]string{"module", "secrets", "bifrost", "remove", "openrouter_api_key", "--confirm", "--site", siteDir, "--age-identity", identityPath}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("secret value leaked from remove output: %q", output.String())
	}
}
