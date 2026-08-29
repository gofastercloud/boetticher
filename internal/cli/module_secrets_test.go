package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestModuleSecretMutationRejectsPlatformAndSharedNames(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	litellmEnabled, tailnetEnabled := true, true
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &litellmEnabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "root_key_pem_b64"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "qwen", Upstream: "openrouter", Model: "some/model"}},
	}
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	if err := validateModuleSecretMutation(config, "litellm", "root_key_pem_b64"); err == nil || !strings.Contains(err.Error(), "platform-owned") {
		t.Fatalf("platform-owned module secret was accepted: %v", err)
	}
	config.Modules.LiteLLM.Upstreams[0].APIKeySecret = "tailscale_auth_key"
	if err := validateModuleSecretMutation(config, "litellm", "tailscale_auth_key"); err == nil || !strings.Contains(err.Error(), "tailnet-router") {
		t.Fatalf("shared module secret was accepted: %v", err)
	}
}

func TestBootstrapSecretRequirementIsSkippedForRetainedModuleState(t *testing.T) {
	retained := []model.RetainedModule{{Module: "tailnet-router", Disposition: "retained"}}
	if !hasRetainedModuleState(retained, "tailnet-router") {
		t.Fatal("retained module state was not recognized")
	}
	if hasRetainedModuleState(retained, "litellm") {
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
	config := model.ConfigFromSite(model.NewSite("installation", "age1test", model.GatewayModeManaged))
	falseValue := false
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &falseValue,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "qwen", Upstream: "openrouter", Model: "some/model"}},
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
	if err := os.WriteFile(filepath.Join(siteDir, "secrets", "boetticher.sops.yaml"), []byte("unrelated: keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "sops"), []byte("#!/bin/sh\nlast=\"\"\nfor arg do last=\"$arg\"; done\nif [ \"$1\" = \"--decrypt\" ]; then cat \"$last\"; else cat; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var output bytes.Buffer
	if err := Run([]string{"module", "secrets", "litellm", "list", "--site", siteDir, "--age-identity", "identity"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "openrouter_api_key\t runtime") && !strings.Contains(output.String(), "openrouter_api_key\truntime") {
		t.Fatalf("secret list omitted declaration: %q", output.String())
	}
	output.Reset()
	secret := "super-secret-value"
	if err := RunWithInput([]string{"module", "secrets", "litellm", "set", "openrouter_api_key", "--site", siteDir, "--age-identity", "identity"}, strings.NewReader(secret+"\n"), &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("secret value leaked from set output: %q", output.String())
	}
	output.Reset()
	if err := Run([]string{"module", "status", "litellm", "--site", siteDir, "--age-identity", "identity"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "openrouter_api_key\truntime\toperator-supplied\tpresent") || strings.Contains(output.String(), secret) {
		t.Fatalf("status did not report redacted secret presence: %q", output.String())
	}
	output.Reset()
	if err := Run([]string{"module", "secrets", "litellm", "remove", "openrouter_api_key", "--confirm", "--site", siteDir, "--age-identity", "identity"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("secret value leaked from remove output: %q", output.String())
	}
}
