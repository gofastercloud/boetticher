package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

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
	if err := Run([]string{"modules", "litellm", "secrets", "list", "--site", siteDir, "--age-identity", "identity"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "openrouter_api_key\t runtime") && !strings.Contains(output.String(), "openrouter_api_key\truntime") {
		t.Fatalf("secret list omitted declaration: %q", output.String())
	}
	output.Reset()
	secret := "super-secret-value"
	if err := RunWithInput([]string{"modules", "litellm", "secrets", "set", "openrouter_api_key", "--site", siteDir, "--age-identity", "identity"}, strings.NewReader(secret+"\n"), &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("secret value leaked from set output: %q", output.String())
	}
	output.Reset()
	if err := Run([]string{"modules", "litellm", "status", "--site", siteDir, "--age-identity", "identity"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "openrouter_api_key\truntime\toperator-supplied\tpresent") || strings.Contains(output.String(), secret) {
		t.Fatalf("status did not report redacted secret presence: %q", output.String())
	}
	output.Reset()
	if err := Run([]string{"modules", "litellm", "secrets", "remove", "openrouter_api_key", "--confirm", "--site", siteDir, "--age-identity", "identity"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("secret value leaked from remove output: %q", output.String())
	}
}
