package appliance

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

type runtimeRunner struct {
	command string
	data    []byte
}

func (r *runtimeRunner) RunWithStdin(_ context.Context, _ string, _ string, command string, stdin io.Reader) ([]byte, error) {
	r.command = command
	data, err := io.ReadAll(stdin)
	r.data = data
	return nil, err
}

func TestRenderRuntimeConfigContainsNoSecretValues(t *testing.T) {
	base := model.NewDefaultSite("installation", "age1example")
	site, _, err := modules.Compose(model.ConfigFromSite(base))
	if err != nil {
		t.Fatal(err)
	}
	var guest model.Component
	var declaration model.ModuleDeclaration
	for _, candidate := range site.Components {
		if candidate.Module == "dns" {
			guest = candidate
			break
		}
	}
	for _, candidate := range site.Declarations {
		if candidate.Module == "dns" {
			declaration = candidate
			break
		}
	}
	config, err := RenderRuntimeConfig(site, guest, declaration)
	if err != nil {
		t.Fatal(err)
	}
	if ContainsSecretValue(config, "synthetic-secret", "private-key-material") {
		t.Fatalf("runtime config contains fixture secret data: %s", config)
	}
}

func TestInstallRuntimeConfigUsesFixedCommandAndStdin(t *testing.T) {
	runner := &runtimeRunner{}
	config := []byte("api_version: boetticher/v3\nmodule: logging\n")
	if err := InstallRuntimeConfig(context.Background(), runner, "192.0.2.10", "labadmin", config); err != nil {
		t.Fatal(err)
	}
	if string(runner.data) != string(config) {
		t.Fatalf("runtime config stdin = %q", runner.data)
	}
	if !strings.Contains(runner.command, "module.yaml") || strings.Contains(runner.command, string(config)) {
		t.Fatalf("unsafe runtime config command: %q", runner.command)
	}
}

func TestInstallArtifactIdentityContainsQualifiedMetadataOnly(t *testing.T) {
	runner := &runtimeRunner{}
	artifact := model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Provider: "blocky", Architecture: "amd64", Kind: "lxc", DefinitionSHA256: "definition", ContentSHA256: "content"}
	if err := InstallArtifactIdentity(context.Background(), runner, "10.10.20.10", "labadmin", artifact); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(runner.command, string(runner.data)) || !strings.Contains(string(runner.data), `"content_sha256": "content"`) {
		t.Fatalf("artifact identity was not sent as expected: command=%q stdin=%q", runner.command, runner.data)
	}
	if strings.Contains(string(runner.data), "secret") {
		t.Fatal("artifact identity contains secret material")
	}
}

func TestInstallRuntimeConfigRejectsSecretFields(t *testing.T) {
	runner := &runtimeRunner{}
	if err := InstallRuntimeConfig(context.Background(), runner, "192.0.2.10", "labadmin", []byte("secret: leaked\n")); err == nil {
		t.Fatal("secret-shaped runtime config was accepted")
	}
}
