package appliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
)

const RuntimeConfigPath = "/etc/boetticher/module.yaml"

const ArtifactIdentityPath = "/usr/lib/boetticher/artifact.json"

// RuntimeConfig is the non-secret site-specific 0.5 contract injected into an
// appliance after its immutable rootfs is created.
type RuntimeConfig struct {
	APIVersion  string                  `yaml:"api_version"`
	Module      string                  `yaml:"module"`
	Version     string                  `yaml:"module_version"`
	Guest       model.Component         `yaml:"guest"`
	Artifact    model.Artifact          `yaml:"artifact"`
	Declaration model.ModuleDeclaration `yaml:"declaration"`
}

func RenderRuntimeConfig(_ model.Site, guest model.Component, declaration model.ModuleDeclaration) ([]byte, error) {
	if guest.Module == "" || guest.Name == "" || guest.Address == "" {
		return nil, fmt.Errorf("runtime config requires a module guest identity")
	}
	if net.ParseIP(guest.Address) == nil {
		return nil, fmt.Errorf("runtime config guest %s has an invalid address", guest.Name)
	}
	if declaration.Module != guest.Module || declaration.Artifact.Name == "" {
		return nil, fmt.Errorf("runtime config declaration does not match guest %s", guest.Name)
	}
	data, err := yaml.Marshal(RuntimeConfig{
		APIVersion:  model.APIVersion,
		Module:      guest.Module,
		Version:     declaration.Artifact.Version,
		Guest:       guest,
		Artifact:    declaration.Artifact,
		Declaration: declaration,
	})
	if err != nil {
		return nil, fmt.Errorf("render runtime config for %s: %w", guest.Name, err)
	}
	return data, nil
}

type StdinRunner interface {
	RunWithStdin(context.Context, string, string, string, io.Reader) ([]byte, error)
}

// InstallRuntimeConfig atomically installs non-secret runtime configuration
// through the existing authenticated SSH path. The command is fixed and the
// configuration bytes are supplied only through stdin.
func InstallRuntimeConfig(ctx context.Context, runner StdinRunner, address, user string, config []byte) error {
	if runner == nil {
		return fmt.Errorf("runtime config runner is required")
	}
	if net.ParseIP(address) == nil || user == "" {
		return fmt.Errorf("runtime config target identity is invalid")
	}
	if len(config) == 0 || bytes.Contains(config, []byte("private_key:")) || bytes.Contains(config, []byte("secret:")) {
		return fmt.Errorf("runtime config is empty or contains a forbidden secret field")
	}
	command := "/usr/lib/boetticher/install-runtime-state module-config"
	if _, err := runner.RunWithStdin(ctx, address, user, command, bytes.NewReader(config)); err != nil {
		return fmt.Errorf("install runtime config: %w", err)
	}
	return nil
}

// InstallArtifactIdentity records only qualified, non-secret artifact
// metadata inside the appliance. It is used for drift diagnosis and contains
// no controller credentials or site-specific secret material.
func InstallArtifactIdentity(ctx context.Context, runner StdinRunner, address, user string, artifact model.Artifact) error {
	if runner == nil {
		return fmt.Errorf("artifact identity runner is required")
	}
	if net.ParseIP(address) == nil || user == "" || artifact.Name == "" || artifact.DefinitionSHA256 == "" || artifact.ContentSHA256 == "" {
		return fmt.Errorf("artifact identity is incomplete")
	}
	data, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal artifact identity: %w", err)
	}
	data = append(data, '\n')
	command := "/usr/lib/boetticher/install-runtime-state artifact-identity"
	if _, err := runner.RunWithStdin(ctx, address, user, command, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("install artifact identity: %w", err)
	}
	return nil
}

func ContainsSecretValue(config []byte, values ...string) bool {
	text := string(config)
	for _, value := range values {
		if value != "" && strings.Contains(text, value) {
			return true
		}
	}
	return false
}
