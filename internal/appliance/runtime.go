package appliance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
)

const RuntimeConfigPath = "/etc/boetticher/module.yaml"

// RuntimeConfig is the non-secret site-specific contract injected into an
// appliance after its immutable rootfs is created.
type RuntimeConfig struct {
	APIVersion  string                  `yaml:"api_version"`
	Module      string                  `yaml:"module"`
	Version     string                  `yaml:"module_version"`
	Provider    string                  `yaml:"provider,omitempty"`
	Guest       model.Component         `yaml:"guest"`
	Artifact    model.Artifact          `yaml:"artifact"`
	Declaration model.ModuleDeclaration `yaml:"declaration"`
}

func RenderRuntimeConfig(site model.Site, guest model.Component, declaration model.ModuleDeclaration) ([]byte, error) {
	if guest.Module == "" || guest.Name == "" || guest.Address == "" {
		return nil, fmt.Errorf("runtime config requires a module guest identity")
	}
	if net.ParseIP(guest.Address) == nil {
		return nil, fmt.Errorf("runtime config guest %s has an invalid address", guest.Name)
	}
	if declaration.Module != guest.Module || declaration.Artifact.Name == "" {
		return nil, fmt.Errorf("runtime config declaration does not match guest %s", guest.Name)
	}
	provider := ""
	if guest.Module == "dns" {
		provider = site.ModuleConfig["dns"].Provider
	}
	data, err := yaml.Marshal(RuntimeConfig{
		APIVersion:  site.APIVersion,
		Module:      guest.Module,
		Version:     declaration.Artifact.Version,
		Provider:    provider,
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
	command := "sudo -n sh -c 'set -eu; install -d -m 0750 /etc/boetticher; tmp=$(mktemp /etc/boetticher/.module.yaml.XXXXXX); trap \"rm -f \\\"$tmp\\\"\" EXIT; install -m 0640 /dev/stdin \\\"$tmp\\\"; chown root:root \\\"$tmp\\\"; mv -f \\\"$tmp\\\" /etc/boetticher/module.yaml'"
	if _, err := runner.RunWithStdin(ctx, address, user, command, bytes.NewReader(config)); err != nil {
		return fmt.Errorf("install runtime config: %w", err)
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
