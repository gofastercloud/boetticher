package host

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

type ProxmoxConfig struct {
	Address    string `yaml:"address"`
	User       string `yaml:"user"`
	Node       string `yaml:"node"`
	Repository string `yaml:"repository"`
}

type StorageConfig struct {
	Profile      string `yaml:"profile"`
	Device       string `yaml:"device"`
	GuestStorage string `yaml:"guest_storage"`
}

type LabConfig struct {
	Name    string         `yaml:"name"`
	Proxmox ProxmoxConfig  `yaml:"proxmox"`
	Storage *StorageConfig `yaml:"storage,omitempty"`
}

func LoadConfig() (LabConfig, error) {
	data, err := os.ReadFile(LabConfigPath)
	if err != nil {
		return LabConfig{}, fmt.Errorf("read %s: %w", LabConfigPath, err)
	}
	var config LabConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return LabConfig{}, fmt.Errorf("decode %s: %w", LabConfigPath, err)
	}
	if err := ValidateConfig(config); err != nil {
		return LabConfig{}, err
	}
	return config, nil
}

func ValidateConfig(config LabConfig) error {
	if config.Name == "" {
		return errors.New("lab configuration name is required")
	}
	if net.ParseIP(config.Proxmox.Address) == nil || net.ParseIP(config.Proxmox.Address).To4() == nil {
		return errors.New("lab configuration requires an IPv4 Proxmox address")
	}
	if config.Proxmox.User != "root" {
		return errors.New("lab configuration requires Proxmox user root")
	}
	if !safeIdentifier(config.Proxmox.Node) {
		return errors.New("lab configuration requires a safe Proxmox node binding")
	}
	if config.Proxmox.Repository != "no-subscription" {
		return errors.New("lab configuration requires the no-subscription repository policy")
	}
	if config.Storage != nil {
		if config.Storage.Profile != "dedicated-data-disk" || config.Storage.GuestStorage != "boetticher-data" || !strings.HasPrefix(config.Storage.Device, "/dev/disk/by-id/") {
			return errors.New("lab configuration contains an invalid dedicated storage selection")
		}
	}
	return nil
}

func SaveConfig(config LabConfig) error {
	if err := ValidateConfig(config); err != nil {
		return err
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode lab configuration: %w", err)
	}
	if err := pathguard.ValidateNoSymlinkComponents(LabConfigPath); err != nil {
		return fmt.Errorf("validate lab configuration path: %w", err)
	}
	if err := pathguard.MkdirAll("/etc/boetticher", 0755); err != nil {
		return fmt.Errorf("create Boetticher configuration directory: %w", err)
	}
	if err := pathguard.WriteFileWithParentMode(LabConfigPath, data, 0600, 0755); err != nil {
		return fmt.Errorf("write lab configuration: %w", err)
	}
	return nil
}

func safeIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func TransportFor(config LabConfig) (Transport, error) {
	if err := ValidateConfig(config); err != nil {
		return Transport{}, err
	}
	return Transport{Address: config.Proxmox.Address, User: config.Proxmox.User, Identity: PrivateKeyPath, KnownHosts: KnownHostsPath}, nil
}

func ConfigSummary(config LabConfig) string {
	return strings.TrimSpace(fmt.Sprintf("%s@%s (node %s)", config.Proxmox.User, config.Proxmox.Address, config.Proxmox.Node))
}
