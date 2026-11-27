package agentlab

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	DefaultUser          = "boetticher-agent"
	DefaultPort          = 22
	DefaultConfigRelPath = ".config/groundhog/agent-lab.yml"
	DefaultIdentityRel   = ".config/groundhog/agent_lab_ed25519"
	DefaultKnownHostsRel = ".config/groundhog/agent_lab_known_hosts"
	EnvConfigPath        = "AGENT_LAB_CONFIG"
)

// Config holds the strict YAML configuration for agent-lab.
type Config struct {
	Host           string
	User           string
	Port           int
	IdentityFile   string
	KnownHostsFile string
}

type rawConfig struct {
	Host           string `yaml:"host"`
	User           string `yaml:"user"`
	Port           *int   `yaml:"port"`
	IdentityFile   string `yaml:"identity_file"`
	KnownHostsFile string `yaml:"known_hosts_file"`
}

// ResolveConfigPath returns the config file path using precedence:
// --config flag > AGENT_LAB_CONFIG env var > ~/.config/groundhog/agent-lab.yml.
func ResolveConfigPath(flagPath, homeDir string, getenv func(string) string) string {
	if p := strings.TrimSpace(flagPath); p != "" {
		return expandHome(p, homeDir)
	}
	if getenv != nil {
		if p := strings.TrimSpace(getenv(EnvConfigPath)); p != "" {
			return expandHome(p, homeDir)
		}
	}
	return filepath.Join(homeDir, DefaultConfigRelPath)
}

func expandHome(path, homeDir string) string {
	if path == "~" {
		return homeDir
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(homeDir, path[2:])
	}
	return path
}

// LoadConfig reads and strictly validates an agent-lab YAML config file.
func LoadConfig(path, homeDir string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Config{}, fmt.Errorf("config %s is empty", path)
	}

	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse config %s: unexpected trailing YAML document", path)
	}

	host := strings.TrimSpace(raw.Host)
	if err := validateSSHToken("host", host); err != nil {
		return Config{}, err
	}

	user := strings.TrimSpace(raw.User)
	if user == "" {
		user = DefaultUser
	}
	if err := validateSSHToken("user", user); err != nil {
		return Config{}, err
	}

	port := DefaultPort
	if raw.Port != nil {
		port = *raw.Port
	}
	if port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}

	identityFile := strings.TrimSpace(raw.IdentityFile)
	if identityFile == "" {
		identityFile = filepath.Join(homeDir, DefaultIdentityRel)
	} else {
		identityFile = expandHome(identityFile, homeDir)
	}

	knownHostsFile := strings.TrimSpace(raw.KnownHostsFile)
	if knownHostsFile == "" {
		knownHostsFile = filepath.Join(homeDir, DefaultKnownHostsRel)
	} else {
		knownHostsFile = expandHome(knownHostsFile, homeDir)
	}

	return Config{
		Host:           host,
		User:           user,
		Port:           port,
		IdentityFile:   identityFile,
		KnownHostsFile: knownHostsFile,
	}, nil
}

func validateSSHToken(field, value string) error {
	if value == "" {
		return fmt.Errorf("config field %q is required", field)
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("config field %q must not start with '-'", field)
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("config field %q contains invalid whitespace or control character", field)
		}
	}
	return nil
}

// CheckSecurity enforces fail-closed preconditions before invoking ssh.
func CheckSecurity(cfg Config) error {
	khInfo, err := os.Stat(cfg.KnownHostsFile)
	if err != nil {
		return fmt.Errorf("pinned known_hosts_file %s unavailable: %w", cfg.KnownHostsFile, err)
	}
	if !khInfo.Mode().IsRegular() {
		return fmt.Errorf("pinned known_hosts_file %s must be a regular file", cfg.KnownHostsFile)
	}

	idInfo, err := os.Stat(cfg.IdentityFile)
	if err != nil {
		return fmt.Errorf("identity_file %s unavailable: %w", cfg.IdentityFile, err)
	}
	if !idInfo.Mode().IsRegular() {
		return fmt.Errorf("identity_file %s must be a regular file", cfg.IdentityFile)
	}
	if mode := idInfo.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("identity_file %s has permissive mode %04o (must not grant group/other permissions; run chmod 0600)", cfg.IdentityFile, mode)
	}
	return nil
}
