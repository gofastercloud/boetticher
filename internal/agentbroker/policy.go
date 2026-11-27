package agentbroker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultPolicyPath is the root-owned opt-in Tier 2 policy file on the Controller.
	DefaultPolicyPath = "/etc/boetticher/agent-policy.yml"
	maxPolicyBytes    = 64 << 10
)

// Policy configures optional Tier 2 capabilities beyond the always-allowed
// Tier 1 read-only commands.
type Policy struct {
	Tier2 Tier2Policy `yaml:"tier2"`
}

// Tier2Policy holds opt-in mutation or active-test permissions.
type Tier2Policy struct {
	SystemPower      bool     `yaml:"system_power"`
	FirewallTest     bool     `yaml:"firewall_test"`
	DNSRecords       bool     `yaml:"dns_records"`
	DHCPReservations bool     `yaml:"dhcp_reservations"`
	ModuleApply      []string `yaml:"module_apply"`
}

// OwnerCheckFunc validates ownership and permissions of the opened policy file.
type OwnerCheckFunc func(os.FileInfo) error

// DefaultOwnerCheck requires the policy file to be owned by root (UID 0) and
// not group- or world-writable.
func DefaultOwnerCheck(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unable to inspect policy file ownership")
	}
	if stat.Uid != 0 {
		return fmt.Errorf("policy file must be owned by root (uid 0), got uid %d", stat.Uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("policy file mode %04o must not be group- or world-writable", info.Mode().Perm())
	}
	return nil
}

// LoadPolicy loads and strictly validates the optional agent policy YAML file.
// If the file does not exist, an empty Policy (Tier 1 only) is returned.
// Symlinks, non-regular files, ownership violations, oversized files, and
// unknown YAML fields are rejected.
func LoadPolicy(path string, ownerCheck OwnerCheckFunc) (Policy, error) {
	if path == "" {
		path = DefaultPolicyPath
	}
	if ownerCheck == nil {
		ownerCheck = DefaultOwnerCheck
	}

	linfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("inspect policy file %s: %w", path, err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return Policy{}, fmt.Errorf("policy file %s must not be a symlink", path)
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Policy{}, fmt.Errorf("open policy file %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return Policy{}, fmt.Errorf("open policy file %s: invalid descriptor", path)
	}
	defer file.Close()

	finfo, err := file.Stat()
	if err != nil {
		return Policy{}, fmt.Errorf("stat policy file %s: %w", path, err)
	}
	if !finfo.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("policy file %s must be a regular file", path)
	}
	if err := ownerCheck(finfo); err != nil {
		return Policy{}, fmt.Errorf("policy file %s ownership check failed: %w", path, err)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read policy file %s: %w", path, err)
	}
	if len(data) > maxPolicyBytes {
		return Policy{}, fmt.Errorf("policy file %s exceeds maximum size of %d bytes", path, maxPolicyBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Policy{}, nil
	}

	var policy Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("parse policy file %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Policy{}, fmt.Errorf("policy file %s must contain a single YAML document", path)
	}

	for _, capName := range policy.Tier2.ModuleApply {
		if _, ok := applyCapabilities[capName]; !ok {
			return Policy{}, fmt.Errorf("policy file %s: unknown module_apply capability %q", path, capName)
		}
	}

	return policy, nil
}
