package sshconfig

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
)

func Render(s model.Site, generatedAt time.Time) (string, error) {
	return render(s, generatedAt, "")
}

// RenderWithKnownHosts renders an SSH projection using a site-scoped trust
// file. Keeping appliance host keys out of the controller's global known-hosts
// file allows a fresh site to enroll its new identities without weakening
// changed-key protection for an existing site.
func RenderWithKnownHosts(s model.Site, generatedAt time.Time, knownHosts string) (string, error) {
	knownHosts = model.ExpandUserPath(knownHosts)
	if knownHosts != "" {
		absolute, err := filepath.Abs(knownHosts)
		if err != nil {
			return "", fmt.Errorf("resolve SSH known-hosts path: %w", err)
		}
		knownHosts = absolute
	}
	return render(s, generatedAt, knownHosts)
}

func render(s model.Site, generatedAt time.Time, knownHosts string) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	revision, err := s.Revision()
	if err != nil {
		return "", err
	}
	identity := model.ExpandUserPath(s.SSHIdentityFile)
	endpoint := s.BootstrapAddress
	if endpoint == "" {
		return "", errors.New("bootstrap endpoint is not configured; record the upstream Proxmox address before generating SSH configuration")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by boetticher. Do not edit.\n# boetticher-model-revision: %s\n# generated-at: %s\n# Configure ~/.ssh/config with: Include ~/.ssh/config.d/*\n\n", revision, generatedAt.UTC().Format(time.RFC3339))

	writeHost(&b, []string{"lab-proxmox-01", "proxmox"}, endpoint, "labadmin", "lab-proxmox-01", identity, knownHosts, false, false)
	writeHost(&b, []string{"lab-bastion"}, endpoint, "lab-jump", "lab-proxmox-01", identity, knownHosts, false, true)

	components := s.PlatformComponents()
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	for _, m := range components {
		if !m.ProductOwned || !m.SSHManaged || m.Name == "lab-proxmox-01" {
			continue
		}
		aliases := append([]string{m.Name, m.Hostname + "." + s.Network.Domain}, m.DNSAliases...)
		if m.Name == "lab-fw-01" {
			aliases = append(aliases, "firewall")
		}
		writeHost(&b, uniqueStrings(aliases), m.Address, m.SSHUser, m.Hostname+"."+s.Network.Domain, identity, knownHosts, true, false)
	}
	return b.String(), nil
}

func RenderBastionPolicy(s model.Site) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	revision, err := s.Revision()
	if err != nil {
		return "", err
	}
	destinations := make([]string, 0)
	for _, m := range s.PlatformComponents() {
		if m.ProductOwned && m.SSHManaged && m.JumpAllowed {
			port := m.SSHPort
			if port == 0 {
				port = 22
			}
			destinations = append(destinations, fmt.Sprintf("%s:%d", m.Address, port))
			if m.Name == "lab-monitor-01" {
				destinations = append(destinations, fmt.Sprintf("%s:443", m.Address))
			}
		}
	}
	sort.Strings(destinations)
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by boetticher.\n# boetticher-model-revision: %s\n# Install through the authenticated Proxmox deployment path.\n\n", revision)
	b.WriteString("Match User lab-jump\n")
	b.WriteString("    PermitTTY no\n")
	b.WriteString("    X11Forwarding no\n")
	b.WriteString("    AllowAgentForwarding no\n")
	b.WriteString("    AllowTcpForwarding local\n")
	b.WriteString("    PermitOpen")
	for _, destination := range destinations {
		b.WriteString(" ")
		b.WriteString(destination)
	}
	b.WriteString("\n")
	return b.String(), nil
}

func DefaultPath() string { return model.ExpandUserPath(model.DefaultSSHConfig) }

func Write(path string, content []byte, force bool) error {
	path = model.ExpandUserPath(path)
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing SSH configuration %s; use --force", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".boetticher-ssh-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// RemoveHostKey removes one exact plain-host entry from a generated
// known-hosts file. It is used only after boetticher has replaced the
// corresponding owned appliance rootfs; all other changed-key checks remain
// strict. Hashed entries are left untouched rather than guessed at.
func RemoveHostKey(path, host string) error {
	path = model.ExpandUserPath(path)
	if path == "" || host == "" || strings.ContainsAny(host, " \t\r\n") {
		return errors.New("known-hosts path and exact host are required")
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read SSH known-hosts file: %w", err)
	}
	lines := strings.SplitAfter(string(content), "\n")
	kept := make([]string, 0, len(lines))
	changed := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			kept = append(kept, line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || strings.HasPrefix(fields[0], "|") {
			kept = append(kept, line)
			continue
		}
		aliases := strings.Split(fields[0], ",")
		remaining := aliases[:0]
		matched := false
		for _, alias := range aliases {
			if alias == host {
				matched = true
				continue
			}
			remaining = append(remaining, alias)
		}
		if !matched {
			kept = append(kept, line)
			continue
		}
		changed = true
		if len(remaining) == 0 {
			continue
		}
		fields[0] = strings.Join(remaining, ",")
		kept = append(kept, strings.Join(fields, " ")+"\n")
	}
	if !changed {
		return nil
	}
	return Write(path, []byte(strings.Join(kept, "")), true)
}

func Check(path string, s model.Site) error {
	content, err := os.ReadFile(model.ExpandUserPath(path))
	if err != nil {
		return fmt.Errorf("read SSH configuration: %w", err)
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	text := string(content)
	if !strings.Contains(text, "# boetticher-model-revision: "+revision) {
		return fmt.Errorf("SSH configuration is stale or from a different model revision")
	}
	for _, required := range []string{"Host lab-bastion", "ProxyJump lab-bastion", "HostKeyAlias", "IdentitiesOnly yes"} {
		if !strings.Contains(text, required) && (required != "IdentitiesOnly yes" || s.SSHIdentityFile != "") {
			return fmt.Errorf("SSH configuration is missing required directive %q", required)
		}
	}
	if strings.Contains(text, "StrictHostKeyChecking no") || strings.Contains(text, "UserKnownHostsFile /dev/null") {
		return fmt.Errorf("SSH configuration weakens host-key verification")
	}
	if s.BootstrapAddress == "" {
		return fmt.Errorf("bootstrap endpoint is not configured")
	}
	return nil
}

func ValidateBootstrapAddress(address string) error {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("bootstrap endpoint must be an IPv4 address")
	}
	return nil
}

// ScanHostKey obtains the public host-key lines for an address without using
// credentials. It is used only to compare a recorded bootstrap identity; it
// is not a trust mechanism and never replaces StrictHostKeyChecking.
func ScanHostKey(ctx context.Context, address string) (string, error) {
	if err := ValidateBootstrapAddress(address); err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, "ssh-keyscan", "-4", "-T", "5", address)
	data, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("scan Proxmox SSH host key: %w", err)
	}
	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return "", errors.New("ssh-keyscan returned no host key")
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}

func writeHost(b *strings.Builder, aliases []string, hostName, user, hostKeyAlias, identity, knownHosts string, throughBastion, bastion bool) {
	aliases = uniqueStrings(append(append([]string{}, aliases...), hostName))
	fmt.Fprintf(b, "Host %s\n", strings.Join(aliases, " "))
	fmt.Fprintf(b, "    HostName %s\n", hostName)
	if user != "" {
		fmt.Fprintf(b, "    User %s\n", user)
	}
	if hostKeyAlias != "" {
		fmt.Fprintf(b, "    HostKeyAlias %s\n", hostKeyAlias)
	}
	if identity != "" {
		fmt.Fprintf(b, "    IdentityFile %s\n    IdentitiesOnly yes\n", identity)
	}
	if knownHosts != "" {
		fmt.Fprintf(b, "    UserKnownHostsFile %s\n", knownHosts)
	}
	if bastion {
		b.WriteString("    RequestTTY no\n    ForwardAgent no\n    ForwardX11 no\n")
	} else if throughBastion {
		b.WriteString("    ProxyJump lab-bastion\n    StrictHostKeyChecking accept-new\n")
	}
	b.WriteString("\n")
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
