package sshconfig

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

func Render(s model.Site, generatedAt time.Time) (string, error) {
	return render(s, generatedAt, "")
}

// RenderDirect renders a short-lived, host-key-pinned SSH configuration for
// one external companion. It deliberately has no include, proxy, command, or
// forwarding directives so Ansible cannot inherit a user's broader SSH
// configuration while configuring a fresh Raspberry Pi.
func RenderDirect(address, user, identity, knownHosts string, port int) (string, error) {
	if err := ValidateBootstrapAddress(address); err != nil {
		return "", fmt.Errorf("external appliance address: %w", err)
	}
	if !validSSHUser(user) {
		return "", fmt.Errorf("SSH user %q is not a valid Unix account name", user)
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("SSH port %d is outside 1-65535", port)
	}
	identity, err := quoteOpenSSHPath("SSH identity file", model.ExpandUserPath(identity))
	if err != nil {
		return "", err
	}
	knownHosts, err = quoteOpenSSHPath("SSH known-hosts file", model.ExpandUserPath(knownHosts))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Temporary Boetticher Raspberry Pi setup transport. Do not edit.\n")
	fmt.Fprintf(&b, "Host boetticher-companion %s\n", address)
	fmt.Fprintf(&b, "    HostName %s\n    Port %d\n    User %s\n", address, port, user)
	b.WriteString("    ConnectTimeout 10\n    BatchMode yes\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    PubkeyAuthentication yes\n    StrictHostKeyChecking yes\n")
	fmt.Fprintf(&b, "    UserKnownHostsFile %s\n    IdentityFile %s\n", knownHosts, identity)
	b.WriteString("    IdentitiesOnly yes\n    ControlMaster no\n    ForwardAgent no\n    ForwardX11 no\n    RequestTTY no\n")
	return b.String(), nil
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
	if identity != "" {
		identity, err = quoteOpenSSHPath("SSH identity file", identity)
		if err != nil {
			return "", err
		}
	}
	if knownHosts != "" {
		knownHosts, err = quoteOpenSSHPath("SSH known-hosts file", knownHosts)
		if err != nil {
			return "", err
		}
	}
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
	for _, retained := range s.RetainedModules {
		for _, m := range retained.Guests {
			if !m.ProductOwned || !m.SSHManaged {
				continue
			}
			aliases := append([]string{m.Name, m.Hostname + "." + s.Network.Domain}, m.DNSAliases...)
			writeHost(&b, uniqueStrings(aliases), m.Address, m.SSHUser, m.Hostname+"."+s.Network.Domain, identity, knownHosts, true, false)
		}
	}
	return b.String(), nil
}

func quoteOpenSSHPath(label, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%s path is empty", label)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%s path contains control characters", label)
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`, nil
}

func RenderBastionPolicy(s model.Site) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	revision, err := s.Revision()
	if err != nil {
		return "", err
	}
	destinations := BastionDestinations(s)
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

// BastionDestinations returns the canonical destination list used by both the
// generated controller projection and the authenticated Proxmox installation
// path. Retained product-owned guests remain within the declared SSH contract,
// but do not gain any destinations outside their model contract.
func BastionDestinations(s model.Site) []string {
	destinations := make([]string, 0)
	for _, m := range s.PlatformComponents() {
		destinations = appendBastionDestinations(destinations, m)
	}
	for _, retained := range s.RetainedModules {
		for _, m := range retained.Guests {
			destinations = appendBastionDestinations(destinations, m)
		}
	}
	sort.Strings(destinations)
	return destinations
}

func appendBastionDestinations(destinations []string, component model.Component) []string {
	if !component.ProductOwned || !component.SSHManaged || !component.JumpAllowed {
		return destinations
	}
	port := component.SSHPort
	if port == 0 {
		port = 22
	}
	destinations = append(destinations, fmt.Sprintf("%s:%d", component.Address, port))
	if component.Name == "lab-monitor-01" || component.Name == "lab-bifrost-01" || component.Name == "lab-portal-01" {
		destinations = append(destinations, fmt.Sprintf("%s:443", component.Address))
	}
	return destinations
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
	content, err := pathguard.ReadFile(path)
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
	return pathguard.WriteFile(path, []byte(strings.Join(kept, "")), 0600)
}

// ReadHostKey returns the first plain host-key entry for the exact alias.
// Hashed entries are intentionally unsupported here because bootstrap trust
// must be bound to the logical identity used by OpenSSH HostKeyAlias.
func ReadHostKey(path, host string) (string, error) {
	path = model.ExpandUserPath(path)
	if path == "" || host == "" || strings.ContainsAny(host, " \t\r\n,|*?!") {
		return "", errors.New("known-hosts path and exact host are required")
	}
	content, err := pathguard.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("host key for %s is not enrolled: %w", host, err)
	}
	if err != nil {
		return "", fmt.Errorf("read SSH known-hosts file: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], "|") {
			continue
		}
		for _, alias := range strings.Split(fields[0], ",") {
			if alias != host {
				continue
			}
			return normalizeKnownHostKey(fields[1] + " " + fields[2])
		}
	}
	return "", fmt.Errorf("host key for %s is not enrolled", host)
}

// AddKnownHostKey records a host key obtained through an already trusted
// connection. Existing entries for the exact alias must agree; a changed key
// is never silently replaced.
func AddKnownHostKey(path, host, publicKey string) error {
	return addHostKey(path, host, publicKey, normalizeKnownHostKey, "known host key")
}

// AddHostKey records an ed25519 host key obtained through an independently
// authenticated management path. Existing entries for the exact alias must
// agree; a changed key is never silently replaced.
func AddHostKey(path, host, publicKey string) error {
	return addHostKey(path, host, publicKey, normalizePublicKey, "independently observed host key")
}

func addHostKey(path, host, publicKey string, normalize func(string) (string, error), description string) error {
	path = model.ExpandUserPath(path)
	if path == "" || host == "" || strings.ContainsAny(host, " \t\r\n,|*?!") {
		return errors.New("known-hosts path and exact host are required")
	}
	canonicalKey, err := normalize(publicKey)
	if err != nil {
		return fmt.Errorf("validate %s: %w", description, err)
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		content = nil
	} else if err != nil {
		return fmt.Errorf("read SSH known-hosts file: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], "|") {
			continue
		}
		for _, alias := range strings.Split(fields[0], ",") {
			if alias != host {
				continue
			}
			observed, normalizeErr := normalize(fields[1] + " " + fields[2])
			if normalizeErr != nil || observed != canonicalKey {
				return fmt.Errorf("existing host key for %s does not match independently observed key", host)
			}
			return nil
		}
	}
	separator := ""
	if len(content) > 0 && !strings.HasSuffix(string(content), "\n") {
		separator = "\n"
	}
	return pathguard.WriteFile(path, append(append(append([]byte{}, content...), []byte(separator)...), []byte(host+" "+canonicalKey+"\n")...), 0600)
}

func normalizeKnownHostKey(publicKey string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(publicKey))
	if len(fields) != 2 || fields[0] == "" {
		return "", errors.New("expected one known-host public key")
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(fields[1])
	}
	if err != nil || len(decoded) == 0 {
		return "", errors.New("known-host public key data is not valid base64")
	}
	return fields[0] + " " + fields[1], nil
}

func normalizePublicKey(publicKey string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(publicKey))
	if len(fields) < 2 || len(fields) > 3 || fields[0] != "ssh-ed25519" {
		return "", errors.New("expected one ssh-ed25519 public key")
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(fields[1])
	}
	if err != nil || len(decoded) == 0 {
		return "", errors.New("public key data is not valid base64")
	}
	if len(decoded) != 51 || string(decoded[4:15]) != "ssh-ed25519" || decoded[0] != 0 || decoded[1] != 0 || decoded[2] != 0 || decoded[3] != 11 || decoded[15] != 0 || decoded[16] != 0 || decoded[17] != 0 || decoded[18] != 32 {
		return "", errors.New("public key data is not a valid ssh-ed25519 key")
	}
	return fields[0] + " " + fields[1], nil
}

// ValidateExecutionConfig rejects OpenSSH directives that can execute local
// commands or redirect a read-only operation. It is a defense-in-depth check;
// callers handling untrusted projections should still render a fresh config
// from the validated model.
func ValidateExecutionConfig(path string) error {
	file, err := os.Open(model.ExpandUserPath(path))
	if err != nil {
		return fmt.Errorf("open SSH configuration: %w", err)
	}
	defer file.Close()
	dangerous := map[string]bool{
		"include": true, "proxycommand": true, "localcommand": true,
		"permitlocalcommand": true, "match": true, "match exec": true,
		"knownhostscommand": true, "remotecommand": true,
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		rawDirective := strings.TrimSpace(strings.SplitN(fields[0], "=", 2)[0])
		if strings.HasPrefix(rawDirective, "\"") || strings.HasPrefix(rawDirective, "'") {
			return fmt.Errorf("SSH configuration contains forbidden quoted directive %q", fields[0])
		}
		directive := strings.ToLower(rawDirective)
		if dangerous[directive] {
			return fmt.Errorf("SSH configuration contains forbidden directive %q", fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read SSH configuration: %w", err)
	}
	return nil
}

func Check(path string, s model.Site) error {
	if err := ValidateExecutionConfig(path); err != nil {
		return err
	}
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
	if strings.Contains(text, "StrictHostKeyChecking no") || strings.Contains(text, "StrictHostKeyChecking accept-new") || strings.Contains(text, "UserKnownHostsFile /dev/null") {
		return fmt.Errorf("SSH configuration weakens host-key verification")
	}
	if s.BootstrapAddress == "" {
		return fmt.Errorf("bootstrap endpoint is not configured")
	}
	return nil
}

func ValidateBootstrapAddress(address string) error {
	if strings.TrimSpace(address) != address {
		return fmt.Errorf("bootstrap endpoint must be a canonical IPv4 address")
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil || ip.To4().String() != address {
		return fmt.Errorf("bootstrap endpoint must be an IPv4 address")
	}
	return nil
}

func validSSHUser(user string) bool {
	if user == "" || len(user) > 32 || (user[0] >= '0' && user[0] <= '9') {
		return false
	}
	for _, character := range user {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.') {
			return false
		}
	}
	return true
}

func writeHost(b *strings.Builder, aliases []string, hostName, user, hostKeyAlias, identity, knownHosts string, throughBastion, bastion bool) {
	aliases = uniqueStrings(append(append([]string{}, aliases...), hostName))
	fmt.Fprintf(b, "Host %s\n", strings.Join(aliases, " "))
	fmt.Fprintf(b, "    HostName %s\n", hostName)
	b.WriteString("    ConnectTimeout 10\n    ControlMaster auto\n    ControlPersist 60\n    ControlPath ~/.ssh/boetticher-control-%C\n")
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
		b.WriteString("    RequestTTY no\n    ForwardAgent no\n    ForwardX11 no\n    ChannelTimeout direct-tcpip=10\n")
	} else if throughBastion {
		b.WriteString("    ProxyJump lab-bastion\n    StrictHostKeyChecking yes\n")
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
