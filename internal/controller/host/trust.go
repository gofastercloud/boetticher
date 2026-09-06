package host

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

func ValidateHostKey(address, value string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("Proxmox address must be an IPv4 address: %q", address)
	}
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("Proxmox host key must be one authorized-key line")
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || key == nil {
		return "", errors.New("Proxmox host key is not valid OpenSSH public-key syntax")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return "", errors.New("Proxmox host key contains unexpected trailing data")
	}
	return strings.TrimSpace(address) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
}

func ImportTrust(address, value string) (bool, error) {
	line, err := ValidateHostKey(address, value)
	if err != nil {
		return false, err
	}
	if os.Geteuid() != 0 {
		return false, errors.New("host trust import requires root; run it with sudo")
	}
	if err := pathguard.ValidateNoSymlinkComponents(KnownHostsPath); err != nil {
		return false, fmt.Errorf("validate controller known-hosts path: %w", err)
	}
	if err := pathguard.MkdirAll(SSHDirectory, 0700); err != nil {
		return false, fmt.Errorf("create controller SSH directory: %w", err)
	}
	data, err := os.ReadFile(KnownHostsPath)
	if errors.Is(err, os.ErrNotExist) {
		data = nil
	} else if err != nil {
		return false, fmt.Errorf("read controller known-hosts: %w", err)
	}
	addressValue := strings.TrimSpace(address)
	for _, raw := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || fields[0] != addressValue {
			continue
		}
		existing, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(strings.Join(fields[1:], " ")))
		if parseErr != nil {
			return false, fmt.Errorf("existing controller host key entry is malformed: %w", parseErr)
		}
		candidate, _, _, _, candidateErr := ssh.ParseAuthorizedKey([]byte(strings.TrimPrefix(line, addressValue+" ")))
		if candidateErr != nil || string(existing.Marshal()) != string(candidate.Marshal()) {
			return false, errors.New("Proxmox host key changed; refusing to replace the trusted entry")
		}
		return false, nil
	}
	updated := string(data)
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += line + "\n"
	if err := pathguard.WriteFileWithParentMode(KnownHostsPath, []byte(updated), 0600, 0700); err != nil {
		return false, fmt.Errorf("write controller known-hosts: %w", err)
	}
	return true, nil
}
