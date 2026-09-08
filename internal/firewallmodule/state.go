package firewallmodule

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	credentialFile = "credential"
	trustFile      = "tls-cert"
	stateEnv       = "BOETTICHER_PROVIDER_STATE_DIR"
)

// StateDir returns the Controller-local provider state root. Tests and
// disposable qualification can override the root without changing the
// production path contract.
func StateDir(site model.Site) string {
	if root := os.Getenv(stateEnv); root != "" {
		return filepath.Join(root, "firewall")
	}
	id := site.SecretMetadata.InstallationID
	if id == "" {
		id = "default"
	}
	return filepath.Join("/var/lib/boetticher/providers/firewall", id)
}

// EnsureCredential returns an existing provider password or creates one with
// restrictive Controller-local permissions. The value is returned only to
// the in-process bootstrap path.
func EnsureCredential(dir string) (credential string, created bool, err error) {
	path := filepath.Join(dir, credentialFile)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return "", false, err
	}
	data, readErr := pathguard.ReadFileLimited(path, 4096)
	if readErr == nil {
		credential = strings.TrimSpace(string(data))
		if credential == "" || strings.ContainsAny(credential, "\r\n") {
			return "", false, errors.New("provider credential state is malformed")
		}
		return credential, false, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return "", false, fmt.Errorf("read provider credential state: %w", readErr)
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", false, fmt.Errorf("generate provider credential: %w", err)
	}
	credential = base64.RawURLEncoding.EncodeToString(bytes)
	for index := range bytes {
		bytes[index] = 0
	}
	if err := pathguard.WriteFileWithParentMode(path, []byte(credential+"\n"), 0600, 0700); err != nil {
		return "", false, fmt.Errorf("store provider credential: %w", err)
	}
	return credential, true, nil
}

func LoadCredential(dir string) (string, error) {
	path := filepath.Join(dir, credentialFile)
	data, err := pathguard.ReadFileLimited(path, 4096)
	if err != nil {
		return "", err
	}
	credential := strings.TrimSpace(string(data))
	if credential == "" || strings.ContainsAny(credential, "\r\n") {
		return "", errors.New("provider credential state is malformed")
	}
	return credential, nil
}

func LoadTrust(dir string) ([]byte, error) {
	path := filepath.Join(dir, trustFile)
	data, err := pathguard.ReadFileLimited(path, 1<<20)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		return nil, errors.New("provider TLS trust state is malformed")
	}
	return data, nil
}

func StoreTrust(dir string, pem []byte) error {
	if len(pem) == 0 || !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		return errors.New("provider TLS certificate is empty or malformed")
	}
	path := filepath.Join(dir, trustFile)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	if err := pathguard.WriteFileWithParentMode(path, pem, 0600, 0700); err != nil {
		return fmt.Errorf("store provider TLS trust: %w", err)
	}
	return nil
}

// RemoveTrust clears only the provider certificate pin when an owned provider
// is deliberately replaced. The Controller credential and other state remain
// reusable across the replacement.
func RemoveTrust(dir string) error {
	path := filepath.Join(dir, trustFile)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	return pathguard.RemoveAll(path)
}

func RemoveState(dir string) error {
	if err := pathguard.ValidateNoSymlinkComponents(dir); err != nil {
		return err
	}
	if err := pathguard.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove provider state: %w", err)
	}
	return nil
}
