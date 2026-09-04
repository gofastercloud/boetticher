package site

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
	"gopkg.in/yaml.v3"
)

type revocationRecord struct {
	Name      string `yaml:"name"`
	Serial    string `yaml:"serial"`
	Status    string `yaml:"status"`
	RevokedAt string `yaml:"revoked_at"`
}

const (
	maxRevocationEntries     = 256
	maxRevocationRecordBytes = 64 << 10
)

// LoadClientRevocations loads certificate-specific revocation records and
// fails closed when a record cannot produce enforceable CRL material.
func LoadClientRevocations(dir string) ([]pki.Revocation, error) {
	revokedDir := filepath.Join(dir, "generated", "pki", "revoked")
	if err := pathguard.ValidateNoSymlinkComponents(revokedDir); err != nil {
		return nil, err
	}
	entries, err := pathguard.ReadDirLimited(revokedDir, maxRevocationEntries)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read client revocation directory: %w", err)
	}
	result := make([]pki.Revocation, 0, len(entries))
	seenSerials := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(revokedDir, entry.Name())
		if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
			return nil, err
		}
		data, err := pathguard.ReadFileLimited(path, maxRevocationRecordBytes)
		if err != nil {
			return nil, fmt.Errorf("read client revocation %s: %w", entry.Name(), err)
		}
		var record revocationRecord
		if err := yaml.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("parse client revocation %s: %w", entry.Name(), err)
		}
		if err := pki.ValidateClientName(record.Name); err != nil {
			return nil, fmt.Errorf("client revocation %s has invalid name: %w", entry.Name(), err)
		}
		if record.Status != "revoked" {
			return nil, fmt.Errorf("client revocation %s does not have revoked status", entry.Name())
		}
		serial, err := pki.ParseSerial(record.Serial)
		if err != nil {
			return nil, fmt.Errorf("client revocation %s: %w", entry.Name(), err)
		}
		canonicalSerial := serial.Text(16)
		if _, exists := seenSerials[canonicalSerial]; exists {
			return nil, fmt.Errorf("duplicate client revocation serial %s", canonicalSerial)
		}
		seenSerials[canonicalSerial] = struct{}{}
		var revokedAt time.Time
		if record.RevokedAt != "" {
			revokedAt, err = time.Parse(time.RFC3339, record.RevokedAt)
			if err != nil {
				return nil, fmt.Errorf("client revocation %s has invalid revoked_at: %w", entry.Name(), err)
			}
		}
		result = append(result, pki.Revocation{Name: record.Name, Serial: canonicalSerial, RevokedAt: revokedAt})
	}
	return result, nil
}
