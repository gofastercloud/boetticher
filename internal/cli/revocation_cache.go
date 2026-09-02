package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
)

const managedCRLCacheDirectory = "revocation"

type crlCacheRevocation struct {
	Name      string `json:"name"`
	Serial    string `json:"serial"`
	RevokedAt string `json:"revoked_at"`
}

type crlCacheInput struct {
	RootKeyPEM     string               `json:"root_key_pem"`
	RootCertPEM    string               `json:"root_cert_pem"`
	IssuingKeyPEM  string               `json:"issuing_key_pem"`
	IssuingCertPEM string               `json:"issuing_cert_pem"`
	Revocations    []crlCacheRevocation `json:"revocations"`
}

func generateOrReuseClientCRL(authority pki.Authority, revocations []pki.Revocation, runtimeDir string, now time.Time) (string, error) {
	cacheable := true
	for _, revocation := range revocations {
		// GenerateCRL uses the current time for a revocation with no recorded
		// timestamp, so that input cannot safely share a cache entry.
		if revocation.RevokedAt.IsZero() {
			cacheable = false
			break
		}
	}

	var cachePath string
	if cacheable {
		key, err := crlCacheKey(authority, revocations)
		if err != nil {
			return "", err
		}
		cachePath = filepath.Join(runtimeDir, "pki", managedCRLCacheDirectory, key+".pem")
		if cached, err := pathguard.ReadFile(cachePath); err == nil {
			if err := pki.ValidateCRL(authority, string(cached), revocations, now); err == nil {
				return string(cached), nil
			}
		}
	}

	crl, err := pki.GenerateCRL(authority, revocations, now)
	if err != nil {
		return "", err
	}
	if err := pki.ValidateCRL(authority, crl, revocations, now); err != nil {
		return "", fmt.Errorf("validate generated CRL: %w", err)
	}
	if cachePath != "" {
		if err := pathguard.MkdirAll(filepath.Dir(cachePath), 0700); err == nil {
			_ = writePublic(cachePath, []byte(crl))
		}
	}
	return crl, nil
}

func crlCacheKey(authority pki.Authority, revocations []pki.Revocation) (string, error) {
	entries := make([]crlCacheRevocation, 0, len(revocations))
	for _, revocation := range revocations {
		entries = append(entries, crlCacheRevocation{
			Name:      revocation.Name,
			Serial:    strings.ToLower(strings.TrimSpace(revocation.Serial)),
			RevokedAt: revocation.RevokedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Serial != entries[j].Serial {
			return entries[i].Serial < entries[j].Serial
		}
		if entries[i].RevokedAt != entries[j].RevokedAt {
			return entries[i].RevokedAt < entries[j].RevokedAt
		}
		return entries[i].Name < entries[j].Name
	})
	payload, err := json.Marshal(crlCacheInput{
		RootKeyPEM:     authority.RootKeyPEM,
		RootCertPEM:    authority.RootCertPEM,
		IssuingKeyPEM:  authority.IssuingKeyPEM,
		IssuingCertPEM: authority.IssuingCertPEM,
		Revocations:    entries,
	})
	if err != nil {
		return "", fmt.Errorf("encode CRL cache key: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
