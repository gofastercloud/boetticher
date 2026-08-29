package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// Revocation identifies one certificate by serial number. Name is retained
// for operator-facing diagnostics; serial, rather than identity name, is the
// enforcement key so a later replacement certificate is not revoked too.
type Revocation struct {
	Name      string
	Serial    string
	RevokedAt time.Time
}

// CertificateSerial returns the lowercase hexadecimal serial of a leaf
// certificate, suitable for a revocation record.
func CertificateSerial(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("certificate PEM block missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		return "", errors.New("certificate has no positive serial number")
	}
	return cert.SerialNumber.Text(16), nil
}

func ParseSerial(serial string) (*big.Int, error) {
	serial = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(serial)), "0x")
	if serial == "" {
		return nil, errors.New("certificate serial is required")
	}
	value, ok := new(big.Int).SetString(serial, 16)
	if !ok || value.Sign() <= 0 {
		return nil, fmt.Errorf("certificate serial %q is invalid", serial)
	}
	return value, nil
}

// GenerateCRL creates the current enforceable client revocation material for
// the issuing CA. Entries are sorted by serial to keep the generated artifact
// stable for the same revocation set; the CRL number and timestamps are still
// fresh on each deployment.
func GenerateCRL(authority Authority, revocations []Revocation, now time.Time) (string, error) {
	issuingKey, err := parseECKey(authority.IssuingKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse issuing key: %w", err)
	}
	issuingCert, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		return "", fmt.Errorf("parse issuing certificate: %w", err)
	}
	// Authorities created before CRL support may not have an SKI. Deriving it
	// from the existing public key preserves compatibility while keeping the
	// CRL issuer and signature tied to the configured issuing key.
	issuer := *issuingCert
	if len(issuer.SubjectKeyId) == 0 {
		issuer.SubjectKeyId = publicKeyIdentifier(issuer.PublicKey)
	}
	if len(issuer.SubjectKeyId) == 0 {
		return "", errors.New("issuing certificate has no usable subject key identifier")
	}
	sorted := append([]Revocation(nil), revocations...)
	sort.Slice(sorted, func(i, j int) bool { return strings.ToLower(sorted[i].Serial) < strings.ToLower(sorted[j].Serial) })
	entries := make([]x509.RevocationListEntry, 0, len(sorted))
	seen := map[string]struct{}{}
	for _, revocation := range sorted {
		serial, parseErr := ParseSerial(revocation.Serial)
		if parseErr != nil {
			return "", fmt.Errorf("revocation %s: %w", revocation.Name, parseErr)
		}
		key := serial.Text(16)
		if _, exists := seen[key]; exists {
			return "", fmt.Errorf("duplicate revoked certificate serial %s", key)
		}
		seen[key] = struct{}{}
		revokedAt := revocation.RevokedAt.UTC()
		if revokedAt.IsZero() {
			revokedAt = now.UTC()
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revokedAt})
	}
	now = now.UTC()
	number, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("generate CRL number: %w", err)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:        issuer.SignatureAlgorithm,
		RevokedCertificateEntries: entries,
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(10, 0, 0),
	}, &issuer, issuingKey)
	if err != nil {
		return "", fmt.Errorf("create client certificate CRL: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}
