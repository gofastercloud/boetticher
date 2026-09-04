package pki

import (
	"bytes"
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
// the issuing CA. Managed client certificates are issued by the intermediate;
// normal operations must not require decrypting the cold root key merely to
// create an empty root CRL.
func GenerateCRL(authority Authority, revocations []Revocation, now time.Time) (string, error) {
	issuingCRL, err := generateCARevocationList(authority.IssuingCertPEM, authority.IssuingKeyPEM, revocations, now)
	if err != nil {
		return "", fmt.Errorf("create issuing CA CRL: %w", err)
	}
	return issuingCRL, nil
}

// ValidateCRL verifies the controller-issued issuing-CA CRL against the
// current authority and exact revocation set. It is used before a cached CRL
// is reused; a cache hit must not bypass trust or revocation validation.
func ValidateCRL(authority Authority, crlPEM string, revocations []Revocation, now time.Time) error {
	issuing, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		return fmt.Errorf("parse issuing certificate: %w", err)
	}
	issuingKey, err := parseECKey(authority.IssuingKeyPEM)
	if err != nil {
		return fmt.Errorf("parse issuing key: %w", err)
	}
	if !samePublicKey(issuingKey.Public(), issuing.PublicKey) {
		return errors.New("issuing private key does not match the issuing certificate")
	}

	crl, err := parseCRL(crlPEM)
	if err != nil {
		return err
	}
	if err := validateParsedCRL(crl, issuing, now); err != nil {
		return fmt.Errorf("validate issuing CRL: %w", err)
	}

	expected, err := normalizedRevocations(revocations, now)
	if err != nil {
		return err
	}
	actual := crl.RevokedCertificateEntries
	if len(actual) != len(expected) {
		return fmt.Errorf("issuing CRL contains %d revoked certificates, expected %d", len(actual), len(expected))
	}
	for index, entry := range actual {
		if entry.SerialNumber == nil || entry.SerialNumber.Cmp(expected[index].serial) != 0 {
			return fmt.Errorf("issuing CRL serial at index %d does not match the requested revocation set", index)
		}
		if !entry.RevocationTime.Equal(expected[index].revokedAt) {
			return fmt.Errorf("issuing CRL revocation time for serial %s does not match", entry.SerialNumber.Text(16))
		}
	}
	return nil
}

type normalizedRevocation struct {
	serial    *big.Int
	revokedAt time.Time
}

func normalizedRevocations(revocations []Revocation, now time.Time) ([]normalizedRevocation, error) {
	sorted := append([]Revocation(nil), revocations...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(sorted[i].Serial)) < strings.ToLower(strings.TrimSpace(sorted[j].Serial))
	})
	expected := make([]normalizedRevocation, 0, len(sorted))
	seen := map[string]struct{}{}
	for _, revocation := range sorted {
		serial, err := ParseSerial(revocation.Serial)
		if err != nil {
			return nil, fmt.Errorf("revocation %s: %w", revocation.Name, err)
		}
		key := serial.Text(16)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate revoked certificate serial %s", key)
		}
		seen[key] = struct{}{}
		revokedAt := revocation.RevokedAt.UTC()
		if revokedAt.IsZero() {
			revokedAt = now.UTC()
		}
		expected = append(expected, normalizedRevocation{
			serial:    serial,
			revokedAt: revokedAt.Truncate(time.Second),
		})
	}
	return expected, nil
}

func parseCRL(value string) (*x509.RevocationList, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "X509 CRL" {
		return nil, errors.New("CRL must contain an issuing CA CRL")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("CRL contains unexpected trailing data")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	return crl, nil
}

func validateParsedCRL(crl *x509.RevocationList, issuer *x509.Certificate, now time.Time) error {
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return errors.New("CRL issuer does not match its signing certificate")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("verify CRL signature: %w", err)
	}
	now = now.UTC()
	if crl.ThisUpdate.After(now.Add(5 * time.Minute)) {
		return errors.New("CRL is issued in the future")
	}
	if !crl.NextUpdate.After(now) {
		return errors.New("CRL is expired")
	}
	return nil
}

func samePublicKey(left, right any) bool {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	return err == nil && bytes.Equal(leftDER, rightDER)
}

func generateCARevocationList(certPEM, keyPEM string, revocations []Revocation, now time.Time) (string, error) {
	key, err := parseECKey(keyPEM)
	if err != nil {
		return "", fmt.Errorf("parse CA key: %w", err)
	}
	certificate, err := parseCert(certPEM)
	if err != nil {
		return "", fmt.Errorf("parse CA certificate: %w", err)
	}
	// Authorities created before CRL support may not have an SKI. Deriving it
	// from the existing public key preserves compatibility while keeping the
	// CRL issuer and signature tied to the configured CA key.
	issuer := *certificate
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
	}, &issuer, key)
	if err != nil {
		return "", fmt.Errorf("create client certificate CRL: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}
