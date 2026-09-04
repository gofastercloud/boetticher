package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

type Authority struct {
	RootKeyPEM     string
	RootCertPEM    string
	IssuingKeyPEM  string
	IssuingCertPEM string
}

type ClientCertificate struct {
	Name        string
	KeyPEM      string
	CertPEM     string
	ChainPEM    string
	Fingerprint string
	Serial      string
}

// CertificateRenewalWindow is the safety margin used when deciding whether a
// cached browser or device certificate can be reused.
const CertificateRenewalWindow = 30 * 24 * time.Hour

// ValidateClientCertificate validates a cached endpoint client certificate
// against the current CSR and authority.
func ValidateClientCertificate(authority Authority, chainPEM, csrPEM, name, domain string, now time.Time) (ClientCertificate, error) {
	if err := ValidateClientName(name); err != nil {
		return ClientCertificate{}, err
	}
	wanted := "client-" + name + "." + domain
	csr, err := parseAndValidateCSR(csrPEM, wanted)
	if err != nil {
		return ClientCertificate{}, err
	}
	leaf, issuing, err := parseCertificateChain(chainPEM)
	if err != nil {
		return ClientCertificate{}, err
	}
	if err := validateCachedCertificate(authority, leaf, issuing, csr, x509.ExtKeyUsageClientAuth, now); err != nil {
		return ClientCertificate{}, err
	}
	return ClientCertificate{
		Name:        name,
		CertPEM:     marshalCert(leaf.Raw),
		ChainPEM:    marshalCert(leaf.Raw) + authority.IssuingCertPEM,
		Fingerprint: certificateFingerprint(leaf.Raw),
		Serial:      leaf.SerialNumber.Text(16),
	}, nil
}

func parseAndValidateCSR(csrPEM, wanted string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("certificate request PEM block missing")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("certificate request contains unexpected trailing data")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify certificate request signature: %w", err)
	}
	if csr.Subject.CommonName != wanted || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, fmt.Errorf("certificate request identity is not approved for %s", wanted)
	}
	if len(csr.DNSNames) != 0 {
		return nil, fmt.Errorf("client certificate request must not contain DNS SANs")
	}
	return csr, nil
}

func parseCertificateChain(chainPEM string) (*x509.Certificate, *x509.Certificate, error) {
	rest := []byte(chainPEM)
	certificates := make([]*x509.Certificate, 0, 2)
	for range 2 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("certificate chain must contain a leaf and issuing certificate")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		certificates = append(certificates, certificate)
		rest = remaining
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("certificate chain contains unexpected trailing data")
	}
	return certificates[0], certificates[1], nil
}

func validateCachedCertificate(authority Authority, leaf, issuing *x509.Certificate, csr *x509.CertificateRequest, usage x509.ExtKeyUsage, now time.Time) error {
	if leaf == nil || issuing == nil || csr == nil {
		return fmt.Errorf("cached certificate inputs are incomplete")
	}
	currentIssuing, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		return fmt.Errorf("parse current issuing certificate: %w", err)
	}
	if !bytes.Equal(issuing.Raw, currentIssuing.Raw) {
		return fmt.Errorf("cached certificate uses a different issuing certificate")
	}
	root, err := parseCert(authority.RootCertPEM)
	if err != nil {
		return fmt.Errorf("parse current root certificate: %w", err)
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("cached certificate has unexpected CA or key usage constraints")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != usage || len(leaf.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("cached certificate has unexpected extended key usage")
	}
	if leaf.Subject.CommonName != csr.Subject.CommonName || !certificateSubjectMatches(leaf.Subject, csr.Subject.CommonName) {
		return fmt.Errorf("cached certificate subject does not match the CSR")
	}
	if len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 {
		return fmt.Errorf("cached client certificate contains subject alternatives")
	}
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CSR public key: %w", err)
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal cached certificate public key: %w", err)
	}
	if !bytes.Equal(csrKey, certificateKey) {
		return fmt.Errorf("cached certificate public key does not match the CSR")
	}
	if !leaf.NotAfter.After(now.UTC().Add(CertificateRenewalWindow)) {
		return fmt.Errorf("cached certificate is within the renewal window")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuing)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now.UTC(),
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}); err != nil {
		return fmt.Errorf("verify cached certificate chain: %w", err)
	}
	return nil
}

func certificateSubjectMatches(subject pkix.Name, commonName string) bool {
	return subject.String() == (pkix.Name{CommonName: commonName, Organization: []string{"boetticher"}}).String() && len(subject.ExtraNames) == 0
}

func certificateFingerprint(der []byte) string {
	fingerprint := sha256.Sum256(der)
	return fmt.Sprintf("sha256:%x", fingerprint[:])
}

var clientNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

func ValidateClientName(name string) error {
	if !clientNamePattern.MatchString(name) {
		return fmt.Errorf("client name must contain only letters, digits, dot, underscore, or hyphen")
	}
	return nil
}

func GenerateAuthority(now time.Time, domain string) (Authority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	rootTemplate, err := certificateTemplate("boetticher Root CA", now, true)
	if err != nil {
		return Authority{}, err
	}
	rootTemplate.MaxPathLen = 1
	rootTemplate.SubjectKeyId = publicKeyIdentifier(&rootKey.PublicKey)
	rootCert, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return Authority{}, err
	}

	issuingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	issuingTemplate, err := certificateTemplate("boetticher Issuing CA", now, true)
	if err != nil {
		return Authority{}, err
	}
	issuingTemplate.Issuer = rootTemplate.Subject
	issuingTemplate.SubjectKeyId = publicKeyIdentifier(&issuingKey.PublicKey)
	issuingCert, err := x509.CreateCertificate(rand.Reader, issuingTemplate, rootTemplate, &issuingKey.PublicKey, rootKey)
	if err != nil {
		return Authority{}, err
	}

	return Authority{
		RootKeyPEM:     marshalECKey(rootKey),
		RootCertPEM:    marshalCert(rootCert),
		IssuingKeyPEM:  marshalECKey(issuingKey),
		IssuingCertPEM: marshalCert(issuingCert),
	}, nil
}

func IssueClient(authority Authority, name, domain string, now time.Time) (ClientCertificate, error) {
	if err := ValidateClientName(name); err != nil {
		return ClientCertificate{}, err
	}
	issuingKey, err := parseECKey(authority.IssuingKeyPEM)
	if err != nil {
		return ClientCertificate{}, fmt.Errorf("parse issuing key: %w", err)
	}
	issuingCert, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		return ClientCertificate{}, fmt.Errorf("parse issuing certificate: %w", err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ClientCertificate{}, err
	}
	template, err := certificateTemplate("client-"+name+"."+domain, now, false)
	if err != nil {
		return ClientCertificate{}, err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	der, err := x509.CreateCertificate(rand.Reader, template, issuingCert, &clientKey.PublicKey, issuingKey)
	if err != nil {
		return ClientCertificate{}, err
	}
	fingerprint := sha256.Sum256(der)
	return ClientCertificate{
		Name:        name,
		KeyPEM:      marshalECKey(clientKey),
		CertPEM:     marshalCert(der),
		ChainPEM:    marshalCert(der) + authority.IssuingCertPEM,
		Fingerprint: fmt.Sprintf("sha256:%x", fingerprint[:]),
		Serial:      template.SerialNumber.Text(16),
	}, nil
}

func PublicMetadata(authority Authority) (map[string]string, error) {
	root, err := parseCert(authority.RootCertPEM)
	if err != nil {
		return nil, err
	}
	issuing, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		return nil, err
	}
	rootHash := sha256.Sum256(root.Raw)
	issuingHash := sha256.Sum256(issuing.Raw)
	return map[string]string{
		"root_ca_cn":          root.Subject.CommonName,
		"root_ca_fingerprint": fmt.Sprintf("sha256:%x", rootHash[:]),
		"root_ca_expiry":      root.NotAfter.UTC().Format(time.RFC3339),
		"issuing_ca_cn":       issuing.Subject.CommonName,
		"issuing_fingerprint": fmt.Sprintf("sha256:%x", issuingHash[:]),
		"issuing_ca_expiry":   issuing.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

func Encode(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func Decode(value string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	return string(data), err
}

func publicKeyIdentifier(key any) []byte {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(der)
	return append([]byte(nil), hash[:20]...)
}

func certificateTemplate(commonName string, now time.Time, isCA bool) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"boetticher"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		MaxPathLen:            0,
	}, nil
}

func marshalECKey(key *ecdsa.PrivateKey) string {
	der, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func marshalCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func parseECKey(value string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("PEM block missing")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func parseCert(value string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("certificate PEM block missing")
	}
	return x509.ParseCertificate(block.Bytes)
}
