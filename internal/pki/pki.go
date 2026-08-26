package pki

import (
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
	rootTemplate, err := certificateTemplate("Homelab Root CA", now, true)
	if err != nil {
		return Authority{}, err
	}
	rootTemplate.MaxPathLen = 1
	rootCert, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return Authority{}, err
	}

	issuingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	issuingTemplate, err := certificateTemplate("Homelab Issuing CA", now, true)
	if err != nil {
		return Authority{}, err
	}
	issuingTemplate.Issuer = rootTemplate.Subject
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
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Lab-in-a-Box"}},
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
