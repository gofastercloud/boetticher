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
	"strings"
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

type ServerCertificate struct {
	Name        string
	CertPEM     string
	ChainPEM    string
	Fingerprint string
}

// SignServerCSR signs a CSR whose key was generated on the managed endpoint.
// The requested identity is checked against the model before the issuing CA
// is allowed to sign it. The returned certificate deliberately contains no
// private key.
func SignServerCSR(authority Authority, csrPEM, name, domain string, aliases []string, now time.Time) (ServerCertificate, error) {
	if err := ValidateClientName(name); err != nil {
		return ServerCertificate{}, err
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return ServerCertificate{}, fmt.Errorf("server CSR PEM block missing")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("parse server CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return ServerCertificate{}, fmt.Errorf("verify server CSR signature: %w", err)
	}
	wantNames := append([]string{name + "." + domain}, aliases...)
	if csr.Subject.CommonName != wantNames[0] || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 || !sameDNSNames(csr.DNSNames, wantNames) {
		return ServerCertificate{}, fmt.Errorf("server CSR identity is not approved for %s", name)
	}
	issuingKey, err := parseECKey(authority.IssuingKeyPEM)
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("parse issuing key: %w", err)
	}
	issuingCert, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("parse issuing certificate: %w", err)
	}
	template, err := certificateTemplate(wantNames[0], now, false)
	if err != nil {
		return ServerCertificate{}, err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.DNSNames = append([]string(nil), wantNames...)
	der, err := x509.CreateCertificate(rand.Reader, template, issuingCert, csr.PublicKey, issuingKey)
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("sign server CSR: %w", err)
	}
	fingerprint := sha256.Sum256(der)
	return ServerCertificate{
		Name: name, CertPEM: marshalCert(der), ChainPEM: marshalCert(der) + authority.IssuingCertPEM,
		Fingerprint: fmt.Sprintf("sha256:%x", fingerprint[:]),
	}, nil
}

func sameDNSNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := map[string]int{}
	for _, name := range got {
		counts[strings.ToLower(strings.TrimSuffix(name, "."))]++
	}
	for _, name := range want {
		key := strings.ToLower(strings.TrimSuffix(name, "."))
		counts[key]--
		if counts[key] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
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

func IssueServer(authority Authority, name, domain string, aliases []string, now time.Time) (ServerCertificate, error) {
	if err := ValidateClientName(name); err != nil {
		return ServerCertificate{}, err
	}
	issuingKey, err := parseECKey(authority.IssuingKeyPEM)
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("parse issuing key: %w", err)
	}
	issuingCert, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("parse issuing certificate: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ServerCertificate{}, err
	}
	template, err := certificateTemplate(name+"."+domain, now, false)
	if err != nil {
		return ServerCertificate{}, err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.DNSNames = append([]string{name + "." + domain}, aliases...)
	for _, alias := range template.DNSNames {
		if alias == "" || strings.ContainsAny(alias, "\r\n") {
			return ServerCertificate{}, fmt.Errorf("server certificate contains an unsafe DNS name")
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuingCert, &key.PublicKey, issuingKey)
	if err != nil {
		return ServerCertificate{}, err
	}
	fingerprint := sha256.Sum256(der)
	return ServerCertificate{
		Name: name, KeyPEM: marshalECKey(key), CertPEM: marshalCert(der), ChainPEM: marshalCert(der) + authority.IssuingCertPEM,
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
