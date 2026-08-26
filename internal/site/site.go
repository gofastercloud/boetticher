package site

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pki"
)

func Load(dir string) (model.Site, error) {
	data, err := os.ReadFile(filepath.Join(dir, "site.yml"))
	if err != nil {
		return model.Site{}, fmt.Errorf("read site.yml: %w", err)
	}
	s, err := model.ParseSite(data)
	if err != nil {
		return model.Site{}, err
	}
	if err := s.Validate(); err != nil {
		return model.Site{}, err
	}
	return s, nil
}

func Save(dir string, s model.Site) error {
	data, err := model.RenderSite(s)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "site.yml"), data, 0600)
}

func Init(dir, ageIdentityPath string) (model.Site, error) {
	for _, tool := range []string{"age-keygen", "sops", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			return model.Site{}, fmt.Errorf("%s is required to initialize the site: %w", tool, err)
		}
	}
	if _, err := os.Stat(dir); err == nil {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			return model.Site{}, readErr
		}
		if len(entries) != 0 {
			return model.Site{}, fmt.Errorf("site directory %s is not empty", dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return model.Site{}, err
	} else if err := os.MkdirAll(dir, 0700); err != nil {
		return model.Site{}, err
	}
	if err := exec.Command("git", "init", "--initial-branch=main", dir).Run(); err != nil {
		return model.Site{}, fmt.Errorf("initialize private site repository: %w", err)
	}

	recipient, err := createAgeIdentity(ageIdentityPath)
	if err != nil {
		return model.Site{}, err
	}
	installationID, err := randomID()
	if err != nil {
		return model.Site{}, err
	}
	s := model.NewDefaultSite(installationID, recipient)
	authority, err := pki.GenerateAuthority(time.Now().UTC(), s.Network.Domain)
	if err != nil {
		return model.Site{}, fmt.Errorf("generate platform CA hierarchy: %w", err)
	}
	metadata, err := pki.PublicMetadata(authority)
	if err != nil {
		return model.Site{}, fmt.Errorf("read platform CA metadata: %w", err)
	}
	s.PKI = model.PKIMetadata{
		RootCommonName:     metadata["root_ca_cn"],
		RootFingerprint:    metadata["root_ca_fingerprint"],
		RootExpiry:         metadata["root_ca_expiry"],
		IssuingCommonName:  metadata["issuing_ca_cn"],
		IssuingFingerprint: metadata["issuing_fingerprint"],
		IssuingExpiry:      metadata["issuing_ca_expiry"],
	}
	if err := s.Validate(); err != nil {
		return model.Site{}, err
	}
	if err := Save(dir, s); err != nil {
		return model.Site{}, err
	}
	if err := atomicWrite(filepath.Join(dir, ".sops.yaml"), []byte("creation_rules:\n  - age: "+recipient+"\n"), 0600); err != nil {
		return model.Site{}, err
	}
	for _, subdir := range []string{"secrets", "generated", "docs"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0700); err != nil {
			return model.Site{}, err
		}
	}
	if err := atomicWrite(filepath.Join(dir, ".gitignore"), []byte("# Runtime state never belongs in Git\n.runtime/\n.terraform/\n*.tfstate\n*.tfstate.*\nplans/\ncaches/\nbootstrap/\ntmp/\n.env\n"), 0600); err != nil {
		return model.Site{}, err
	}
	if err := writeInitialGenerated(dir, s); err != nil {
		return model.Site{}, err
	}
	if err := writeEncryptedSecrets(dir, s, authority); err != nil {
		return model.Site{}, err
	}
	return s, nil
}

func writeInitialGenerated(dir string, s model.Site) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	modelForProjection := s.Normalize()
	modelForProjection.SSHIdentityFile = ""
	modelDocument := struct {
		ModelRevision string     `json:"model_revision"`
		Model         model.Site `json:"model"`
	}{revision, modelForProjection}
	modelData, err := json.MarshalIndent(modelDocument, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, "generated", "model.json"), append(modelData, '\n'), 0644); err != nil {
		return err
	}
	statusData, err := json.MarshalIndent(struct {
		ModelRevision string `json:"model_revision"`
		Status        string `json:"status"`
		GeneratedAt   string `json:"generated_at"`
	}{revision, "NOT TESTED", time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "generated", "status.json"), append(statusData, '\n'), 0644)
}

func RuntimeDir(s model.Site) string {
	if configured := os.Getenv("BOETTICHER_RUNTIME_DIR"); configured != "" {
		return filepath.Join(configured, s.SecretMetadata.InstallationID)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".runtime", s.SecretMetadata.InstallationID)
	}
	return filepath.Join(home, ".config", "boetticher", "runtime", s.SecretMetadata.InstallationID)
}

func LoadAuthority(dir string, s model.Site, ageIdentityPath string) (pki.Authority, error) {
	values, err := LoadEncryptedDocument(dir, ageIdentityPath, filepath.Join("secrets", "boetticher.sops.yaml"))
	if err != nil {
		return pki.Authority{}, err
	}
	get := func(key string) (string, error) {
		value, ok := values[key].(string)
		if !ok || value == "" {
			return "", fmt.Errorf("encrypted platform secrets missing %s", key)
		}
		return pki.Decode(value)
	}
	rootKey, err := get("root_key_pem_b64")
	if err != nil {
		return pki.Authority{}, err
	}
	rootCert, err := get("root_cert_pem_b64")
	if err != nil {
		return pki.Authority{}, err
	}
	issuingKey, err := get("issuing_key_pem_b64")
	if err != nil {
		return pki.Authority{}, err
	}
	issuingCert, err := get("issuing_cert_pem_b64")
	if err != nil {
		return pki.Authority{}, err
	}
	return pki.Authority{RootKeyPEM: rootKey, RootCertPEM: rootCert, IssuingKeyPEM: issuingKey, IssuingCertPEM: issuingCert}, nil
}

// StoreEncryptedDocument streams a secret document to SOPS. The document is
// never written as a plaintext intermediate. relativePath is constrained to
// the site directory so callers cannot accidentally place encrypted state
// outside the private repository.
func StoreEncryptedDocument(dir, recipient, relativePath string, document any) error {
	if recipient == "" {
		return errors.New("Age recipient is required")
	}
	path, err := safeSitePath(dir, relativePath)
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("sops"); err != nil {
		return fmt.Errorf("sops is required to write encrypted secrets: %w", err)
	}
	plaintext, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode encrypted document: %w", err)
	}
	plaintext = append(plaintext, '\n')
	command := exec.Command("sops", "--encrypt", "--age", recipient, "--input-type", "yaml", "--output-type", "yaml", "/dev/stdin")
	command.Stdin = strings.NewReader(string(plaintext))
	encrypted, err := command.Output()
	if err != nil {
		return fmt.Errorf("encrypt document with SOPS: %w", err)
	}
	return atomicWrite(path, encrypted, 0600)
}

func LoadEncryptedDocument(dir, ageIdentityPath, relativePath string) (map[string]any, error) {
	path, err := safeSitePath(dir, relativePath)
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("sops"); err != nil {
		return nil, fmt.Errorf("sops is required to read encrypted platform secrets: %w", err)
	}
	identity := model.ExpandUserPath(ageIdentityPath)
	if identity == "" {
		return nil, errors.New("Age identity path is required")
	}
	command := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", path)
	command.Env = envWithout("SOPS_AGE_KEY_FILE")
	command.Env = append(command.Env, "SOPS_AGE_KEY_FILE="+identity)
	plaintext, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("decrypt encrypted document with SOPS: %w", err)
	}
	document, err := model.ParseDocument(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parse decrypted document: %w", err)
	}
	values, ok := document.(map[string]any)
	if !ok {
		return nil, errors.New("decrypted document is not a mapping")
	}
	return values, nil
}

func safeSitePath(dir, relativePath string) (string, error) {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return "", errors.New("encrypted document path must be relative to the site repository")
	}
	clean := filepath.Clean(relativePath)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("encrypted document path escapes the site repository")
	}
	return filepath.Join(dir, clean), nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".boetticher-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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

func createAgeIdentity(path string) (string, error) {
	path = model.ExpandUserPath(path)
	if path == "" {
		return "", fmt.Errorf("Age identity path is required")
	}
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("Age identity already exists at %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		return "", fmt.Errorf("age-keygen is required to initialize secrets: %w", err)
	}
	command := exec.Command("age-keygen")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("generate Age identity: %w", err)
	}
	recipient := ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "# public key: ") {
			recipient = strings.TrimSpace(strings.TrimPrefix(line, "# public key: "))
		}
	}
	if recipient == "" {
		return "", fmt.Errorf("age-keygen output did not contain a public recipient")
	}
	if err := atomicWrite(path, output, 0600); err != nil {
		return "", fmt.Errorf("write Age identity: %w", err)
	}
	return recipient, nil
}

func writeEncryptedSecrets(dir string, s model.Site, authority pki.Authority) error {
	secret, err := randomID()
	if err != nil {
		return err
	}
	ddnsSecret, err := randomSecret()
	if err != nil {
		return err
	}
	zabbixDBPassword, err := randomSecret()
	if err != nil {
		return err
	}
	monitorCertificate, err := pki.IssueServer(authority, "monitor", s.Network.Domain, []string{"lab-monitor-01." + s.Network.Domain}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("issue monitor server certificate: %w", err)
	}
	portalCertificate, err := pki.IssueServer(authority, "portal", s.Network.Domain, []string{"lab-portal-01." + s.Network.Domain}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("issue portal server certificate: %w", err)
	}
	// Plaintext exists only in process memory and is piped directly to SOPS.
	document := map[string]string{
		"installation_id":      s.SecretMetadata.InstallationID,
		"bootstrap_secret":     secret,
		"root_key_pem_b64":     pki.Encode(authority.RootKeyPEM),
		"root_cert_pem_b64":    pki.Encode(authority.RootCertPEM),
		"issuing_key_pem_b64":  pki.Encode(authority.IssuingKeyPEM),
		"issuing_cert_pem_b64": pki.Encode(authority.IssuingCertPEM),
		"ddns_tsig_secret":     ddnsSecret,
		"zabbix_db_password":   zabbixDBPassword,
		"monitor_server_key":   pki.Encode(monitorCertificate.KeyPEM),
		"monitor_server_cert":  pki.Encode(monitorCertificate.CertPEM),
		"portal_server_key":    pki.Encode(portalCertificate.KeyPEM),
		"portal_server_cert":   pki.Encode(portalCertificate.CertPEM),
	}
	return StoreEncryptedDocument(dir, s.SecretMetadata.AgeRecipient, filepath.Join("secrets", "boetticher.sops.yaml"), document)
}

// LoadPlatformSecret reads one named value from the encrypted platform
// document without exposing the document or secret in generated artifacts.
func LoadPlatformSecret(dir string, s model.Site, ageIdentityPath, key string) (string, error) {
	values, err := LoadEncryptedDocument(dir, ageIdentityPath, filepath.Join("secrets", "boetticher.sops.yaml"))
	if err != nil {
		return "", err
	}
	value := stringValue(values, key)
	if value == "" {
		return "", fmt.Errorf("encrypted platform secrets missing %s", key)
	}
	return value, nil
}

func randomID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func randomSecret() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data[:]), nil
}

func envWithout(name string) []string {
	prefix := name + "="
	env := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, prefix) {
			env = append(env, value)
		}
	}
	return env
}
