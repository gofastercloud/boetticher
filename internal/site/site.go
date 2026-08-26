package site

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dave/labinabox/internal/model"
	"github.com/dave/labinabox/internal/pki"
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
	if err := atomicWrite(filepath.Join(dir, ".gitignore"), []byte("# Runtime state never belongs in Git\n.runtime/\n*.tfstate\n*.tfstate.*\nplans/\ncaches/\nbootstrap/\ntmp/\n"), 0600); err != nil {
		return model.Site{}, err
	}
	if err := writeEncryptedSecrets(dir, s, authority); err != nil {
		return model.Site{}, err
	}
	return s, nil
}

func RuntimeDir(s model.Site) string {
	if configured := os.Getenv("LABINABOX_RUNTIME_DIR"); configured != "" {
		return filepath.Join(configured, s.SecretMetadata.InstallationID)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".runtime", s.SecretMetadata.InstallationID)
	}
	return filepath.Join(home, ".config", "labinabox", "runtime", s.SecretMetadata.InstallationID)
}

func LoadAuthority(dir string, s model.Site, ageIdentityPath string) (pki.Authority, error) {
	if _, err := exec.LookPath("sops"); err != nil {
		return pki.Authority{}, fmt.Errorf("sops is required to read encrypted platform secrets: %w", err)
	}
	command := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", filepath.Join(dir, "secrets", "homelab.sops.yaml"))
	command.Env = envWithout("SOPS_AGE_KEY_FILE")
	command.Env = append(command.Env, "SOPS_AGE_KEY_FILE="+model.ExpandUserPath(ageIdentityPath))
	plaintext, err := command.Output()
	if err != nil {
		return pki.Authority{}, fmt.Errorf("decrypt platform secrets with SOPS: %w", err)
	}
	document, err := model.ParseDocument(plaintext)
	if err != nil {
		return pki.Authority{}, fmt.Errorf("parse decrypted platform secrets: %w", err)
	}
	values, ok := document.(map[string]any)
	if !ok {
		return pki.Authority{}, fmt.Errorf("decrypted platform secrets are not a mapping")
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

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".labinabox-*")
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
	if _, err := exec.LookPath("sops"); err != nil {
		return fmt.Errorf("sops is required to initialize encrypted secrets: %w", err)
	}
	secret, err := randomID()
	if err != nil {
		return err
	}
	// Plaintext exists only in process memory and is piped directly to SOPS.
	plaintext := []byte("installation_id: " + s.SecretMetadata.InstallationID + "\nbootstrap_secret: " + secret + "\nroot_key_pem_b64: " + pki.Encode(authority.RootKeyPEM) + "\nroot_cert_pem_b64: " + pki.Encode(authority.RootCertPEM) + "\nissuing_key_pem_b64: " + pki.Encode(authority.IssuingKeyPEM) + "\nissuing_cert_pem_b64: " + pki.Encode(authority.IssuingCertPEM) + "\n")
	command := exec.Command("sops", "--encrypt", "--age", s.SecretMetadata.AgeRecipient, "--input-type", "yaml", "--output-type", "yaml", "/dev/stdin")
	command.Stdin = strings.NewReader(string(plaintext))
	encrypted, err := command.Output()
	if err != nil {
		return fmt.Errorf("encrypt initial secrets with SOPS: %w", err)
	}
	return atomicWrite(filepath.Join(dir, "secrets", "homelab.sops.yaml"), encrypted, 0600)
}

func randomID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
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
