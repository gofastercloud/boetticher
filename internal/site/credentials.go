package site

import (
	"fmt"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	ProxmoxSecretsPath = "secrets/proxmox.sops.yaml"
)

type ProxmoxCredentials struct {
	APIUser     string `json:"api_user"`
	TokenID     string `json:"token_id"`
	TokenSecret string `json:"token_secret"`
	CAPEM       string `json:"ca_pem,omitempty"`
}

func StoreProxmoxCredentials(dir string, s model.Site, ageIdentityPath string, credentials ProxmoxCredentials) error {
	if credentials.APIUser == "" || credentials.TokenID == "" || credentials.TokenSecret == "" {
		return fmt.Errorf("Proxmox credentials are incomplete")
	}
	recipient, err := validatedAgeRecipient(ageIdentityPath, s.SecretMetadata.AgeRecipient)
	if err != nil {
		return fmt.Errorf("validate Age identity for Proxmox credential storage: %w", err)
	}
	return StoreEncryptedDocument(dir, recipient, ProxmoxSecretsPath, credentials)
}

func LoadProxmoxCredentials(dir string, s model.Site, ageIdentityPath string) (ProxmoxCredentials, error) {
	values, err := LoadEncryptedDocument(dir, ageIdentityPath, ProxmoxSecretsPath)
	if err != nil {
		return ProxmoxCredentials{}, err
	}
	return ProxmoxCredentials{
		APIUser:     stringValue(values, "api_user"),
		TokenID:     stringValue(values, "token_id"),
		TokenSecret: stringValue(values, "token_secret"),
		CAPEM:       stringValue(values, "ca_pem"),
	}, validateProxmoxCredentials(values)
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func validateProxmoxCredentials(values map[string]any) error {
	for _, key := range []string{"api_user", "token_id", "token_secret"} {
		if stringValue(values, key) == "" {
			return fmt.Errorf("encrypted Proxmox credentials are missing %s", key)
		}
	}
	return nil
}

func RuntimeCredentialPath(s model.Site, name string) string {
	return filepath.Join(RuntimeDir(s), "credentials", name)
}
