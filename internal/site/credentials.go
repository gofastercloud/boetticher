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
}

func StoreProxmoxCredentials(dir string, s model.Site, credentials ProxmoxCredentials) error {
	if credentials.APIUser == "" || credentials.TokenID == "" || credentials.TokenSecret == "" {
		return fmt.Errorf("Proxmox credentials are incomplete")
	}
	return StoreEncryptedDocument(dir, s.SecretMetadata.AgeRecipient, ProxmoxSecretsPath, credentials)
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
