package site

import (
	"fmt"

	"github.com/dave/labinabox/internal/model"
)

func LoadDDNSTSIG(dir string, s model.Site, ageIdentityPath string) (string, error) {
	values, err := LoadEncryptedDocument(dir, ageIdentityPath, "secrets/homelab.sops.yaml")
	if err != nil {
		return "", err
	}
	value, ok := values["ddns_tsig_secret"].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("encrypted platform secrets missing ddns_tsig_secret")
	}
	return value, nil
}
