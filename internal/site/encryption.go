package site

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/yaml"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"google.golang.org/grpc"
)

const (
	bundledSOPSVersion = "3.13.3"
	bundledAgeVersion  = "1.3.1"
)

// BundledEncryptionVersions identifies the cryptographic implementations
// compiled into the controller binary.
func BundledEncryptionVersions() (sopsVersion, ageVersion string) {
	return bundledSOPSVersion, bundledAgeVersion
}

// Store and recover only the SOPS YAML/Age contract used by Boetticher. The
// upstream libraries are linked into the controller, so no SOPS, age, or
// external encryption helper executable is required at runtime.

func encryptSOPSYAML(plaintext []byte, recipient string) ([]byte, error) {
	store := yaml.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parse plaintext YAML: %w", err)
	}
	masterKey, err := sopsage.MasterKeyFromRecipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("parse Age recipient: %w", err)
	}
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{masterKey}},
			Version:   bundledSOPSVersion,
		},
	}
	dataKey, errs := tree.GenerateDataKey()
	if len(errs) > 0 {
		return nil, fmt.Errorf("generate SOPS data key: %v", errs)
	}
	if err := encryptSOPSTree(&tree, dataKey); err != nil {
		return nil, err
	}
	encrypted, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted YAML: %w", err)
	}
	return encrypted, nil
}

func decryptSOPSYAML(encrypted, identityData []byte) ([]byte, error) {
	store := yaml.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, fmt.Errorf("parse encrypted YAML: %w", err)
	}
	identities, err := age.ParseIdentities(bytes.NewReader(identityData))
	if err != nil {
		return nil, fmt.Errorf("parse Age identity: %w", err)
	}
	keyService := bundledAgeKeyService{identities: sopsage.ParsedIdentities(identities)}
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyService}, nil)
	if err != nil {
		return nil, fmt.Errorf("recover SOPS data key: %w", err)
	}
	if err := decryptSOPSTree(&tree, dataKey); err != nil {
		return nil, err
	}
	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("encode plaintext YAML: %w", err)
	}
	return plaintext, nil
}

func encryptSOPSTree(tree *sops.Tree, dataKey []byte) error {
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("encrypt SOPS values: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("encrypt SOPS MAC: %w", err)
	}
	return nil
}

func decryptSOPSTree(tree *sops.Tree, dataKey []byte) error {
	cipher := aes.NewCipher()
	computedMAC, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("decrypt SOPS values: %w", err)
	}
	fileMAC, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("decrypt SOPS MAC: %w", err)
	}
	if fileMAC != computedMAC {
		return errors.New("SOPS MAC mismatch")
	}
	return nil
}

type bundledAgeKeyService struct {
	identities sopsage.ParsedIdentities
}

func (s bundledAgeKeyService) Encrypt(ctx context.Context, request *keyservice.EncryptRequest, _ ...grpc.CallOption) (*keyservice.EncryptResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	masterKey, err := ageMasterKeyFromRequest(request)
	if err != nil {
		return nil, err
	}
	if err := masterKey.Encrypt(request.Plaintext); err != nil {
		return nil, fmt.Errorf("encrypt Age data key: %w", err)
	}
	return &keyservice.EncryptResponse{Ciphertext: masterKey.EncryptedDataKey()}, nil
}

func (s bundledAgeKeyService) Decrypt(ctx context.Context, request *keyservice.DecryptRequest, _ ...grpc.CallOption) (*keyservice.DecryptResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	masterKey, err := ageMasterKeyFromDecryptRequest(request)
	if err != nil {
		return nil, err
	}
	s.identities.ApplyToMasterKey(masterKey)
	plaintext, err := masterKey.Decrypt()
	if err != nil {
		return nil, fmt.Errorf("decrypt Age data key: %w", err)
	}
	return &keyservice.DecryptResponse{Plaintext: plaintext}, nil
}

func ageMasterKeyFromRequest(request *keyservice.EncryptRequest) (*sopsage.MasterKey, error) {
	if request == nil || request.Key == nil || request.Key.GetAgeKey() == nil {
		return nil, errors.New("SOPS key request is not an Age key")
	}
	return sopsage.MasterKeyFromRecipient(request.Key.GetAgeKey().GetRecipient())
}

func ageMasterKeyFromDecryptRequest(request *keyservice.DecryptRequest) (*sopsage.MasterKey, error) {
	if request == nil || request.Key == nil || request.Key.GetAgeKey() == nil {
		return nil, errors.New("SOPS key request is not an Age key")
	}
	masterKey, err := sopsage.MasterKeyFromRecipient(request.Key.GetAgeKey().GetRecipient())
	if err != nil {
		return nil, err
	}
	masterKey.SetEncryptedDataKey(request.Ciphertext)
	return masterKey, nil
}

func readAgeIdentity(path string) ([]byte, error) {
	path = model.ExpandUserPath(path)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("Age identity must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("Age identity permissions are %04o; group/other access must be absent", info.Mode().Perm())
	}
	return pathguard.ReadFileLimited(path, MaxEncryptedDocumentBytes)
}

func ageIdentityRecipient(path string) (string, error) {
	data, err := readAgeIdentity(path)
	if err != nil {
		return "", err
	}
	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("parse Age identity: %w", err)
	}
	if len(identities) != 1 {
		return "", errors.New("Age identity must contain exactly one identity")
	}
	identity, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return "", errors.New("Age identity must contain an X25519 identity")
	}
	return identity.Recipient().String(), nil
}

// validatedAgeRecipient verifies that the operator-supplied identity is
// usable for this site and returns the identity-derived encryption recipient.
func validatedAgeRecipient(path, expectedRecipient string) (string, error) {
	recipient, err := ageIdentityRecipient(path)
	if err != nil {
		return "", err
	}
	if expectedRecipient == "" || recipient != expectedRecipient {
		return "", errors.New("Age identity recipient does not match site metadata")
	}
	return recipient, nil
}

// ValidateAgeIdentity verifies that the operator-supplied identity is usable
// for this site before a live lifecycle operation begins.
func ValidateAgeIdentity(path, expectedRecipient string) error {
	_, err := validatedAgeRecipient(path, expectedRecipient)
	return err
}

func createAgeIdentity(path string) (string, error) {
	path = model.ExpandUserPath(path)
	if path == "" {
		return "", errors.New("Age identity path is required")
	}
	if _, err := os.Lstat(path); err == nil {
		data, err := readAgeIdentity(path)
		if err != nil {
			return "", fmt.Errorf("read existing Age identity: %w", err)
		}
		identities, err := age.ParseIdentities(bytes.NewReader(data))
		if err != nil {
			return "", fmt.Errorf("parse existing Age identity: %w", err)
		}
		if len(identities) != 1 {
			return "", errors.New("existing Age identity must contain exactly one identity")
		}
		identity, ok := identities[0].(*age.X25519Identity)
		if !ok {
			return "", errors.New("existing Age identity must be an X25519 identity generated by Boetticher")
		}
		return identity.Recipient().String(), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generate Age identity: %w", err)
	}
	if err := atomicWrite(path, []byte(identity.String()+"\n"), 0600); err != nil {
		return "", fmt.Errorf("write Age identity: %w", err)
	}
	return identity.Recipient().String(), nil
}

var _ keyservice.KeyServiceClient = bundledAgeKeyService{}
