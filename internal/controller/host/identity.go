package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	SSHDirectory           = "/var/lib/boetticher/controller/ssh"
	PrivateKeyPath         = SSHDirectory + "/id_ed25519"
	PublicKeyPath          = SSHDirectory + "/id_ed25519.pub"
	KnownHostsPath         = SSHDirectory + "/known_hosts"
	LabConfigPath          = "/etc/boetticher/lab.yml"
	ClientServicesLockPath = "/var/lib/boetticher/controller/client-services.lock"
	ControllerKeyTag       = "boetticher-controller"
)

type CommandFunc func(context.Context, string, ...string) ([]byte, error)

func defaultCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// CreateIdentity creates the one persistent controller identity. Existing
// material is validated and never rotated implicitly.
func CreateIdentity(ctx context.Context, command CommandFunc) (string, bool, error) {
	if os.Geteuid() != 0 {
		return "", false, errors.New("host identity creation requires root; run it with sudo")
	}
	if command == nil {
		command = defaultCommand
	}
	if err := pathguard.ValidateNoSymlinkComponents(SSHDirectory); err != nil {
		return "", false, fmt.Errorf("validate controller SSH directory: %w", err)
	}
	if err := pathguard.MkdirAll(SSHDirectory, 0700); err != nil {
		return "", false, fmt.Errorf("create controller SSH directory: %w", err)
	}
	privateInfo, privateErr := os.Lstat(PrivateKeyPath)
	publicInfo, publicErr := os.Lstat(PublicKeyPath)
	if privateErr == nil {
		if publicErr != nil && !errors.Is(publicErr, os.ErrNotExist) {
			return "", false, fmt.Errorf("inspect controller public key: %w", publicErr)
		}
		if privateInfo.Mode()&os.ModeSymlink != 0 || !privateInfo.Mode().IsRegular() {
			return "", false, errors.New("controller SSH private key is not a regular file")
		}
		if errors.Is(publicErr, os.ErrNotExist) {
			private, readErr := os.ReadFile(PrivateKeyPath)
			if readErr != nil {
				return "", false, fmt.Errorf("read controller private key: %w", readErr)
			}
			signer, parseErr := ssh.ParsePrivateKey(private)
			if parseErr != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
				return "", false, errors.New("controller private key is not a valid Ed25519 identity")
			}
			publicKey := formatPublicKey(signer.PublicKey())
			if writeErr := pathguard.WriteFileWithParentMode(PublicKeyPath, []byte(publicKey+"\n"), 0644, 0700); writeErr != nil {
				return "", false, fmt.Errorf("restore controller public key cache: %w", writeErr)
			}
			_ = os.Chmod(PrivateKeyPath, 0600)
			return publicKey, false, nil
		}
		if privateInfo.Mode()&os.ModeSymlink != 0 || publicInfo.Mode()&os.ModeSymlink != 0 || !privateInfo.Mode().IsRegular() || !publicInfo.Mode().IsRegular() {
			return "", false, errors.New("controller SSH identity is not a regular file")
		}
		publicKey, err := validateIdentity(privateInfo, publicInfo)
		if err != nil {
			return "", false, err
		}
		_ = os.Chmod(PrivateKeyPath, 0600)
		_ = os.Chmod(PublicKeyPath, 0644)
		return publicKey, false, nil
	}
	if !errors.Is(privateErr, os.ErrNotExist) || !errors.Is(publicErr, os.ErrNotExist) {
		return "", false, fmt.Errorf("inspect controller SSH identity: private=%v public=%v", privateErr, publicErr)
	}
	if _, err := command(ctx, "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-C", ControllerKeyTag, "-N", "", "-f", PrivateKeyPath); err != nil {
		return "", false, fmt.Errorf("generate controller SSH identity: %w", err)
	}
	privateInfo, err := os.Lstat(PrivateKeyPath)
	if err != nil {
		return "", false, fmt.Errorf("inspect generated controller private key: %w", err)
	}
	publicInfo, err = os.Lstat(PublicKeyPath)
	if err != nil {
		return "", false, fmt.Errorf("inspect generated controller public key: %w", err)
	}
	publicKey, err := validateIdentity(privateInfo, publicInfo)
	if err != nil {
		return "", false, err
	}
	if err := os.Chmod(PrivateKeyPath, 0600); err != nil {
		return "", false, fmt.Errorf("protect controller private key: %w", err)
	}
	if err := os.Chmod(PublicKeyPath, 0644); err != nil {
		return "", false, fmt.Errorf("protect controller public key: %w", err)
	}
	return publicKey, true, nil
}

func PublicKey() (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("host public-key access requires root; run it with sudo")
	}
	if err := pathguard.ValidateNoSymlinkComponents(PrivateKeyPath); err != nil {
		return "", fmt.Errorf("validate controller SSH identity: %w", err)
	}
	private, err := os.ReadFile(PrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("read controller private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		return "", fmt.Errorf("parse controller private key: %w", err)
	}
	return formatPublicKey(signer.PublicKey()), nil
}

func validateIdentity(privateInfo, publicInfo os.FileInfo) (string, error) {
	if privateInfo.Mode()&os.ModeSymlink != 0 || publicInfo.Mode()&os.ModeSymlink != 0 || !privateInfo.Mode().IsRegular() || !publicInfo.Mode().IsRegular() {
		return "", errors.New("controller SSH identity is not a regular file")
	}
	private, err := os.ReadFile(PrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("read controller private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		return "", fmt.Errorf("parse controller private key: %w", err)
	}
	public, err := os.ReadFile(PublicKeyPath)
	if err != nil {
		return "", fmt.Errorf("read controller public key: %w", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(public)
	if err != nil || parsed.Type() != ssh.KeyAlgoED25519 {
		return "", errors.New("controller public key is not a valid Ed25519 key")
	}
	if string(parsed.Marshal()) != string(signer.PublicKey().Marshal()) {
		return "", errors.New("controller public key does not match the private key")
	}
	return formatPublicKey(parsed), nil
}

func formatPublicKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + ControllerKeyTag
}
