package agentlab

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Init ensures the dedicated Ed25519 key exists with 0600 permissions and
// prints the public key plus the exact Pi Controller enable command.
func Init(identityPath string, stdout io.Writer) error {
	dir := filepath.Dir(identityPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create key directory %s: %w", dir, err)
	}

	info, err := os.Stat(identityPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		var outBuf bytes.Buffer
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", DefaultUser, "-f", identityPath)
		cmd.Stdout = &outBuf
		cmd.Stderr = &outBuf
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("generate ed25519 key with ssh-keygen: %w (%s)", err, strings.TrimSpace(outBuf.String()))
		}
		if err := os.Chmod(identityPath, 0o600); err != nil {
			return fmt.Errorf("set 0600 permissions on %s: %w", identityPath, err)
		}
	case err != nil:
		return fmt.Errorf("stat identity key %s: %w", identityPath, err)
	default:
		if !info.Mode().IsRegular() {
			return fmt.Errorf("identity_file %s must be a regular file", identityPath)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return fmt.Errorf("existing identity_file %s has permissive mode %04o (must not grant group/other permissions)", identityPath, mode)
		}
	}

	pubKey, err := readOrDerivePublicKey(identityPath)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "Identity key: %s\nPublic key:\n%s\n\nRun on the Pi Controller to authorise this key:\nboetticher controller agent-access enable --key '%s' --yes\n",
		identityPath, pubKey, pubKey)
	return err
}

func readOrDerivePublicKey(identityPath string) (string, error) {
	pubPath := identityPath + ".pub"
	data, err := os.ReadFile(pubPath)
	if errors.Is(err, os.ErrNotExist) {
		var outBuf, errBuf bytes.Buffer
		cmd := exec.Command("ssh-keygen", "-y", "-f", identityPath)
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if runErr := cmd.Run(); runErr != nil {
			return "", fmt.Errorf("derive public key from %s: %w (%s)", identityPath, runErr, strings.TrimSpace(errBuf.String()))
		}
		data = outBuf.Bytes()
		if writeErr := os.WriteFile(pubPath, data, 0o644); writeErr != nil {
			return "", fmt.Errorf("write public key %s: %w", pubPath, writeErr)
		}
	} else if err != nil {
		return "", fmt.Errorf("read public key %s: %w", pubPath, err)
	}

	pubKey := strings.TrimSpace(string(data))
	if pubKey == "" || strings.ContainsAny(pubKey, "\r\n'") {
		return "", fmt.Errorf("invalid public key content in %s", pubPath)
	}
	return pubKey, nil
}
