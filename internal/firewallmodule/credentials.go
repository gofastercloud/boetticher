package firewallmodule

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// PasswordHash delegates crypt-format generation to the platform's OpenSSL
// implementation. The credential is streamed on stdin and never appears in
// process arguments, logs, or an intermediate file.
func PasswordHash(ctx context.Context, credential string) (string, error) {
	if credential == "" || strings.ContainsAny(credential, "\r\n") {
		return "", errors.New("provider credential is empty or malformed")
	}
	command := exec.CommandContext(ctx, "openssl", "passwd", "-6", "-stdin")
	command.Stdin = strings.NewReader(credential + "\n")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("generate provider password hash: %w", err)
	}
	hash := strings.TrimSpace(output.String())
	if hash == "" || !strings.HasPrefix(hash, "$6$") || strings.ContainsAny(hash, "\r\n") {
		return "", errors.New("provider password hash output is malformed")
	}
	return hash, nil
}
