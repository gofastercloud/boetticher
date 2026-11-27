package agentlab

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// FormatRemoteCommand builds a safely quoted remote command prefixed with "boetticher".
func FormatRemoteCommand(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("no boetticher arguments provided")
	}

	parts := make([]string, 0, len(args)+1)
	parts = append(parts, "boetticher")
	for _, arg := range args {
		if strings.ContainsRune(arg, '\x00') {
			return "", errors.New("argument contains NUL byte")
		}
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " "), nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !isSafeUnquotedRune(r) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isSafeUnquotedRune(r rune) bool {
	if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
		return true
	}
	switch r {
	case '-', '_', '.', '/', ':', '=', '@', '+', ',':
		return true
	default:
		return false
	}
}

// BuildSSHArgs constructs the pinned, non-interactive ssh argv that never
// touches ~/.ssh/config or SSH agents/Secretive.
func BuildSSHArgs(cfg Config, remoteArgs []string) ([]string, error) {
	remoteCmd, err := FormatRemoteCommand(remoteArgs)
	if err != nil {
		return nil, err
	}

	return []string{
		"-F", "/dev/null",
		"-i", cfg.IdentityFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=" + cfg.KnownHostsFile,
		"-p", strconv.Itoa(cfg.Port),
		"--",
		cfg.User + "@" + cfg.Host,
		remoteCmd,
	}, nil
}

// SanitizedEnv returns a copy of environ with SSH_AUTH_SOCK removed so ssh
// cannot contact Secretive or any ambient ssh-agent.
func SanitizedEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func defaultRunSSH(name string, args []string, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return ExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("execute %s: %w", name, err)
	}
	return nil
}
