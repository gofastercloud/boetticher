// Package agentbroker implements the server-side forced-command policy engine,
// strict SSH_ORIGINAL_COMMAND parser, direct execve runner, and JSON audit
// logger for boetticher-agent-broker.
package agentbroker

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// MaxCommandBytes is the maximum permitted length of SSH_ORIGINAL_COMMAND.
	MaxCommandBytes = 4096
	// MaxArgs is the maximum permitted number of whitespace-separated tokens.
	MaxArgs = 64
)

const forbiddenMetaChars = ";|&$`()<>\\'\"*?[]{}~!#"

// ParseCommand strictly validates and tokenises SSH_ORIGINAL_COMMAND.
// It rejects empty input, oversized commands, NUL/control characters,
// non-ASCII characters, shell metacharacters, path traversal segments, and
// commands that do not begin with the literal "boetticher" prefix.
func ParseCommand(raw string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty command")
	}
	if len(raw) > MaxCommandBytes {
		return nil, fmt.Errorf("command exceeds maximum length of %d bytes", MaxCommandBytes)
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b == 0 {
			return nil, errors.New("command contains NUL byte")
		}
		if b < 0x20 || b >= 0x7f {
			return nil, fmt.Errorf("command contains forbidden character 0x%02x", b)
		}
		if strings.IndexByte(forbiddenMetaChars, b) >= 0 {
			return nil, fmt.Errorf("command contains forbidden shell metacharacter %q", b)
		}
	}

	argv := strings.Fields(raw)
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	if len(argv) > MaxArgs {
		return nil, fmt.Errorf("command exceeds maximum argument count of %d", MaxArgs)
	}
	if argv[0] != "boetticher" {
		return nil, fmt.Errorf("command must start with literal boetticher, got %q", argv[0])
	}
	for _, arg := range argv[1:] {
		if strings.Contains(arg, "..") {
			return nil, fmt.Errorf("argument %q contains forbidden path traversal", arg)
		}
	}
	return argv, nil
}
