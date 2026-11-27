package agentlab

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Runner executes ssh with the given argv, environment, and stdio streams.
type Runner func(name string, args []string, env []string, stdin io.Reader, stdout, stderr io.Writer) error

// Options configures dependencies for Run.
type Options struct {
	HomeDir string
	Getenv  func(string) string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	RunSSH  Runner
}

// ExitError carries a remote process exit status code.
type ExitError struct {
	Code int
}

func (e ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

const usageText = `Usage:
  agent-lab [--config <path>] init
  agent-lab [--config <path>] status
  agent-lab [--config <path>] [--] <boetticher args...>

Options:
  --config <path>   Override config path (default: ~/.config/groundhog/agent-lab.yml or $AGENT_LAB_CONFIG)
  -h, --help        Show this help message
`

// Run executes the agent-lab CLI with the provided arguments and options.
func Run(args []string, opts Options) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if opts.RunSSH == nil {
		opts.RunSSH = defaultRunSSH
	}
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		opts.HomeDir = home
	}

	var flagConfig string
	sawDoubleDash := false
	i := 0
	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "--":
			sawDoubleDash = true
			i++
		case arg == "-h" || arg == "--help":
			_, err := io.WriteString(opts.Stdout, usageText)
			return err
		case arg == "--config":
			if i+1 >= len(args) {
				return errors.New("--config requires a path argument")
			}
			flagConfig = args[i+1]
			i += 2
			continue
		case strings.HasPrefix(arg, "--config="):
			flagConfig = strings.TrimPrefix(arg, "--config=")
			if strings.TrimSpace(flagConfig) == "" {
				return errors.New("--config requires a non-empty path argument")
			}
			i++
			continue
		}
		break
	}

	rest := args[i:]
	if len(rest) == 0 {
		_, _ = io.WriteString(opts.Stderr, usageText)
		return errors.New("missing command or boetticher arguments")
	}

	if !sawDoubleDash && rest[0] == "help" && len(rest) == 1 {
		_, err := io.WriteString(opts.Stdout, usageText)
		return err
	}

	cfgPath := ResolveConfigPath(flagConfig, opts.HomeDir, opts.Getenv)

	if !sawDoubleDash && rest[0] == "init" {
		if len(rest) > 1 {
			return fmt.Errorf("init accepts no extra arguments: %v", rest[1:])
		}
		identityPath := filepath.Join(opts.HomeDir, DefaultIdentityRel)
		if _, err := os.Stat(cfgPath); err == nil {
			cfg, loadErr := LoadConfig(cfgPath, opts.HomeDir)
			if loadErr != nil {
				return loadErr
			}
			identityPath = cfg.IdentityFile
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat config %s: %w", cfgPath, err)
		}
		return Init(identityPath, opts.Stdout)
	}

	remoteArgs := rest
	if !sawDoubleDash && len(rest) == 1 && rest[0] == "status" {
		remoteArgs = []string{"controller", "status"}
	}

	cfg, err := LoadConfig(cfgPath, opts.HomeDir)
	if err != nil {
		return err
	}
	if err := CheckSecurity(cfg); err != nil {
		return err
	}
	sshArgs, err := BuildSSHArgs(cfg, remoteArgs)
	if err != nil {
		return err
	}

	return opts.RunSSH("ssh", sshArgs, SanitizedEnv(os.Environ()), opts.Stdin, opts.Stdout, opts.Stderr)
}
