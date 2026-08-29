package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
)

func runSSHConfig(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("ssh-config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", sshconfig.DefaultPath(), "output path, or - for stdout")
	force := fs.Bool("force", false, "overwrite an existing output")
	check := fs.Bool("check", false, "validate an existing configuration")
	identity := fs.String("identity-file", "", "operator SSH identity file")
	installInclude := fs.Bool("install-include", false, "explicitly add the config.d include to ~/.ssh/config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if *identity != "" {
		s.SSHIdentityFile = *identity
	}
	if *check {
		if err := sshconfig.Check(*output, s); err != nil {
			return err
		}
		fmt.Fprintln(out, "SSH configuration: PASS current and model-consistent")
		return nil
	}
	content, err := sshconfig.RenderWithKnownHosts(s, time.Now(), filepath.Join(*siteDir, "generated", "ssh", "known_hosts"))
	if err != nil {
		return err
	}
	if *output == "-" {
		_, err = out.Write([]byte(content))
	} else {
		err = sshconfig.Write(*output, []byte(content), *force)
		if err == nil {
			fmt.Fprintf(out, "Generated SSH configuration: %s\n", model.ExpandUserPath(*output))
		}
	}
	if err != nil {
		return err
	}
	if *installInclude {
		if *output == "-" {
			return fmt.Errorf("--install-include requires a file output")
		}
		if err := installSSHInclude(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Installed explicit ~/.ssh/config include")
	}
	if *output != "-" {
		if err := writeAccessProjection(*siteDir, s); err != nil {
			return err
		}
	}
	return nil
}

func runSSHJourney(configPath string) error {
	if err := sshconfig.ValidateExecutionConfig(configPath); err != nil {
		return fmt.Errorf("validate SSH journey configuration: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh", "-F", model.ExpandUserPath(configPath), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "dns01", "true")
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("authenticated SSH journey timed out")
		}
		return fmt.Errorf("authenticated SSH journey failed: %w", err)
	}
	return nil
}

func jumpDestinations(s model.Site) []string {
	result := []string{}
	for _, m := range s.PlatformComponents() {
		if m.ProductOwned && m.SSHManaged && m.JumpAllowed {
			port := m.SSHPort
			if port == 0 {
				port = 22
			}
			result = append(result, fmt.Sprintf("%s:%d", m.Address, port))
			if m.Name == "lab-monitor-01" {
				result = append(result, fmt.Sprintf("%s:443", m.Address))
			}
		}
	}
	sort.Strings(result)
	return result
}

func defaultOperatorPublicKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"} {
		path := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func readOperatorPublicKey(path string) (string, error) {
	if path == "" {
		return "", errors.New("operator SSH public key is required; use --operator-key PATH")
	}
	data, err := os.ReadFile(model.ExpandUserPath(path))
	if err != nil {
		return "", fmt.Errorf("read operator SSH public key: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func installSSHInclude() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".ssh", "config")
	include := "Include ~/.ssh/config.d/*"
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data = nil
	} else if err != nil {
		return err
	}
	if strings.Contains(string(data), include) {
		return nil
	}
	data = append(data, []byte("\n"+include+"\n")...)
	return sshconfig.Write(path, data, true)
}
