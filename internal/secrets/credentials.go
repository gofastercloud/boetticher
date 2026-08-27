package secrets

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var credentialName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// CredentialSpec is metadata for one systemd service credential. It contains
// no secret value. The encrypted store is persistent target state while the
// credential is exposed only through the consuming unit's runtime directory.
type CredentialSpec struct {
	Name       string
	Unit       string
	StorePath  string
	RuntimeRef string
}

func Validate(specs []CredentialSpec) error {
	seen := map[string]string{}
	for _, spec := range specs {
		if !credentialName.MatchString(spec.Name) {
			return fmt.Errorf("credential %q has an unsafe name", spec.Name)
		}
		if spec.Unit == "" || strings.ContainsAny(spec.Unit, "\r\n ") {
			return fmt.Errorf("credential %s has an invalid consuming unit", spec.Name)
		}
		cleanPath := filepath.Clean(spec.StorePath)
		if spec.StorePath == "" || cleanPath != spec.StorePath || !strings.HasPrefix(cleanPath, "/var/lib/boetticher/credentials/") {
			return fmt.Errorf("credential %s must use the protected boetticher credential store", spec.Name)
		}
		if previous, ok := seen[spec.Name]; ok && previous != spec.Unit {
			return fmt.Errorf("credential %s is requested by both %s and %s", spec.Name, previous, spec.Unit)
		}
		seen[spec.Name] = spec.Unit
	}
	return nil
}

func UnitDropIn(specs []CredentialSpec) (string, error) {
	if err := Validate(specs); err != nil {
		return "", err
	}
	units, err := UnitDropIns(specs)
	if err != nil {
		return "", err
	}
	if len(units) != 1 {
		return "", fmt.Errorf("UnitDropIn requires credentials for exactly one unit")
	}
	for _, content := range units {
		return content, nil
	}
	return "", nil
}

// UnitDropIns renders one valid systemd service drop-in per consuming unit.
// Credentials are deliberately not combined into a single cross-unit file.
func UnitDropIns(specs []CredentialSpec) (map[string]string, error) {
	if err := Validate(specs); err != nil {
		return nil, err
	}
	sorted := append([]CredentialSpec(nil), specs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Unit == sorted[j].Unit {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Unit < sorted[j].Unit
	})
	result := map[string]string{}
	for _, spec := range sorted {
		result[spec.Unit] += fmt.Sprintf("[Service]\nLoadCredentialEncrypted=%s:%s\n", spec.Name, spec.StorePath)
	}
	return result, nil
}

// InstallCommand returns an argv-safe systemd-creds invocation for the
// temporary root deployment transport. The plaintext value is supplied on
// stdin by the caller and never appears in argv.
func InstallCommand(spec CredentialSpec) ([]string, error) {
	if err := Validate([]CredentialSpec{spec}); err != nil {
		return nil, err
	}
	return []string{"systemd-creds", "encrypt", "--name=" + spec.Name, "/dev/stdin", spec.StorePath}, nil
}

// StdinRunner is the narrow transport needed for secret installation.
type StdinRunner interface {
	RunWithStdin(context.Context, string, string, string, io.Reader) ([]byte, error)
}

// InstallCredential encrypts one required value on the target using
// systemd-creds. The value is streamed over SSH stdin and is never included
// in argv, generated configuration, or the returned output.
func InstallCredential(ctx context.Context, runner StdinRunner, address, user string, spec CredentialSpec, value []byte) error {
	if runner == nil {
		return fmt.Errorf("credential runner is required")
	}
	if len(value) == 0 {
		return fmt.Errorf("credential %s has an empty value", spec.Name)
	}
	if err := Validate([]CredentialSpec{spec}); err != nil {
		return err
	}
	command, err := InstallCommand(spec)
	if err != nil {
		return err
	}
	_, err = runner.RunWithStdin(ctx, address, user, strings.Join(shellQuoteArgs(command), " "), bytes.NewReader(value))
	if err != nil {
		return fmt.Errorf("install encrypted credential %s: %w", spec.Name, err)
	}
	return nil
}

func shellQuoteArgs(args []string) []string {
	quoted := make([]string, len(args))
	for i, value := range args {
		quoted[i] = "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return quoted
}
