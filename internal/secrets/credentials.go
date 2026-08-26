package secrets

import (
	"fmt"
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
		if spec.StorePath == "" || !strings.HasPrefix(spec.StorePath, "/var/lib/boetticher/credentials/") {
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
	sorted := append([]CredentialSpec(nil), specs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Unit == sorted[j].Unit {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Unit < sorted[j].Unit
	})
	var b strings.Builder
	current := ""
	for _, spec := range sorted {
		if spec.Unit != current {
			if current != "" {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "[%s]\n", spec.Unit)
			current = spec.Unit
		}
		fmt.Fprintf(&b, "LoadCredentialEncrypted=%s:%s\n", spec.Name, spec.StorePath)
	}
	return b.String(), nil
}

// InstallCommand returns an argv-safe systemd-creds invocation. The plaintext
// value is supplied on stdin by the caller and never appears in argv.
func InstallCommand(spec CredentialSpec) ([]string, error) {
	if err := Validate([]CredentialSpec{spec}); err != nil {
		return nil, err
	}
	return []string{"systemd-creds", "encrypt", "--name=" + spec.Name, "/dev/stdin", spec.StorePath}, nil
}
