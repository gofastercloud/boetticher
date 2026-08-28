package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

const maxOperatorSecretBytes = 64 * 1024

func runModuleSecrets(args []string, input io.Reader, out, errOut interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module secrets MODULE list|set|remove")
	}
	return runModuleSecretsForName(args[1:], input, out, errOut, args[0])
}

func runModuleSecretsForName(args []string, input io.Reader, out, errOut interface{ Write([]byte) (int, error) }, name string) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher modules MODULE secrets list|set|remove")
	}
	switch args[0] {
	case "list":
		return runModuleSecretList(name, args[1:], out)
	case "set":
		return runModuleSecretSet(name, args[1:], input, out, errOut)
	case "remove":
		return runModuleSecretRemove(name, args[1:], out)
	default:
		return fmt.Errorf("unknown module secrets command %q", args[0])
	}
}

type moduleSecretFlags struct {
	siteDir     string
	ageIdentity string
	confirm     bool
}

func parseModuleSecretFlags(args []string, command string) (moduleSecretFlags, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	result := moduleSecretFlags{}
	fs.StringVar(&result.siteDir, "site", ".", "private site repository directory")
	fs.StringVar(&result.ageIdentity, "age-identity", model.DefaultAgeIdentity, "external Age identity path")
	fs.BoolVar(&result.confirm, "confirm", false, "confirm a secret removal")
	if err := fs.Parse(args); err != nil {
		return moduleSecretFlags{}, err
	}
	return result, nil
}

func loadModuleSecretContract(flags moduleSecretFlags, name string) (model.Site, model.SiteConfig, []model.SecretDeclaration, error) {
	config, err := site.LoadConfig(flags.siteDir)
	if err != nil {
		return model.Site{}, model.SiteConfig{}, nil, err
	}
	resolved, err := site.Load(flags.siteDir)
	if err != nil {
		return model.Site{}, model.SiteConfig{}, nil, err
	}
	declarations, err := modules.SecretDeclarations(config, name)
	if err != nil {
		return model.Site{}, model.SiteConfig{}, nil, err
	}
	return resolved, config, declarations, nil
}

func runModuleSecretList(name string, args []string, out interface{ Write([]byte) (int, error) }) error {
	flags, err := parseModuleSecretFlags(args, "module secrets list")
	if err != nil {
		return err
	}
	s, _, declarations, err := loadModuleSecretContract(flags, name)
	if err != nil {
		return err
	}
	keys := secretNamesOnly(declarations)
	presence, err := site.PlatformSecretPresence(flags.siteDir, s, flags.ageIdentity, keys)
	if err != nil {
		return fmt.Errorf("inspect encrypted platform secrets: %w", err)
	}
	fmt.Fprintf(out, "Module %s secrets\nNAME\tLIFECYCLE\tMANAGEMENT\tSTATUS\n", name)
	for _, declaration := range declarations {
		management := declaration.Generation
		status := "missing"
		if presence[declaration.Name] {
			status = "present"
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", declaration.Name, lifecycleName(declaration), management, status)
	}
	return nil
}

func runModuleSecretSet(name string, args []string, input io.Reader, out, errOut interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: boetticher modules MODULE secrets set NAME [--site DIR] [--age-identity PATH]")
	}
	key := args[0]
	flags, err := parseModuleSecretFlags(args[1:], "module secrets set")
	if err != nil {
		return err
	}
	s, _, declarations, err := loadModuleSecretContract(flags, name)
	if err != nil {
		return err
	}
	declaration, ok := findSecretDeclaration(declarations, key)
	if !ok {
		return fmt.Errorf("secret %q is not declared by module %s", key, name)
	}
	if declaration.Generation != "operator-supplied" {
		return fmt.Errorf("secret %q is managed by Core and cannot be set by the operator", key)
	}
	value, err := readOperatorSecret(input, errOut, key)
	if err != nil {
		return err
	}
	if err := site.UpdatePlatformSecrets(flags.siteDir, s, flags.ageIdentity, map[string]string{key: value}); err != nil {
		return fmt.Errorf("store encrypted platform secret %s: %w", key, err)
	}
	fmt.Fprintf(out, "%s: stored\n", key)
	return nil
}

func runModuleSecretRemove(name string, args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: boetticher modules MODULE secrets remove NAME --confirm [--site DIR] [--age-identity PATH]")
	}
	key := args[0]
	flags, err := parseModuleSecretFlags(args[1:], "module secrets remove")
	if err != nil {
		return err
	}
	if !flags.confirm {
		return errors.New("secret removal requires --confirm")
	}
	s, config, declarations, err := loadModuleSecretContract(flags, name)
	if err != nil {
		return err
	}
	declaration, ok := findSecretDeclaration(declarations, key)
	if !ok {
		return fmt.Errorf("secret %q is not declared by module %s", key, name)
	}
	if declaration.Generation != "operator-supplied" {
		return fmt.Errorf("secret %q is managed by Core and cannot be removed by the operator", key)
	}
	all, err := modules.AllSecretDeclarations(config)
	if err != nil {
		return err
	}
	for _, other := range all {
		if other.Module == name {
			continue
		}
		if _, shared := findSecretDeclaration(other.Secrets, key); shared {
			return fmt.Errorf("HOLD: refusing to remove secret %q because module %s also declares it", key, other.Module)
		}
	}
	changed, err := site.RemovePlatformSecrets(flags.siteDir, s, flags.ageIdentity, []string{key})
	if err != nil {
		return fmt.Errorf("remove encrypted platform secret %s: %w", key, err)
	}
	if changed {
		fmt.Fprintf(out, "%s: removed\n", key)
	} else {
		fmt.Fprintf(out, "%s: already absent\n", key)
	}
	return nil
}

func readOperatorSecret(input io.Reader, errOut interface{ Write([]byte) (int, error) }, name string) (string, error) {
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprintf(errOut, "Provide secret %s: ", name)
		value, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(errOut)
		if err != nil {
			return "", fmt.Errorf("read secret %s: %w", name, err)
		}
		return validateOperatorSecret(value, name)
	}
	if input == nil {
		return "", errors.New("secret input is required")
	}
	limited := io.LimitReader(input, maxOperatorSecretBytes+1)
	value, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("read secret %s: %w", name, err)
	}
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	return validateOperatorSecret(value, name)
}

func validateOperatorSecret(value []byte, name string) (string, error) {
	if len(value) == 0 {
		return "", fmt.Errorf("secret %s cannot be empty", name)
	}
	if len(value) > maxOperatorSecretBytes {
		return "", fmt.Errorf("secret %s exceeds the %d-byte limit", name, maxOperatorSecretBytes)
	}
	if !utf8.Valid(value) {
		return "", fmt.Errorf("secret %s is not valid UTF-8", name)
	}
	if strings.IndexByte(string(value), 0) >= 0 {
		return "", fmt.Errorf("secret %s contains an invalid NUL byte", name)
	}
	return string(value), nil
}

func secretNamesOnly(declarations []model.SecretDeclaration) []string {
	keys := make([]string, 0, len(declarations))
	for _, declaration := range declarations {
		keys = append(keys, declaration.Name)
	}
	sort.Strings(keys)
	return keys
}

func findSecretDeclaration(declarations []model.SecretDeclaration, name string) (model.SecretDeclaration, bool) {
	for _, declaration := range declarations {
		if declaration.Name == name {
			return declaration, true
		}
	}
	return model.SecretDeclaration{}, false
}

func lifecycleName(declaration model.SecretDeclaration) string {
	if declaration.Lifecycle == "" {
		return model.SecretLifecycleRuntime
	}
	return declaration.Lifecycle
}

// ensureModuleSecrets prepares missing operator-supplied values before an
// enable mutation. Dry-runs only report the gap; confirmed interactive runs
// collect all values before performing one encrypted document update.
func ensureModuleSecrets(siteDir string, s model.Site, config model.SiteConfig, module, ageIdentity string, input io.Reader, out, errOut interface{ Write([]byte) (int, error) }, dryRun bool) error {
	declarations, err := modules.SecretDeclarations(config, module)
	if err != nil {
		return err
	}
	operator := make([]model.SecretDeclaration, 0, len(declarations))
	for _, declaration := range declarations {
		if declaration.Generation == "operator-supplied" {
			operator = append(operator, declaration)
		}
	}
	if len(operator) == 0 {
		return nil
	}
	keys := secretNamesOnly(operator)
	presence, err := site.PlatformSecretPresence(siteDir, s, ageIdentity, keys)
	if err != nil {
		return fmt.Errorf("inspect encrypted platform secrets: %w", err)
	}
	missing := make([]model.SecretDeclaration, 0, len(operator))
	for _, declaration := range operator {
		if !presence[declaration.Name] {
			missing = append(missing, declaration)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if dryRun {
		fmt.Fprintf(out, "  Secrets: missing %s\n", strings.Join(secretNamesOnly(missing), ", "))
		return nil
	}
	file, interactive := input.(*os.File)
	if !interactive || !term.IsTerminal(int(file.Fd())) {
		commands := make([]string, 0, len(missing))
		for _, declaration := range missing {
			commands = append(commands, "boetticher modules "+module+" secrets set "+declaration.Name)
		}
		return fmt.Errorf("HOLD: module %s is missing operator secret(s) %s; run %s", module, strings.Join(secretNamesOnly(missing), ", "), strings.Join(commands, " and "))
	}
	updates := make(map[string]string, len(missing))
	for _, declaration := range missing {
		value, readErr := readOperatorSecret(input, errOut, declaration.Name)
		if readErr != nil {
			return readErr
		}
		updates[declaration.Name] = value
	}
	if err := site.UpdatePlatformSecrets(siteDir, s, ageIdentity, updates); err != nil {
		return fmt.Errorf("store encrypted module %s secrets: %w", module, err)
	}
	fmt.Fprintf(out, "  Secrets: stored %s\n", strings.Join(secretNamesOnly(missing), ", "))
	return nil
}
