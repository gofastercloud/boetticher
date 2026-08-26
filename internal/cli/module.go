package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runModule(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module list|show|plan|enable|disable|status")
	}
	switch args[0] {
	case "list":
		return runModuleList(args[1:], out)
	case "show":
		return runModuleShow(args[1:], out)
	case "plan":
		return runModulePlan(args[1:], out)
	case "enable":
		return runModuleChange(args[1:], out, true)
	case "disable":
		return runModuleChange(args[1:], out, false)
	case "status":
		return runModuleStatus(args[1:], out)
	default:
		return fmt.Errorf("unknown module command %q", args[0])
	}
}

func moduleSite(args []string, name string) (string, *flag.FlagSet, *bool, *bool, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	dryRun := fs.Bool("dry-run", false, "validate and display the plan without changing the site")
	confirm := fs.Bool("confirm", false, "confirm a site configuration mutation")
	returnValue := fs.Parse(args)
	if returnValue != nil {
		return "", nil, nil, nil, returnValue
	}
	return *siteDir, fs, dryRun, confirm, nil
}

func runModuleList(args []string, out interface{ Write([]byte) (int, error) }) error {
	siteDir, _, _, _, err := moduleSite(args, "module list")
	if err != nil {
		return err
	}
	s, err := site.Load(siteDir)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "NAME\tPOLICY\tENABLED\tREASON\tSTATE")
	for _, module := range s.Modules {
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n", module.Name, module.Policy, yesNo(module.Enabled), module.Reason, module.State)
	}
	return nil
}

func runModuleShow(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module show NAME [--site DIR]")
	}
	name := args[0]
	siteDir, _, _, _, err := moduleSite(args[1:], "module show")
	if err != nil {
		return err
	}
	s, err := site.Load(siteDir)
	if err != nil {
		return err
	}
	registry := modules.FirstPartyRegistry()
	definition, ok := registry.Definition(name)
	if !ok {
		return fmt.Errorf("unknown first-party module %q", name)
	}
	resolved, ok := findResolvedModule(s, name)
	if !ok {
		return fmt.Errorf("module %q is not resolved", name)
	}
	fmt.Fprintf(out, "Module %s\n  Description  %s\n  Version      %s\n  Policy       %s\n  Enabled      %s\n  Reason       %s\n  State        %s\n  Depends on   %s\n  Requires     %s\n  Provides     %s\n  Guest IDs    %s\n", definition.Name, definition.Description, definition.Version, definition.Policy, yesNo(resolved.Enabled), resolved.Reason, resolved.State, strings.Join(definition.DependsOn, ", "), strings.Join(capabilityNames(definition.Requires), ", "), strings.Join(capabilityNames(definition.Provides), ", "), ints(definition.GuestIDs))
	for _, declaration := range s.Declarations {
		if declaration.Module != name {
			continue
		}
		fmt.Fprintf(out, "  Artifact     %s %s (%s, sha256 %s)\n", declaration.Artifact.Name, declaration.Artifact.Version, declaration.Artifact.Kind, declaration.Artifact.SHA256)
		fmt.Fprintf(out, "  Guests       %s\n  Persistent   %s\n  Secrets      %s\n", guestNames(declaration.Guests), persistentNames(declaration.Persistent), secretNames(declaration.Secrets))
	}
	return nil
}

func runModulePlan(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module plan NAME [--site DIR]")
	}
	name := args[0]
	siteDir, _, _, _, err := moduleSite(args[1:], "module plan")
	if err != nil {
		return err
	}
	s, err := site.Load(siteDir)
	if err != nil {
		return err
	}
	if _, ok := modules.FirstPartyRegistry().Definition(name); !ok {
		return fmt.Errorf("unknown first-party module %q", name)
	}
	for _, module := range s.Modules {
		if module.Name == name {
			fmt.Fprintf(out, "Module %s\n  Enabled  %s\n  Reason   %s\n  State    %s\n", name, yesNo(module.Enabled), module.Reason, module.State)
		}
	}
	for _, declaration := range s.Declarations {
		if declaration.Module != name {
			continue
		}
		fmt.Fprintf(out, "Artifact\n  %s %s (%s)\nCreate/retain\n", declaration.Artifact.Name, declaration.Artifact.Version, declaration.Artifact.Kind)
		for _, guest := range declaration.Guests {
			fmt.Fprintf(out, "  guest %d %s\n", guest.VMID, guest.Name)
		}
		for _, persistent := range declaration.Persistent {
			fmt.Fprintf(out, "Persistent\n  retain %s at %s\n", persistent.Name, persistent.Path)
		}
	}
	if _, ok := findDeclaration(s, name); !ok {
		fmt.Fprintln(out, "No active resources")
	}
	return nil
}

func runModuleStatus(args []string, out interface{ Write([]byte) (int, error) }) error {
	name := ""
	remaining := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		remaining = args[1:]
	}
	siteDir, _, _, _, err := moduleSite(remaining, "module status")
	if err != nil {
		return err
	}
	s, err := site.Load(siteDir)
	if err != nil {
		return err
	}
	if name != "" {
		module, ok := findResolvedModule(s, name)
		if !ok {
			return fmt.Errorf("unknown module %q", name)
		}
		fmt.Fprintf(out, "%s: %s (%s, %s)\n", module.Name, module.State, yesNo(module.Enabled), module.Reason)
		return nil
	}
	return runModuleList(remaining, out)
}

func runModuleChange(args []string, out interface{ Write([]byte) (int, error) }, enable bool) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module enable|disable NAME [--site DIR] [--dry-run] [--confirm]")
	}
	name := args[0]
	remaining := args[1:]
	fs := flag.NewFlagSet("module change", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	dryRun := fs.Bool("dry-run", false, "validate and display the plan without changing the site")
	confirm := fs.Bool("confirm", false, "confirm a site configuration mutation")
	purge := fs.Bool("purge", false, "remove retained module resources; requires --confirm")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	config, err := site.LoadConfig(*siteDir)
	if err != nil {
		return err
	}
	definition, ok := modules.FirstPartyRegistry().Definition(name)
	if !ok {
		return fmt.Errorf("unknown first-party module %q", name)
	}
	if definition.Policy == modules.Mandatory && !enable {
		return fmt.Errorf("cannot disable %s: the module is mandatory", name)
	}
	if *purge && (!*confirm || enable) {
		return errors.New("--purge requires --confirm and is valid only when disabling a module")
	}
	if config.Modules == nil {
		config.Modules = map[string]model.ModuleConfig{}
	}
	value := enable
	config.Modules[name] = model.ModuleConfig{Enabled: &value}
	resolved, _, err := modules.Compose(config)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Module %s\n  Desired  %s\n", name, yesNo(enable))
	if *purge {
		fmt.Fprintln(out, "  Retained resources: none (purge requested and confirmed)")
	} else {
		fmt.Fprintln(out, "  Persistent resources: retained by default")
	}
	if *dryRun {
		fmt.Fprintln(out, "  Site mutation: NOT RUN (dry-run)")
		return nil
	}
	if !*confirm {
		return errors.New("module changes require --confirm; use --dry-run to inspect the plan")
	}
	if err := site.SaveConfig(*siteDir, model.ConfigFromSite(resolved)); err != nil {
		return err
	}
	fmt.Fprintf(out, "  Configuration: saved (model %s)\n", mustRevision(resolved))
	return nil
}

func findResolvedModule(s model.Site, name string) (model.ResolvedModule, bool) {
	for _, module := range s.Modules {
		if module.Name == name {
			return module, true
		}
	}
	return model.ResolvedModule{}, false
}

func findDeclaration(s model.Site, name string) (model.ModuleDeclaration, bool) {
	for _, declaration := range s.Declarations {
		if declaration.Module == name {
			return declaration, true
		}
	}
	return model.ModuleDeclaration{}, false
}

func capabilityNames(values []modules.Capability) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func ints(values []int) string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = fmt.Sprint(value)
	}
	return strings.Join(result, ", ")
}

func guestNames(values []model.Component) string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = fmt.Sprintf("%d:%s", value.VMID, value.Name)
	}
	return strings.Join(result, ", ")
}

func persistentNames(values []model.PersistentState) string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = value.Name
	}
	sort.Strings(result)
	return strings.Join(result, ", ")
}

func secretNames(values []model.SecretDeclaration) string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = value.Name + " (metadata only)"
	}
	return strings.Join(result, ", ")
}
