package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
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

// runModules is the registry-driven plural namespace for first-party module
// operations. The lifecycle implementation remains the established generic
// module path so module-specific commands cannot acquire a second deploy
// engine or different ownership semantics.
func runModules(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher modules list|MODULE show|plan|enable|disable|status|purge")
	}
	if args[0] == "list" {
		return runModuleList(args[1:], out)
	}
	if len(args) < 2 {
		return errors.New("usage: boetticher modules MODULE show|plan|enable|disable|status|purge")
	}
	name, command := args[0], args[1]
	forward := append([]string{name}, args[2:]...)
	switch command {
	case "show":
		return runModuleShow(forward, out)
	case "plan":
		return runModulePlan(forward, out)
	case "enable":
		return runModuleChange(forward, out, true)
	case "disable":
		return runModuleChange(forward, out, false)
	case "status":
		return runModuleStatus(forward, out)
	case "purge":
		return runModuleChange(append(forward, "--purge"), out, false)
	default:
		return fmt.Errorf("unknown module command %q", command)
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
	if name == "dns" {
		provider := s.ModuleConfig["dns"].Provider
		if provider == "" {
			provider = string(model.DNSProviderBlocky)
		}
		fmt.Fprintf(out, "  Provider     %s\n", provider)
	}
	fmt.Fprintf(out, "Module %s\n  Description  %s\n  Version      %s\n  Policy       %s\n  Enabled      %s\n  Reason       %s\n  State        %s\n  Depends on   %s\n  Requires     %s\n  Provides     %s\n  Guest IDs    %s\n", definition.Name, definition.Description, definition.Version, definition.Policy, yesNo(resolved.Enabled), resolved.Reason, resolved.State, strings.Join(definition.DependsOn, ", "), strings.Join(capabilityNames(definition.Requires), ", "), strings.Join(capabilityNames(definition.Provides), ", "), ints(definition.GuestIDs))
	for _, declaration := range s.Declarations {
		if declaration.Module != name {
			continue
		}
		fmt.Fprintf(out, "  Artifact     %s %s (%s, definition sha256 %s)\n", declaration.Artifact.Name, declaration.Artifact.Version, declaration.Artifact.Kind, declaration.Artifact.DefinitionSHA256)
		fmt.Fprintf(out, "  Guests       %s\n  Persistent   %s\n  Volumes      %s\n  Secrets      %s\n", guestNames(declaration.Guests), persistentNames(declaration.Persistent), volumeNames(declaration.Volumes), secretNames(declaration.Secrets))
	}
	return nil
}

func volumeNames(volumes []model.PersistentVolumeDeclaration) string {
	parts := make([]string, 0, len(volumes))
	for _, volume := range volumes {
		parts = append(parts, volume.Name+"@"+volume.MountPath+"/"+string(volume.Placement))
	}
	return strings.Join(parts, ", ")
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
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
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
	value := enable
	if err := config.Modules.Set(name, model.ModuleConfig{Enabled: &value}); err != nil {
		return err
	}
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
	oldSite, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if *purge {
		client, _, err := loadProxmoxClient(*siteDir, oldSite, *ageIdentity, *proxmoxCA, *insecure)
		if err != nil {
			return fmt.Errorf("load Proxmox client for module purge: %w", err)
		}
		purgeSite, err := modulePurgeSite(oldSite, name)
		if err != nil {
			return err
		}
		oldPlan, err := proxmox.PlanFromSite(purgeSite)
		if err != nil {
			return err
		}
		oldPlan, err = proxmox.ResolveQualifiedArtifacts(*siteDir, oldPlan, true)
		if err != nil {
			return fmt.Errorf("resolve qualified artifacts for module purge: %w", err)
		}
		node, err := client.SingleNode(context.Background())
		if err != nil {
			return fmt.Errorf("resolve live Proxmox node for module purge: %w", err)
		}
		oldPlan.Node = node
		if err := proxmox.PurgeModule(context.Background(), client, oldPlan, name); err != nil {
			return err
		}
	}
	retained := append([]model.RetainedModule(nil), oldSite.RetainedModules...)
	if enable || *purge {
		filtered := retained[:0]
		for _, item := range retained {
			if item.Module != name {
				filtered = append(filtered, item)
			}
		}
		retained = filtered
	} else if !*purge {
		if declaration, ok := findDeclaration(oldSite, name); ok {
			retained = append(retained, model.RetainedModule{Module: name, Disposition: "retained", Guests: declaration.Guests, Persistent: declaration.Persistent})
		}
	}
	if err := site.SaveConfig(*siteDir, model.ConfigFromSite(resolved)); err != nil {
		return err
	}
	if err := site.SaveRetainedModules(*siteDir, retained); err != nil {
		return err
	}
	fmt.Fprintf(out, "  Configuration: saved (model %s)\n", mustRevision(resolved))
	deployArgs := []string{"--site", *siteDir, "--age-identity", *ageIdentity}
	if *proxmoxCA != "" {
		deployArgs = append(deployArgs, "--proxmox-ca", *proxmoxCA)
	}
	if *insecure {
		deployArgs = append(deployArgs, "--insecure")
	}
	if *confirm || *purge {
		deployArgs = append(deployArgs, "--confirm")
	}
	if err := runDeploy(deployArgs, out); err != nil {
		return fmt.Errorf("deploy module change: %w", err)
	}
	return nil
}

// modulePurgeSite reconstructs the disabled module's declaration in memory so
// the generic Proxmox purge path can prove its exact guest, volume, and
// security identity. It never changes the persisted site configuration; the
// caller saves the already-disabled resolved configuration separately.
func modulePurgeSite(s model.Site, name string) (model.Site, error) {
	config := model.ConfigFromSite(s)
	enabled := true
	if err := config.Modules.Set(name, model.ModuleConfig{Enabled: &enabled}); err != nil {
		return model.Site{}, err
	}
	purgeSite, _, err := modules.Compose(config)
	if err != nil {
		return model.Site{}, fmt.Errorf("reconstruct module %s for purge: %w", name, err)
	}
	return purgeSite, nil
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
