package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runModuleWithInput(args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module list|configure|enable|disable|secrets")
	}
	switch args[0] {
	case "list":
		return runModuleList(args[1:], out)
	case "configure":
		return runModuleConfigure(args[1:], input, out, errOut)
	case "enable":
		return runModuleChangeWithInput(args[1:], input, out, errOut, true)
	case "disable":
		return runModuleChangeWithInput(args[1:], input, out, errOut, false)
	case "secrets":
		return runModuleSecrets(args[1:], input, out, errOut)
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

func runModuleList(args []string, out io.Writer) error {
	siteDir, _, _, _, err := moduleSite(args, "module list")
	if err != nil {
		return err
	}
	return runModuleListRequest(siteDir, out)
}

func runModuleListRequest(siteDir string, out io.Writer) error {
	if siteDir == "" {
		siteDir = "."
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

func runModuleChange(args []string, out io.Writer, enable bool) error {
	return runModuleChangeWithInput(args, os.Stdin, out, os.Stderr, enable)
}

func runModuleChangeWithInput(args []string, input io.Reader, out, errOut io.Writer, enable bool) error {
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
		if enable {
			if err := ensureModuleSecrets(*siteDir, resolved, config, name, *ageIdentity, input, out, errOut, true); err != nil {
				return err
			}
		}
		fmt.Fprintln(out, "  Site mutation: not applied (dry-run)")
		return nil
	}
	if !*confirm {
		return errors.New("module changes require --confirm; use --dry-run to inspect the plan")
	}
	if enable {
		if err := ensureModuleSecrets(*siteDir, resolved, config, name, *ageIdentity, input, out, errOut, *dryRun); err != nil {
			return err
		}
	}
	oldSite, err := site.Load(*siteDir)
	if err != nil {
		return err
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
	} else {
		if declaration, ok := findDeclaration(oldSite, name); ok {
			retained = append(retained, model.RetainedModule{Module: name, Disposition: "retained", Guests: declaration.Guests, Persistent: declaration.Persistent})
		}
	}
	var purgeIntent *site.PurgeIntent
	if *purge {
		purgeSite, err := modulePurgeSite(oldSite, name)
		if err != nil {
			return err
		}
		declaration, ok := findDeclaration(purgeSite, name)
		if !ok {
			return fmt.Errorf("module %s purge declaration is missing", name)
		}
		if err := site.ValidateModuleSecretOwnership(purgeSite, name, declaration); err != nil {
			return err
		}
		oldPlan, err := proxmox.PlanFromSite(purgeSite)
		if err != nil {
			return err
		}
		intent := purgeIntentForPlan(oldPlan, name)
		if existing, found, intentErr := site.LoadPurgeIntent(*siteDir); intentErr != nil {
			return intentErr
		} else if found {
			if existing.Module != name || !purgeIntentMatches(existing, intent) {
				return errors.New("the persisted purge intent does not match the current module plan; inspect it before retrying")
			}
		}
		purgeIntent = &intent
	}
	if err := site.ApplyModuleState(*siteDir, model.ConfigFromSite(resolved), retained, purgeIntent); err != nil {
		return err
	}
	fmt.Fprintf(out, "  Configuration: saved (model %s)\n", mustRevision(resolved))
	if *purge {
		fmt.Fprintf(out, "  Purge: pending deployment for %d exact owned guest(s); run deploy --confirm to apply\n", len(purgeIntent.Guests))
	} else {
		fmt.Fprintln(out, "  Deployment: pending (module changes never deploy implicitly)")
	}
	return nil
}

func purgeIntentForPlan(plan proxmox.Plan, module string) site.PurgeIntent {
	intent := site.PurgeIntent{Module: module, ModelRevision: plan.ModelRevision, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	owner := "boetticher/module/" + module
	for _, guest := range plan.Guests {
		if guest.Owner != owner {
			continue
		}
		intent.Guests = append(intent.Guests, site.PurgeGuest{VMID: guest.VMID, Name: guest.Name, Kind: string(guest.Kind), Owner: guest.Owner})
	}
	site.SortPurgeGuests(intent.Guests)
	return intent
}

func findResolvedModule(s model.Site, name string) (model.ResolvedModule, bool) {
	for _, module := range s.Modules {
		if module.Name == name {
			return module, true
		}
	}
	return model.ResolvedModule{}, false
}

func purgeIntentMatches(existing, current site.PurgeIntent) bool {
	if existing.ModelRevision != current.ModelRevision || len(existing.Guests) != len(current.Guests) {
		return false
	}
	existingGuests := append([]site.PurgeGuest(nil), existing.Guests...)
	currentGuests := append([]site.PurgeGuest(nil), current.Guests...)
	site.SortPurgeGuests(existingGuests)
	site.SortPurgeGuests(currentGuests)
	for index := range existingGuests {
		if existingGuests[index] != currentGuests[index] {
			return false
		}
	}
	return true
}

type pendingModulePurge struct {
	intent    site.PurgeIntent
	purgeSite model.Site
	plan      proxmox.Plan
}

// loadPendingModulePurge validates the controller-local destructive operation
// against the currently requested module definition. It is deliberately
// usable without a Proxmox connection: planning a purge must be safe offline,
// while the live ownership proof remains in proxmox.PurgeModule.
func loadPendingModulePurge(siteDir string, s model.Site) (*pendingModulePurge, bool, error) {
	intent, found, err := site.LoadPurgeIntent(siteDir)
	if err != nil || !found {
		return nil, found, err
	}
	purgeSite, err := modulePurgeSite(s, intent.Module)
	if err != nil {
		return nil, true, err
	}
	declaration, ok := findDeclaration(purgeSite, intent.Module)
	if !ok {
		return nil, true, fmt.Errorf("module %s purge declaration is missing", intent.Module)
	}
	if err := site.ValidateModuleSecretOwnership(purgeSite, intent.Module, declaration); err != nil {
		return nil, true, err
	}
	plan, err := proxmox.PlanFromSite(purgeSite)
	if err != nil {
		return nil, true, err
	}
	if !purgeIntentMatches(intent, purgeIntentForPlan(plan, intent.Module)) {
		return nil, true, errors.New("the persisted purge intent does not match the current module plan; inspect it before retrying")
	}
	return &pendingModulePurge{intent: intent, purgeSite: purgeSite, plan: plan}, true, nil
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

func findDeclaration(s model.Site, name string) (model.ModuleDeclaration, bool) {
	for _, declaration := range s.Declarations {
		if declaration.Module == name {
			return declaration, true
		}
	}
	return model.ModuleDeclaration{}, false
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func guestNames(values []model.Component) string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = fmt.Sprintf("%d:%s", value.VMID, value.Name)
	}
	return strings.Join(result, ", ")
}
