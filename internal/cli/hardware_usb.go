package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

var usbPhysicalPort = regexp.MustCompile(`^[0-9]+-[0-9]+(?:\.[0-9]+)*$`)

func runHardware(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) < 2 || args[0] != "usb" {
		return fmt.Errorf("usage: boetticher hardware usb list|status|bind|unbind")
	}
	command, rest := args[1], args[2:]
	var positional []string
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	fs := flag.NewFlagSet("hardware usb", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	live := fs.Bool("live", false, "inspect Proxmox USB devices")
	confirm := fs.Bool("confirm", false, "confirm desired-state change and deploy")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "allow self-signed Proxmox API TLS")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if command == "list" {
		for _, definition := range modules.FirstPartyRegistry().Definitions() {
			for _, requirement := range definition.USBRequirements {
				fmt.Fprintf(out, "%s/%s guest=%s required=%t allowed=%s\n", definition.Name, requirement.Name, requirement.Guest, requirement.Required, usbAllowed(requirement))
			}
		}
		if *live {
			observed, err := observeUSB(context.Background(), s, *siteDir)
			if err != nil {
				return err
			}
			fmt.Fprint(out, observed)
		}
		return nil
	}
	if command == "status" {
		if len(positional) != 0 && len(positional) != 2 {
			return fmt.Errorf("status accepts either no filter or MODULE REQUIREMENT")
		}
		bindings := append([]model.USBExportBinding(nil), s.USBExports...)
		sort.Slice(bindings, func(i, j int) bool {
			return bindings[i].Module+bindings[i].Requirement < bindings[j].Module+bindings[j].Requirement
		})
		for _, binding := range bindings {
			if len(positional) == 0 || binding.Module == positional[0] && binding.Requirement == positional[1] {
				fmt.Fprintf(out, "%s/%s port=%s identity=%s:%s serial=%s status=CONFIGURED\n", binding.Module, binding.Requirement, binding.Port, binding.VendorID, binding.ProductID, valueOrUnknown(binding.Serial))
			}
		}
		if *live {
			observed, err := observeUSB(context.Background(), s, *siteDir)
			if err != nil {
				return err
			}
			fmt.Fprint(out, observed)
		}
		return nil
	}
	if command != "bind" && command != "unbind" {
		return fmt.Errorf("unknown hardware usb command %q", command)
	}
	want := 3
	if command == "unbind" {
		want = 2
	}
	if len(positional) != want {
		return fmt.Errorf("%s requires MODULE REQUIREMENT%s", command, map[bool]string{true: " PORT", false: ""}[command == "bind"])
	}
	if !*confirm {
		return fmt.Errorf("hardware usb %s changes desired state and invokes deploy; repeat with --confirm", command)
	}
	module, requirement := positional[0], positional[1]
	_, req, ok := findUSBRequirement(s, module, requirement)
	if !ok {
		return fmt.Errorf("%s/%s is not a compiled-in USB requirement", module, requirement)
	}
	if command == "unbind" {
		if modules.IsEnabled(s, module) && req.Required {
			return fmt.Errorf("cannot unbind required %s/%s while the module is enabled", module, requirement)
		}
		filtered := s.USBExports[:0]
		for _, binding := range s.USBExports {
			if binding.Module != module || binding.Requirement != requirement {
				filtered = append(filtered, binding)
			}
		}
		s.USBExports = filtered
	} else {
		port := positional[2]
		if !usbPhysicalPort.MatchString(port) {
			return fmt.Errorf("invalid physical USB port %q", port)
		}
		identity, err := observeUSBPort(context.Background(), s, *siteDir, port)
		if err != nil {
			return err
		}
		allowed := false
		for _, candidate := range req.AllowedIdentities {
			if candidate.VendorID+":"+candidate.ProductID == identity[0]+":"+identity[1] {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("observed USB identity %s:%s is not allowed for %s/%s", identity[0], identity[1], module, requirement)
		}
		for _, binding := range s.USBExports {
			if binding.Port == port && (binding.Module != module || binding.Requirement != requirement) {
				return fmt.Errorf("physical USB port %s is already bound", port)
			}
		}
		filtered := s.USBExports[:0]
		for _, binding := range s.USBExports {
			if binding.Module != module || binding.Requirement != requirement {
				filtered = append(filtered, binding)
			}
		}
		s.USBExports = append(filtered, model.USBExportBinding{Module: module, Requirement: requirement, Port: port, VendorID: identity[0], ProductID: identity[1], Serial: identity[2]})
	}
	composed, _, err := modules.Compose(model.ConfigFromSite(s))
	if err != nil {
		return err
	}
	if err := site.Save(*siteDir, composed); err != nil {
		return err
	}
	deployArgs := []string{"--site", *siteDir, "--age-identity", *ageIdentity, "--confirm"}
	if *proxmoxCA != "" {
		deployArgs = append(deployArgs, "--proxmox-ca", *proxmoxCA)
	}
	if *insecure {
		deployArgs = append(deployArgs, "--insecure")
	}
	return runDeploy(deployArgs, out)
}

func findUSBRequirement(s model.Site, module, name string) (model.ModuleDeclaration, model.USBRequirement, bool) {
	for _, d := range s.Declarations {
		if d.Module == module {
			for _, r := range d.USBRequirements {
				if r.Name == name {
					return d, r, true
				}
			}
		}
	}
	definition, ok := modules.FirstPartyRegistry().Definition(module)
	if ok {
		for _, r := range definition.USBRequirements {
			if r.Name == name {
				return model.ModuleDeclaration{Module: module}, r, true
			}
		}
	}
	return model.ModuleDeclaration{}, model.USBRequirement{}, false
}
func usbAllowed(r model.USBRequirement) string {
	values := make([]string, len(r.AllowedIdentities))
	for i, v := range r.AllowedIdentities {
		values[i] = v.VendorID + ":" + v.ProductID
	}
	return strings.Join(values, ",")
}

func observeUSB(ctx context.Context, s model.Site, siteDir string) (string, error) {
	runner := proxmoxRootSSHRunner(s, siteDir)
	output, err := runner.Run(ctx, s.BootstrapAddress, "root", `set -eu; for d in /sys/bus/usb/devices/*-*; do test -f "$d/idVendor" || continue; test "$(cat "$d/uevent" | sed -n 's/^DEVTYPE=//p')" = usb_device || continue; printf '%s %s:%s %s\n' "$(basename "$d")" "$(cat "$d/idVendor")" "$(cat "$d/idProduct")" "$(cat "$d/serial" 2>/dev/null || true)"; done`)
	return string(output), err
}
func observeUSBPort(ctx context.Context, s model.Site, siteDir, port string) ([3]string, error) {
	var zero [3]string
	runner := proxmoxRootSSHRunner(s, siteDir)
	output, err := runner.Run(ctx, s.BootstrapAddress, "root", fmt.Sprintf(`set -eu; d=/sys/bus/usb/devices/%s; test -f "$d/idVendor"; test "$(sed -n 's/^DEVTYPE=//p' "$d/uevent")" = usb_device; cat "$d/idVendor"; cat "$d/idProduct"; cat "$d/serial" 2>/dev/null || true`, port))
	if err != nil {
		return zero, err
	}
	fields := strings.SplitN(strings.TrimSuffix(string(output), "\n"), "\n", 3)
	if len(fields) < 2 || strings.TrimSpace(fields[0]) == "" || strings.TrimSpace(fields[1]) == "" {
		return zero, fmt.Errorf("incomplete USB identity at %s", port)
	}
	zero[0], zero[1] = strings.ToLower(strings.TrimSpace(fields[0])), strings.ToLower(strings.TrimSpace(fields[1]))
	if len(fields) > 2 {
		zero[2] = strings.TrimSpace(fields[2])
	}
	return zero, nil
}
