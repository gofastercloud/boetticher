package cli

import (
	"fmt"
	"strings"
)

// Run dispatches the small, intentionally explicit operator command surface.
// Command implementations live in focused files; this file owns only the
// public entry point and top-level help.
func Run(args []string, out, errOut interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		usage(out)
		return nil
	}
	if helpRequested(args) {
		commandHelp(args, out)
		return nil
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], out)
	case "preflight":
		return runPreflight(args[1:], out)
	case "ssh-config":
		return runSSHConfig(args[1:], out)
	case "access":
		return runAccess(args[1:], out)
	case "portal":
		if len(args) > 1 && args[1] == "build" {
			return runPortalBuild(args[2:], out)
		}
	case "bootstrap-endpoint":
		return runBootstrapEndpoint(args[1:], out)
	case "pki":
		return runPKI(args[1:], out)
	case "firewall":
		return runFirewall(args[1:], out)
	case "dhcp":
		return runDHCP(args[1:], out)
	case "storage":
		return runStorage(args[1:], out)
	case "module":
		return runModule(args[1:], out)
	case "config":
		return runConfig(args[1:], out)
	case "network":
		return runNetwork(args[1:], out)
	case "verify":
		return runVerify(args[1:], out)
	case "doctor":
		return runDoctor(args[1:], out)
	case "bootstrap":
		return runBootstrap(args[1:], out)
	case "deploy":
		return runDeploy(args[1:], out)
	case "upgrade":
		return runIntegrationGate(args[0], args[1:], out)
	}
	fmt.Fprintln(errOut, "usage: boetticher <command>")
	return fmt.Errorf("unknown or incomplete command %q", strings.Join(args, " "))
}

func helpRequested(args []string) bool {
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func commandHelp(args []string, out interface{ Write([]byte) (int, error) }) {
	command := args[0]
	for _, spec := range commandSpecs {
		if strings.HasPrefix(spec.Usage, "boetticher "+command+" ") {
			fmt.Fprintf(out, "Usage:\n  %s\n\n", spec.Usage)
			break
		}
	}
	switch command {
	case "deploy":
		fmt.Fprintln(out, "Deploy the resolved boetticher platform model through the single deployment engine.")
		fmt.Fprintln(out, "Safety: without --dry-run this can create or replace boetticher-owned resources.")
		fmt.Fprintln(out, "Example: boetticher deploy --site ./my-boetticher --dry-run")
	case "module":
		fmt.Fprintln(out, "Inspect and change first-party module enablement; modules emit declarations and core performs mutation.")
		fmt.Fprintln(out, "Examples: boetticher module list; boetticher module plan monitoring")
	case "config":
		fmt.Fprintln(out, "Validate or inspect typed, non-secret SiteConfig without mutating infrastructure.")
		fmt.Fprintln(out, "Examples: boetticher config validate; boetticher config schema")
	default:
		fmt.Fprintf(out, "Run boetticher %s with --help for command options.\n", command)
	}
}

func usage(out interface{ Write([]byte) (int, error) }) {
	fmt.Fprintln(out, "boetticher operator CLI\n\nUsage:")
	for _, spec := range commandSpecs {
		fmt.Fprintln(out, "  "+spec.Usage)
	}
}
