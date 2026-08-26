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
	case "network":
		return runNetwork(args[1:], out)
	case "verify":
		return runVerify(args[1:], out)
	case "doctor":
		return runDoctor(args[1:], out)
	case "bootstrap":
		return runBootstrap(args[1:], out)
	case "provision":
		return runProvision(args[1:], out)
	case "converge":
		return runConverge(args[1:], out)
	case "upgrade":
		return runIntegrationGate(args[0], args[1:], out)
	}
	fmt.Fprintln(errOut, "usage: boetticher <command>")
	return fmt.Errorf("unknown or incomplete command %q", strings.Join(args, " "))
}

func usage(out interface{ Write([]byte) (int, error) }) {
	fmt.Fprintln(out, "boetticher operator CLI\n\nUsage:")
	for _, spec := range commandSpecs {
		fmt.Fprintln(out, "  "+spec.Usage)
	}
}
