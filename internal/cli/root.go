package cli

import (
	"fmt"
	"strings"
)

// Run dispatches the small, intentionally explicit operator command surface.
// Command implementations live in focused files; this file owns only the
// public entry point and top-level help.
func Run(args []string, out, errOut interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
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
	case "dns":
		return runDNS(args[1:], out)
	case "storage":
		return runStorage(args[1:], out)
	case "module":
		return runModule(args[1:], out)
	case "modules":
		return runModules(args[1:], out)
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
	case "logs":
		return runLogs(args[1:], out)
	case "aiops":
		return runAIOps(args[1:], out)
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
	pathParts := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			break
		}
		pathParts = append(pathParts, arg)
	}
	path := strings.Join(pathParts, " ")
	spec, ok := nestedHelpSpecs[path]
	if !ok {
		spec, ok = helpSpecs[path]
	}
	if !ok && len(pathParts) > 0 {
		spec, ok = helpSpecs[pathParts[0]]
	}
	if !ok {
		usage(out)
		return
	}
	fmt.Fprintf(out, "Purpose:\n  %s\n\nUsage:\n  %s\n\nArguments:\n  %s\n\nOptions:\n  %s\n\nSafety:\n  %s\n\nExamples:\n  %s\n\nRelated commands:\n  %s\n", spec.Purpose, spec.Usage, spec.Arguments, spec.Options, spec.Safety, spec.Examples, spec.Related)
}

func usage(out interface{ Write([]byte) (int, error) }) {
	fmt.Fprintln(out, "boetticher operator CLI\n\nUsage:")
	for _, spec := range commandSpecs {
		fmt.Fprintln(out, "  "+spec.Usage)
	}
}
