package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Run dispatches Boetticher's small, intentionally clear command menu.
// Command implementations live in focused files; this file owns the public
// entry point and the top-level help.
func Run(args []string, out, errOut io.Writer) error {
	return RunWithInput(args, os.Stdin, out, errOut)
}

// RunWithInput is the input-aware dispatcher used for hidden secret prompts.
// The input stream is never passed as a command argument.
func RunWithInput(args []string, input io.Reader, out, errOut io.Writer) error {
	return operatorErrorForHuman(run(args, input, out, errOut))
}

func run(args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		usage(out)
		return errors.New("a command is required; choose a Controller or Host command")
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		if len(args) > 1 && args[0] == "help" && args[1] == "--advanced" {
			advancedUsage(out)
		} else {
			usage(out)
		}
		return nil
	}
	if isLegacyLifecycleCommand(args[0]) {
		return legacyLifecycleDisabled(args[0])
	}
	if err := retiredCommandError(args); err != nil {
		return err
	}
	if helpRequested(args) {
		commandHelp(args, out)
		return nil
	}
	switch args[0] {
	case "controller":
		return runController(args[1:], out, errOut)
	case "host":
		return runHost(args[1:], input, out, errOut)
	case "ssh-config":
		return runSSHConfig(args[1:], out)
	case "access":
		return runAccess(args[1:], out)
	case "firewall":
		return runFirewall(args[1:], out)
	case "dhcp":
		return runDHCP(args[1:], out)
	case "dns":
		return runDNS(args[1:], out)
	case "module":
		return runModuleWithInput(args[1:], input, out, errOut)
	case "config":
		return runConfig(args[1:], out)
	case "hardware":
		return runHardware(args[1:], out)
	case "recover":
		return runRecovery(args[1:], out)
	case "logs":
		return runLogs(args[1:], out)
	case "aiops":
		return runAIOps(args[1:], out)
	}
	fmt.Fprintln(errOut, "usage: boetticher <command>")
	return fmt.Errorf("unknown or incomplete command %q", strings.Join(args, " "))
}

func legacyLifecycleDisabled(command string) error {
	return fmt.Errorf("boetticher %s is retired from the supported Controller/Host workflow", command)
}

func retiredCommandError(args []string) error {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "foundation":
		return errors.New("boetticher foundation is retired; use boetticher host apply, status, teardown, or reboot")
	case "storage":
		return errors.New("boetticher storage is retired; storage is Host configuration; use boetticher host apply, status, or plan-storage")
	case "network":
		return errors.New("boetticher network is retired; networking is Host configuration; use boetticher host apply, status, or test-ipv6")
	case "host":
		if len(args) < 2 {
			return nil
		}
		switch args[1] {
		case "identity":
			return errors.New("boetticher host identity is retired; use boetticher host create-identity or show-public-key")
		case "trust":
			return errors.New("boetticher host trust is retired; use boetticher host import-host-key")
		case "prepare":
			return errors.New("boetticher host prepare is retired; use boetticher host apply")
		}
	}
	return nil
}

func isLegacyLifecycleCommand(command string) bool {
	switch command {
	case "init", "enroll", "plan", "bundle", "deploy", "status", "update", "tui", "pki", "companion":
		return true
	default:
		return false
	}
}

func helpRequested(args []string) bool {
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func commandHelp(args []string, out io.Writer) {
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
		path = normalizedHelpPath(pathParts)
		spec, ok = nestedHelpSpecs[path]
	}
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
	fmt.Fprintf(out, "What it does:\n  %s\n\nUsage:\n  %s\n\nArguments:\n  %s\n\nOptions:\n  %s\n\nWorth knowing:\n  %s\n\nTry it:\n  %s\n\nRelated commands:\n  %s\n", spec.Purpose, spec.Usage, spec.Arguments, spec.Options, spec.Safety, spec.Examples, spec.Related)
}

func normalizedHelpPath(pathParts []string) string {
	if len(pathParts) < 2 {
		return ""
	}
	switch pathParts[0] {
	case "module", "host":
		return strings.Join(pathParts[:2], " ")
	}
	return ""
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "boetticher — your automated homelab helper\n\nStart here:")
	for _, spec := range commandSpecs {
		fmt.Fprintln(out, "  "+spec.Usage)
	}
}

func advancedUsage(out io.Writer) {
	fmt.Fprintln(out, "boetticher — the bigger toolbox\n\nCommand menu:")
	for _, spec := range advancedCommandSpecs {
		fmt.Fprintln(out, "  "+spec.Usage)
	}
}
