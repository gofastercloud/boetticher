package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func runHostReboot(args []string, out io.Writer) error {
	return runHostRebootWith(hostMaintenance, args, out)
}

// runHostRebootWith reboots only the enrolled Proxmox Host. With guests
// present it requires --with-guests and relies on Proxmox's native
// pve-guests ordered shutdown and onboot startup; Boetticher never stops or
// starts guests itself.
func runHostRebootWith(deps hostMaintenanceDeps, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("host reboot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	withGuests := fs.Bool("with-guests", false, "reboot with guests through Proxmox's ordered guest shutdown and startup")
	plan := fs.Bool("plan", false, "preview the reboot without changing the Host")
	yes := fs.Bool("yes", false, "confirm rebooting the enrolled Proxmox host")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *plan && *yes {
		return errors.New("usage: boetticher host reboot [--with-guests] --plan|--yes")
	}
	if !*plan && !*yes {
		return errors.New("host reboot requires --yes (or --plan to preview)")
	}
	if err := deps.ready(); err != nil {
		return err
	}
	release, err := deps.lock()
	if err != nil {
		return err
	}
	defer release()
	ctx := context.Background()
	config, runner, err := openEnrolledHost(ctx, deps, "reboot")
	if err != nil {
		return err
	}
	if err := requirePackageSystemIdle(ctx, runner); err != nil {
		return fmt.Errorf("Host reboot refused: %w", err)
	}
	guests, err := controllerhost.ReadGuests(ctx, runner)
	if err != nil {
		return fmt.Errorf("verify Proxmox guests before reboot: %w", err)
	}
	if len(guests) != 0 && !*withGuests {
		return fmt.Errorf("Host reboot requires an empty guest inventory; found %s. Use --with-guests to reboot through Proxmox's native ordered guest shutdown and startup", guestList(guests))
	}
	policies := make([]controllerhost.GuestBootPolicy, 0, len(guests))
	for _, guest := range guests {
		command, err := controllerhost.GuestConfigCommand(config.Proxmox.Node, guest)
		if err != nil {
			return err
		}
		output, err := runner.Run(ctx, command)
		if err != nil {
			return fmt.Errorf("read guest %d boot policy: %w", guest.VMID, err)
		}
		policy, err := controllerhost.ParseGuestBootPolicy(guest, output.Stdout)
		if err != nil {
			return err
		}
		policies = append(policies, policy)
	}
	controllerhost.SortByStartOrder(policies)
	fmt.Fprintf(out, "Proxmox Host reboot (%s)\n", config.Proxmox.Node)
	renderGuestBootPolicies(out, policies)
	if len(policies) > 0 {
		enabled, err := runner.Run(ctx, controllerhost.GuestsServiceCommand)
		if err != nil {
			return fmt.Errorf("read pve-guests.service state: %w", err)
		}
		if state := strings.TrimSpace(string(enabled.Stdout)); state != "enabled" {
			return fmt.Errorf("pve-guests.service is %q, so Proxmox would not shut down and start guests in order; the Host was not rebooted", state)
		}
		fmt.Fprintln(out, "  pve-guests.service enabled: guests stop in reverse start order and onboot guests start in order")
	}
	bootOutput, err := runner.Run(ctx, controllerhost.BootIDCommand)
	bootID := strings.TrimSpace(string(bootOutput.Stdout))
	if err != nil {
		return fmt.Errorf("read Host boot identity before reboot: %w", err)
	}
	if !validBootID(bootID) {
		return errors.New("read Host boot identity before reboot: unrecognised boot identity")
	}
	if *plan {
		fmt.Fprintf(out, "\nPlan only. The Host was not rebooted. A reboot waits up to %s for the Host to return and %s for guest startup.\n", deps.rebootReturnBudget, deps.guestStartBudget)
		return nil
	}
	requested := deps.now()
	if _, err := runner.Run(ctx, controllerhost.RebootCommand); err != nil {
		// The reply may be lost (SSH drop, hang killed by the timeout) even
		// though the reboot was scheduled. A new boot ID is the only proof
		// either way, so keep waiting; an unchanged one gives the failure.
		fmt.Fprintf(out, "\nProxmox reboot request returned an error (%v); waiting for a new Host boot to confirm.\n", err)
	} else {
		fmt.Fprintln(out, "\nProxmox reboot requested.")
	}

	returned, address, err := waitForHostReturn(ctx, deps, config, bootID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Host returned after %s via %s\n", deps.now().Sub(requested).Round(time.Second), address)
	if len(policies) == 0 {
		return reportManagementPath(ctx, deps, config, address, out)
	}
	// pve-guests finishing is not enough: /cluster/resources lags guest
	// state, so the comparison retries within the same startup budget.
	deadline := deps.now().Add(deps.guestStartBudget)
	startErr := waitForGuestStartup(ctx, deps, returned, deadline)
	var rows []string
	var failures int
	var readErr error
	for {
		after, err := controllerhost.ReadGuests(ctx, returned)
		readErr = err
		if err == nil {
			rows, failures = guestRecovery(policies, after)
		}
		if startErr != nil || (err == nil && failures == 0) || !deps.now().Before(deadline) {
			break
		}
		if err := deps.sleep(ctx, deps.pollInterval); err != nil {
			return err
		}
	}
	if rows == nil {
		return fmt.Errorf("read Proxmox guests after reboot: %w", readErr)
	}
	fmt.Fprintln(out, "\nGuests after reboot")
	fmt.Fprintf(out, "    %-5s %-24s %-8s %-8s %s\n", "VMID", "NAME", "BEFORE", "AFTER", "RESULT")
	for _, row := range rows {
		fmt.Fprintln(out, row)
	}
	pathErr := reportManagementPath(ctx, deps, config, address, out)
	if startErr != nil {
		return startErr
	}
	if failures > 0 {
		return fmt.Errorf("%d guest(s) that were running with onboot enabled are not running after the Host reboot", failures)
	}
	fmt.Fprintf(out, "\nHost reboot: PASS in %s\n", deps.now().Sub(requested).Round(time.Second))
	return pathErr
}

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validBootID(value string) bool { return bootIDPattern.MatchString(value) }

// hostPaths lists the normal connection first and the HOME fallback second.
// The fallback carries only read-only probes: while the firewall guest is
// still down after a reboot, the LAB path to the Host is unavailable.
func hostPaths(config controllerhost.LabConfig) []bool {
	if config.Proxmox.ConnectionAddress != "" && config.Proxmox.ConnectionAddress != config.Proxmox.Address {
		return []bool{false, true}
	}
	return []bool{false}
}

func waitForHostReturn(ctx context.Context, deps hostMaintenanceDeps, config controllerhost.LabConfig, previousBoot string) (controllerhost.Runner, string, error) {
	deadline := deps.now().Add(deps.rebootReturnBudget)
	last := errors.New("no observation yet")
	for {
		if err := deps.sleep(ctx, deps.pollInterval); err != nil {
			return nil, "", err
		}
		for _, home := range hostPaths(config) {
			runner, address, err := deps.runner(config, home, hostProbeTimeout)
			if err != nil {
				return nil, "", err
			}
			output, err := runner.Run(ctx, controllerhost.BootIDCommand)
			bootID := strings.TrimSpace(string(output.Stdout))
			switch {
			case err != nil:
				last = fmt.Errorf("%s: %w", address, err)
			case bootID == previousBoot:
				last = fmt.Errorf("%s: still running the previous boot", address)
			case !validBootID(bootID):
				last = fmt.Errorf("%s: unrecognised boot identity", address)
			default:
				return runner, address, nil
			}
		}
		if !deps.now().Before(deadline) {
			return nil, "", fmt.Errorf("Proxmox Host did not return within %s; last observation: %v", deps.rebootReturnBudget, last)
		}
	}
}

// waitForGuestStartup waits for pve-guests.service, which performs the
// native onboot startall, to finish.
func waitForGuestStartup(ctx context.Context, deps hostMaintenanceDeps, runner controllerhost.Runner, deadline time.Time) error {
	started := deps.now()
	state := "unknown"
	for {
		output, err := runner.Run(ctx, controllerhost.GuestsServiceActiveCmd)
		if err == nil {
			state = strings.TrimSpace(string(output.Stdout))
		}
		switch state {
		case "active":
			return nil
		case "failed":
			return errors.New("pve-guests.service failed during guest startup")
		}
		if !deps.now().Before(deadline) {
			return fmt.Errorf("guest startup did not finish within %s (pve-guests.service %s after %s)", deps.guestStartBudget, state, deps.now().Sub(started).Round(time.Second))
		}
		if err := deps.sleep(ctx, deps.pollInterval); err != nil {
			return err
		}
	}
}

func reportManagementPath(ctx context.Context, deps hostMaintenanceDeps, config controllerhost.LabConfig, answered string, out io.Writer) error {
	runner, address, err := deps.runner(config, false, hostProbeTimeout)
	if err != nil || address == answered {
		return err
	}
	if _, err := runner.Run(ctx, controllerhost.BootIDCommand); err != nil {
		fmt.Fprintf(out, "ATTENTION  Normal Host path %s is not answering yet: %v\n", address, err)
		return nil
	}
	fmt.Fprintf(out, "Normal Host path %s restored\n", address)
	return nil
}

func renderGuestBootPolicies(out io.Writer, policies []controllerhost.GuestBootPolicy) {
	if len(policies) == 0 {
		fmt.Fprintln(out, "  Guests: none")
		return
	}
	fmt.Fprintln(out, "  Guests in Proxmox start order (shutdown runs in reverse)")
	fmt.Fprintf(out, "    %-5s %-24s %-4s %-8s %-6s %-5s %-4s %-4s\n", "VMID", "NAME", "TYPE", "STATUS", "ONBOOT", "ORDER", "UP", "DOWN")
	for _, policy := range policies {
		fmt.Fprintf(out, "    %-5d %-24s %-4s %-8s %-6s %-5s %-4s %-4s\n", policy.VMID, policy.Name, policy.Type, policy.Status, map[bool]string{true: "yes", false: "no"}[policy.OnBoot], unsetDash(policy.Order), unsetDash(policy.Up), unsetDash(policy.Down))
	}
	for _, policy := range policies {
		switch {
		case policy.Status == "running" && !policy.OnBoot:
			fmt.Fprintf(out, "  WARNING  %d %s is running but onboot is disabled; it will NOT start after the reboot\n", policy.VMID, policy.Name)
		case policy.Status != "running" && policy.OnBoot:
			fmt.Fprintf(out, "  NOTE     %d %s is %s but onboot is enabled; it will start after the reboot\n", policy.VMID, policy.Name, policy.Status)
		}
	}
}

func unsetDash(value int) string {
	if value == 0 {
		return "-"
	}
	return fmt.Sprint(value)
}

func guestRecovery(policies []controllerhost.GuestBootPolicy, after []controllerhost.Guest) ([]string, int) {
	current := map[int]string{}
	for _, guest := range after {
		current[guest.VMID] = guest.Status
	}
	failures := 0
	rows := make([]string, 0, len(policies))
	for _, policy := range policies {
		status, ok := current[policy.VMID]
		if !ok {
			status = "missing"
		}
		var result string
		switch {
		case policy.Status == "running" && status == "running":
			result = "PASS  running again"
		case policy.Status == "running" && !policy.OnBoot:
			result = "ATTENTION  not started (onboot disabled); start it explicitly"
		case policy.Status == "running":
			result = "FAIL  was running, onboot enabled"
			failures++
		case status == "running":
			result = "PASS  started by onboot"
		case status == "missing":
			result = "FAIL  missing from inventory"
			failures++
		default:
			result = "PASS  remains " + status
		}
		rows = append(rows, fmt.Sprintf("    %-5d %-24s %-8s %-8s %s", policy.VMID, policy.Name, policy.Status, status, result))
	}
	return rows, failures
}
