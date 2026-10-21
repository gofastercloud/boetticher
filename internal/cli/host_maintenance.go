package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

// hostMaintenanceDeps are the narrow seams for Host package upgrade and
// reboot. Production uses the strict Controller-to-Host SSH transport and the
// shared mutation lock; tests substitute fakes.
type hostMaintenanceDeps struct {
	ready      func() error
	lock       func() (func(), error)
	loadConfig func() (controllerhost.LabConfig, error)
	// runner returns the normal (LAB) path, or the HOME path when home is set.
	runner func(config controllerhost.LabConfig, home bool, timeout time.Duration) (controllerhost.Runner, string, error)
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	// runID returns a fresh lowercase-hex ID for one upgrade run.
	runID func() (string, error)

	pollInterval       time.Duration
	rebootReturnBudget time.Duration
	guestStartBudget   time.Duration
}

const (
	hostCommandTimeout = 30 * time.Second
	hostRefreshTimeout = 10 * time.Minute
	hostUpgradeTimeout = 60 * time.Minute
	hostProbeTimeout   = 20 * time.Second
)

var hostMaintenance = hostMaintenanceDeps{
	ready: requireControllerReady,
	lock: func() (func(), error) {
		lock, err := acquireClientServicesLock()
		if err != nil {
			return nil, err
		}
		return func() { _ = lock.Release() }, nil
	},
	loadConfig: controllerhost.LoadConfig,
	runner: func(config controllerhost.LabConfig, home bool, timeout time.Duration) (controllerhost.Runner, string, error) {
		transport, err := controllerhost.TransportFor(config)
		if home {
			transport, err = controllerhost.HomeTransportFor(config)
		}
		if err != nil {
			return nil, "", err
		}
		transport.Timeout = timeout
		return transport, transport.Address, nil
	},
	now: time.Now,
	runID: func() (string, error) {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			return "", err
		}
		return hex.EncodeToString(value), nil
	},
	sleep: func(ctx context.Context, duration time.Duration) error {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	},
	pollInterval:       10 * time.Second,
	rebootReturnBudget: 20 * time.Minute,
	guestStartBudget:   10 * time.Minute,
}

// openEnrolledHost is the common start of a Host maintenance command, run
// after the mutation lock is held.
func openEnrolledHost(ctx context.Context, deps hostMaintenanceDeps, operation string) (controllerhost.LabConfig, controllerhost.Runner, error) {
	config, err := deps.loadConfig()
	if err != nil {
		return controllerhost.LabConfig{}, nil, err
	}
	if config.Proxmox.Node == "" {
		return controllerhost.LabConfig{}, nil, fmt.Errorf("host enrollment is required before a Host %s", operation)
	}
	runner, _, err := deps.runner(config, false, hostCommandTimeout)
	if err != nil {
		return controllerhost.LabConfig{}, nil, err
	}
	nodes, err := controllerhost.ReadNodes(ctx, runner)
	if err != nil {
		return controllerhost.LabConfig{}, nil, fmt.Errorf("verify Proxmox before %s: %w", operation, err)
	}
	if len(nodes) != 1 || nodes[0].Node != config.Proxmox.Node {
		return controllerhost.LabConfig{}, nil, fmt.Errorf("Proxmox node identity mismatch: expected %s", config.Proxmox.Node)
	}
	return config, runner, nil
}

func runHostUpgrade(args []string, input io.Reader, out io.Writer) error {
	return runHostUpgradeWith(hostMaintenance, args, input, out)
}

func runHostUpgradeWith(deps hostMaintenanceDeps, args []string, input io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("host upgrade", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	plan := fs.Bool("plan", false, "refresh package indexes and preview the full upgrade")
	yes := fs.Bool("yes", false, "approve the full upgrade")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *plan && *yes {
		return errors.New("usage: boetticher host upgrade [--plan|--yes]")
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
	config, runner, err := openEnrolledHost(ctx, deps, "upgrade")
	if err != nil {
		return err
	}
	if err := requirePackageSystemIdle(ctx, runner); err != nil {
		return err
	}
	repositories, err := runner.Run(ctx, controllerhost.AptRepositoryCommand)
	if err != nil {
		return fmt.Errorf("read Host APT repositories: %w", err)
	}
	pveSources, err := controllerhost.CheckRepositoryPolicy(controllerhost.ParseAptRepositories(repositories.Stdout))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Proxmox Host upgrade (%s)\n", config.Proxmox.Node)
	for _, source := range pveSources {
		fmt.Fprintf(out, "  Repository        %s\n", source.Describe())
	}
	before, err := readRebootState(ctx, runner)
	if err != nil {
		return err
	}

	refreshRunner, _, err := deps.runner(config, false, hostRefreshTimeout)
	if err != nil {
		return err
	}
	refresh, err := refreshRunner.Run(ctx, controllerhost.AptRefreshCommand)
	if err != nil {
		return fmt.Errorf("refresh Host package indexes: %w%s", err, outputTail(refresh.Stdout))
	}
	if problems := controllerhost.RefreshProblems(refresh.Stdout); len(problems) > 0 {
		return fmt.Errorf("refresh Host package indexes reported problems; no packages were changed:\n  %s", strings.Join(problems, "\n  "))
	}
	fmt.Fprintln(out, "  Package indexes   refreshed")
	simulation, err := refreshRunner.Run(ctx, controllerhost.AptSimulateCommand)
	if err != nil {
		return fmt.Errorf("simulate Host full-upgrade: %w%s", err, outputTail(simulation.Stdout))
	}
	planned := controllerhost.ParseSimulatedUpgrade(simulation.Stdout)
	renderUpgradeChanges(out, planned, "Planned")
	if reasons := planned.RebootReasons(); len(reasons) > 0 {
		fmt.Fprintf(out, "  Reboot expected   yes (%s)\n", strings.Join(reasons, ", "))
	} else {
		fmt.Fprintln(out, "  Reboot expected   not predicted (confirmed after the upgrade)")
	}
	fmt.Fprintf(out, "  Reboot pending    %s\n", yesNoDetail(before.Required(), before.Reason()))
	protected := planned.ProtectedRemovals()
	if len(protected) > 0 {
		fmt.Fprintf(out, "\nRefused: the full-upgrade would remove %s. Check the Host repository configuration.\n", strings.Join(protected, ", "))
	}
	if *plan {
		fmt.Fprintln(out, "\nPlan only. Refreshing the package indexes was the only change; no packages were installed, upgraded, or removed.")
		if len(protected) > 0 {
			return fmt.Errorf("host upgrade plan refused: the full-upgrade would remove %s", strings.Join(protected, ", "))
		}
		return nil
	}
	if planned.Count() == 0 {
		fmt.Fprintln(out, "\nNo changes required.")
		return nil
	}
	if len(protected) > 0 {
		return fmt.Errorf("host upgrade refused: it would remove %s; no packages were changed", strings.Join(protected, ", "))
	}
	if !*yes {
		if input == nil {
			return errors.New("host upgrade requires --yes or an interactive confirmation")
		}
		answer, err := promptYesNo(input, out, fmt.Sprintf("\nApply %d package changes to the Proxmox Host? [y/N]: ", planned.Count()), false)
		if err != nil || !answer {
			return errors.New("host upgrade cancelled; no packages were changed")
		}
	}
	if err := requirePackageSystemIdle(ctx, runner); err != nil {
		return err
	}
	snapshot, err := runner.Run(ctx, controllerhost.PackageSnapshotCmd)
	if err != nil {
		return fmt.Errorf("read installed packages before upgrade: %w", err)
	}
	installedBefore := controllerhost.ParsePackageSnapshot(snapshot.Stdout)
	upgradeRunner, _, err := deps.runner(config, false, hostUpgradeTimeout)
	if err != nil {
		return err
	}
	runID, err := deps.runID()
	if err != nil {
		return fmt.Errorf("generate upgrade run ID: %w", err)
	}
	command, err := controllerhost.AptUpgradeCommand(runID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nUpgrading Proxmox Host packages (noninteractive full-upgrade, existing configuration files kept; run %s)...\n", runID)
	started := deps.now()
	if _, err := upgradeRunner.Run(ctx, command); err != nil {
		return describeUpgradeFailure(ctx, runner, err, runID)
	}
	elapsed := deps.now().Sub(started).Round(time.Second)
	snapshot, err = runner.Run(ctx, controllerhost.PackageSnapshotCmd)
	if err != nil {
		return fmt.Errorf("Host full-upgrade completed in %s but installed packages could not be read: %w", elapsed, err)
	}
	changed := controllerhost.DiffPackages(installedBefore, controllerhost.ParsePackageSnapshot(snapshot.Stdout))
	fmt.Fprintf(out, "\nHost upgrade: PASS in %s\n", elapsed)
	renderUpgradeChanges(out, changed, "Changed")
	after, err := readRebootState(ctx, runner)
	if err != nil {
		return err
	}
	after.Changed = changed.RebootReasons()
	fmt.Fprintf(out, "  Reboot required   %s\n", yesNoDetail(after.Required(), after.Reason()))
	if after.Required() {
		fmt.Fprintln(out, "\nThe Host was not rebooted. Review and reboot explicitly:\n  sudo boetticher host reboot --with-guests --plan\n  sudo boetticher host reboot --with-guests --yes")
	}
	return nil
}

func requirePackageSystemIdle(ctx context.Context, runner controllerhost.Runner) error {
	output, err := runner.Run(ctx, controllerhost.UpgradeBusyCommand)
	if err != nil {
		return fmt.Errorf("read Host package system state: %w", err)
	}
	return controllerhost.CheckPackageSystemIdle(output.Stdout)
}

var upgradeCheckHint = "Check on the Host: systemctl status " + controllerhost.UpgradeUnit + "; grep " + controllerhost.UpgradeResultMarker + " " + controllerhost.UpgradeLog + ". The Host was not rebooted"

// describeUpgradeFailure reports the upgrade unit's live state after the
// Controller's wait failed, so an SSH drop or timeout is not mistaken for a
// failed (or finished) upgrade.
func describeUpgradeFailure(ctx context.Context, runner controllerhost.Runner, runErr error, runID string) error {
	if text := runErr.Error(); strings.Contains(text, "already loaded") || strings.Contains(text, "already exists") {
		return fmt.Errorf("Host full-upgrade did not start: a %s unit already exists from another run: %w. %s", controllerhost.UpgradeUnit, runErr, upgradeCheckHint)
	}
	output, err := runner.Run(ctx, controllerhost.UpgradeOutcomeCommand)
	if err != nil {
		return fmt.Errorf("Host full-upgrade outcome is unknown: the Controller wait ended (%v) and the unit state could not be read (%v). %s", runErr, err, upgradeCheckHint)
	}
	unit := "unknown"
	for _, line := range strings.Split(string(output.Stdout), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "BOETTICHER_UPGRADE_UNIT="); ok {
			unit = value
		}
	}
	result := controllerhost.UpgradeResult(output.Stdout, runID)
	tail := outputTail(output.Stdout)
	switch {
	case unit == "active" || unit == "activating":
		return fmt.Errorf("Host full-upgrade is still running: the Controller wait ended (%v) but %s.service is %s. Wait for it, then rerun `boetticher host upgrade --plan`. %s", runErr, controllerhost.UpgradeUnit, unit, upgradeCheckHint)
	case result == "success":
		return fmt.Errorf("Host full-upgrade finished on the Host, but the Controller lost its result (%v); changed packages were not reported. Rerun `boetticher host upgrade --plan` and `boetticher host status`. %s", runErr, upgradeCheckHint)
	case result == "failed":
		return fmt.Errorf("Host full-upgrade failed: %w%s\n%s", runErr, tail, upgradeCheckHint)
	}
	return fmt.Errorf("Host full-upgrade outcome is unknown: %w (%s.service is %s, no result marker for run %s in the log; any earlier log content belongs to a previous run)%s\n%s", runErr, controllerhost.UpgradeUnit, unit, runID, tail, upgradeCheckHint)
}

func readRebootState(ctx context.Context, runner controllerhost.Runner) (controllerhost.RebootState, error) {
	output, err := runner.Run(ctx, controllerhost.RebootStateCommand)
	if err != nil {
		return controllerhost.RebootState{}, fmt.Errorf("read Host reboot state: %w", err)
	}
	return controllerhost.ParseRebootState(output.Stdout)
}

func renderUpgradeChanges(out io.Writer, plan controllerhost.UpgradePlan, label string) {
	fmt.Fprintf(out, "  %-17s %d packages (%d upgraded, %d new, %d removed)\n", label, plan.Count(), len(plan.Upgrades), len(plan.Installs), len(plan.Removals))
	var proxmox, kernel []string
	for _, change := range append(append(append([]controllerhost.PackageChange{}, plan.Upgrades...), plan.Installs...), plan.Removals...) {
		switch {
		case controllerhost.IsKernelPackage(change.Name):
			kernel = append(kernel, change.Name)
		case controllerhost.IsProxmoxPackage(change.Name):
			proxmox = append(proxmox, change.Name)
		}
	}
	fmt.Fprintf(out, "  Proxmox packages  %s\n", listOrNone(proxmox))
	fmt.Fprintf(out, "  Kernel packages   %s\n", listOrNone(kernel))
	if plan.Count() == 0 {
		return
	}
	fmt.Fprintln(out, "\n  Packages")
	for _, change := range plan.Upgrades {
		fmt.Fprintf(out, "    upgrade  %-40s %s -> %s\n", change.Name, change.From, change.To)
	}
	for _, change := range plan.Installs {
		fmt.Fprintf(out, "    install  %-40s %s\n", change.Name, change.To)
	}
	for _, change := range plan.Removals {
		fmt.Fprintf(out, "    remove   %-40s %s\n", change.Name, change.From)
	}
	fmt.Fprintln(out)
}

func listOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func yesNoDetail(value bool, detail string) string {
	if value {
		return "yes (" + detail + ")"
	}
	return "no (" + detail + ")"
}

func outputTail(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return ""
	}
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return "\n  " + strings.Join(lines, "\n  ")
}
