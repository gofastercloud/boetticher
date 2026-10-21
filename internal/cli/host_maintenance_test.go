package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

const (
	testBootBefore = "11111111-1111-1111-1111-111111111111"
	testBootAfter  = "22222222-2222-2222-2222-222222222222"
	testNodes      = `[{"node":"lab-proxmox-01","status":"online","type":"node"}]`
	testSources    = "BOETTICHER_SOURCE_FILE=/etc/apt/sources.list.d/boetticher-pve-no-subscription.sources\nTypes: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-no-subscription\n\nBOETTICHER_SUBSCRIPTION=notfound\n"
	testSimulation = "Inst pve-manager [9.2.21] (9.2.22 Proxmox:9.2/stable [all])\nInst proxmox-kernel-7.0.15-1-pve-signed (7.0.15-1 Proxmox:9.2/stable [amd64])\nInst curl [8.14-1] (8.14-2 Debian:13.2/stable [amd64])\n"
)

// fakeHost is a scripted Host reachable over the LAB and HOME paths. Every
// command is recorded with the path that carried it.
type fakeHost struct {
	commands  []string
	handle    func(path, command string) (controllerhost.Result, error)
	labDown   bool
	upgraded  bool
	rebooted  bool
	clock     time.Time
	lockCalls int
	// busy is the UpgradeBusyCommand output; empty means idle.
	busy string
	// upgradeErr, when set, is the systemd-run result; outcome is then the
	// UpgradeOutcomeCommand output (an error when outcomeErr is set).
	upgradeErr error
	outcome    string
	outcomeErr error
	// rebootErr is returned by the reboot request; rebootIgnored keeps the
	// previous boot (the request never took effect).
	rebootErr     error
	rebootExit    int
	rebootIgnored bool
	// guestLag is how many post-reboot listings still show 280 stopped.
	guestLag int
}

const testRunID = "0123456789abcdef0123456789abcdef"

var testUpgradeCommand = func() string {
	command, err := controllerhost.AptUpgradeCommand(testRunID)
	if err != nil {
		panic(err)
	}
	return command
}()

const idlePackages = "BOETTICHER_UPGRADE_UNIT=inactive\nBOETTICHER_DPKG_LOCK=free\n"

func (h *fakeHost) busyOutput() (controllerhost.Result, error) {
	if h.busy == "" {
		return controllerhost.Result{Stdout: []byte(idlePackages)}, nil
	}
	return controllerhost.Result{Stdout: []byte(h.busy)}, nil
}

type fakeHostPath struct {
	host *fakeHost
	path string
}

func (p fakeHostPath) Run(_ context.Context, command string) (controllerhost.Result, error) {
	p.host.commands = append(p.host.commands, p.path+": "+command)
	return p.host.handle(p.path, command)
}

func (h *fakeHost) count(fragment string) int {
	total := 0
	for _, command := range h.commands {
		if strings.Contains(command, fragment) {
			total++
		}
	}
	return total
}

func (h *fakeHost) deps() hostMaintenanceDeps {
	h.clock = time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	return hostMaintenanceDeps{
		ready: func() error { return nil },
		lock: func() (func(), error) {
			h.lockCalls++
			return func() {}, nil
		},
		loadConfig: func() (controllerhost.LabConfig, error) {
			return controllerhost.LabConfig{Proxmox: controllerhost.ProxmoxConfig{Address: "192.168.4.5", ConnectionAddress: "10.10.99.5", User: "root", Node: "lab-proxmox-01"}}, nil
		},
		runner: func(_ controllerhost.LabConfig, home bool, _ time.Duration) (controllerhost.Runner, string, error) {
			if home {
				return fakeHostPath{h, "home"}, "192.168.4.5", nil
			}
			return fakeHostPath{h, "lab"}, "10.10.99.5", nil
		},
		now:   func() time.Time { return h.clock },
		runID: func() (string, error) { return testRunID, nil },
		sleep: func(_ context.Context, duration time.Duration) error {
			h.clock = h.clock.Add(duration)
			return nil
		},
		pollInterval:       10 * time.Second,
		rebootReturnBudget: 20 * time.Minute,
		guestStartBudget:   10 * time.Minute,
	}
}

func upgradeHost(sources, simulation string) *fakeHost {
	host := &fakeHost{}
	host.handle = func(_ string, command string) (controllerhost.Result, error) {
		out := func(text string) (controllerhost.Result, error) {
			return controllerhost.Result{Stdout: []byte(text)}, nil
		}
		switch command {
		case "pvesh get /nodes --output-format json":
			return out(testNodes)
		case controllerhost.AptRepositoryCommand:
			return out(sources)
		case controllerhost.RebootStateCommand:
			if host.upgraded {
				return out("BOETTICHER_RUNNING_KERNEL=7.0.14-16-pve\nBOETTICHER_PINNED_KERNEL=\nBOETTICHER_NEWEST_KERNEL=7.0.15-1-pve\nBOETTICHER_REBOOT_REQUIRED=0\n")
			}
			return out("BOETTICHER_RUNNING_KERNEL=7.0.14-16-pve\nBOETTICHER_PINNED_KERNEL=\nBOETTICHER_NEWEST_KERNEL=7.0.14-16-pve\nBOETTICHER_REBOOT_REQUIRED=0\n")
		case controllerhost.AptRefreshCommand:
			return out("Hit:1 http://download.proxmox.com/debian/pve trixie InRelease\nReading package lists...\n")
		case controllerhost.AptSimulateCommand:
			return out(simulation)
		case controllerhost.PackageSnapshotCmd:
			if host.upgraded {
				return out("ii \tpve-manager\t9.2.22\nii \tproxmox-kernel-7.0.15-1-pve-signed\t7.0.15-1\nii \tcurl\t8.14-2\n")
			}
			return out("ii \tpve-manager\t9.2.21\nii \tcurl\t8.14-1\n")
		case controllerhost.UpgradeBusyCommand:
			return host.busyOutput()
		case controllerhost.UpgradeOutcomeCommand:
			if host.outcomeErr != nil {
				return controllerhost.Result{ExitCode: 255}, host.outcomeErr
			}
			return out(host.outcome)
		case testUpgradeCommand:
			if host.upgradeErr != nil {
				return controllerhost.Result{ExitCode: 255}, host.upgradeErr
			}
			host.upgraded = true
			return out("")
		}
		return controllerhost.Result{ExitCode: 1}, errors.New("unexpected command " + command)
	}
	return host
}

func TestHostUpgradePlanRefreshesIndexesWithoutChangingPackages(t *testing.T) {
	host := upgradeHost(testSources, testSimulation)
	var out bytes.Buffer
	if err := runHostUpgradeWith(host.deps(), []string{"--plan"}, strings.NewReader("y\n"), &out); err != nil {
		t.Fatalf("plan: %v\n%s", err, out.String())
	}
	if host.lockCalls != 1 || host.count(controllerhost.AptRefreshCommand) != 1 || host.count(controllerhost.AptSimulateCommand) != 1 {
		t.Fatalf("plan commands=%v", host.commands)
	}
	if host.count("full-upgrade") != 1 || host.count("systemd-run") != 0 || host.count(controllerhost.PackageSnapshotCmd) != 0 || host.upgraded {
		t.Fatalf("plan mutated packages: %v", host.commands)
	}
	text := out.String()
	for _, want := range []string{"Planned           3 packages (2 upgraded, 1 new, 0 removed)", "Proxmox packages  pve-manager", "Kernel packages   proxmox-kernel-7.0.15-1-pve-signed", "Reboot expected   yes (proxmox-kernel-7.0.15-1-pve-signed)", "Refreshing the package indexes was the only change"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan output missing %q:\n%s", want, text)
		}
	}
}

func TestHostUpgradeRequiresApprovalAndRefusalOrEOFChangesNothing(t *testing.T) {
	for name, input := range map[string]string{"refusal": "n\n", "blank": "\n", "eof": ""} {
		host := upgradeHost(testSources, testSimulation)
		var out bytes.Buffer
		err := runHostUpgradeWith(host.deps(), nil, strings.NewReader(input), &out)
		if err == nil || !strings.Contains(err.Error(), "no packages were changed") {
			t.Fatalf("%s: err=%v", name, err)
		}
		if host.count("systemd-run") != 0 || host.upgraded {
			t.Fatalf("%s mutated packages: %v", name, host.commands)
		}
	}
	host := upgradeHost(testSources, testSimulation)
	if err := runHostUpgradeWith(host.deps(), nil, nil, &bytes.Buffer{}); err == nil || host.upgraded {
		t.Fatalf("non-interactive upgrade without --yes: err=%v upgraded=%v", err, host.upgraded)
	}
	for _, args := range [][]string{{"--plan", "--yes"}, {"--unknown"}, {"extra"}} {
		host := upgradeHost(testSources, testSimulation)
		if err := runHostUpgradeWith(host.deps(), args, strings.NewReader("y\n"), &bytes.Buffer{}); err == nil || host.lockCalls != 0 || len(host.commands) != 0 {
			t.Fatalf("%v: err=%v commands=%v", args, err, host.commands)
		}
	}
}

func TestHostUpgradeYesReportsChangedPackagesAndNeverReboots(t *testing.T) {
	host := upgradeHost(testSources, testSimulation)
	var out bytes.Buffer
	if err := runHostUpgradeWith(host.deps(), []string{"--yes"}, nil, &out); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, out.String())
	}
	if host.count(testUpgradeCommand) != 1 || host.count(controllerhost.RebootCommand) != 0 {
		t.Fatalf("commands=%v", host.commands)
	}
	for _, fragment := range []string{"DEBIAN_FRONTEND=noninteractive", "--force-confdef", "--force-confold", "full-upgrade"} {
		if !strings.Contains(testUpgradeCommand, fragment) {
			t.Fatalf("upgrade command lacks %s", fragment)
		}
	}
	text := out.String()
	for _, want := range []string{"Host upgrade: PASS", "Changed           3 packages (2 upgraded, 1 new, 0 removed)", "upgrade  pve-manager", "9.2.21 -> 9.2.22", "Reboot required   yes (running kernel 7.0.14-16-pve, newest installed 7.0.15-1-pve; changed proxmox-kernel-7.0.15-1-pve-signed)", "The Host was not rebooted"} {
		if !strings.Contains(text, want) {
			t.Errorf("upgrade output missing %q:\n%s", want, text)
		}
	}
}

func TestHostUpgradeNoChangeAndRepositoryRefusalsDoNotMutate(t *testing.T) {
	host := upgradeHost(testSources, "")
	var out bytes.Buffer
	if err := runHostUpgradeWith(host.deps(), []string{"--yes"}, nil, &out); err != nil || !strings.Contains(out.String(), "No changes required.") || host.upgraded {
		t.Fatalf("no-op err=%v upgraded=%v\n%s", err, host.upgraded, out.String())
	}
	enterprise := "BOETTICHER_SOURCE_FILE=/etc/apt/sources.list.d/pve-enterprise.sources\nTypes: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\n\nBOETTICHER_SUBSCRIPTION=notfound\n"
	host = upgradeHost(enterprise, testSimulation)
	if err := runHostUpgradeWith(host.deps(), []string{"--plan"}, nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "enterprise repository") || host.count(controllerhost.AptRefreshCommand) != 0 {
		t.Fatalf("enterprise err=%v commands=%v", err, host.commands)
	}
	host = upgradeHost(testSources, testSimulation+"Remv proxmox-ve [9.1.0]\n")
	if err := runHostUpgradeWith(host.deps(), []string{"--yes"}, nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "proxmox-ve") || host.upgraded {
		t.Fatalf("protected removal err=%v upgraded=%v", err, host.upgraded)
	}
}

const testGuests = `[{"type":"qemu","vmid":280,"name":"lab-firewall-01","status":"running","node":"lab-proxmox-01"},{"type":"qemu","vmid":502,"name":"lab-jupyter-01","status":"running","node":"lab-proxmox-01"},{"type":"lxc","vmid":120,"name":"lab-monitor-01","status":"running","node":"lab-proxmox-01"}]`

// rebootHost models a reboot during which the LAB path stays down (the
// firewall guest is not yet running) while HOME answers first.
func rebootHost(returnAfterPolls int) *fakeHost {
	host := &fakeHost{}
	homeProbes := 0
	guestPolls := 0
	host.handle = func(path, command string) (controllerhost.Result, error) {
		out := func(text string) (controllerhost.Result, error) {
			return controllerhost.Result{Stdout: []byte(text)}, nil
		}
		down := func() (controllerhost.Result, error) {
			return controllerhost.Result{ExitCode: 255}, errors.New("Proxmox SSH command failed: exit status 255: connect timed out")
		}
		if host.rebooted && path == "lab" && host.labDown {
			return down()
		}
		switch {
		case command == "pvesh get /nodes --output-format json":
			return out(testNodes)
		case command == controllerhost.UpgradeBusyCommand:
			return host.busyOutput()
		case command == "pvesh get /cluster/resources --output-format json":
			if host.rebooted {
				listing := strings.Replace(testGuests, `"vmid":502,"name":"lab-jupyter-01","status":"running"`, `"vmid":502,"name":"lab-jupyter-01","status":"stopped"`, 1)
				if host.guestLag > 0 {
					host.guestLag--
					listing = strings.Replace(listing, `"vmid":280,"name":"lab-firewall-01","status":"running"`, `"vmid":280,"name":"lab-firewall-01","status":"stopped"`, 1)
				}
				return out(listing)
			}
			return out(testGuests)
		case strings.HasSuffix(command, "/qemu/280/config --output-format json"):
			return out(`{"onboot":1,"startup":"order=1,up=60"}`)
		case strings.HasSuffix(command, "/qemu/502/config --output-format json"):
			return out(`{"name":"lab-jupyter-01"}`)
		case strings.HasSuffix(command, "/lxc/120/config --output-format json"):
			return out(`{"onboot":1,"startup":"order=2"}`)
		case command == controllerhost.GuestsServiceCommand:
			return out("enabled\n")
		case command == controllerhost.GuestsServiceActiveCmd:
			guestPolls++
			if guestPolls < 3 {
				return out("activating\n")
			}
			return out("active\n")
		case command == controllerhost.BootIDCommand:
			if !host.rebooted || host.rebootIgnored {
				return out(testBootBefore + "\n")
			}
			homeProbes++
			if homeProbes <= returnAfterPolls {
				return down()
			}
			return out(testBootAfter + "\n")
		case command == controllerhost.RebootCommand:
			host.rebooted = true
			host.labDown = !host.rebootIgnored
			if host.rebootErr != nil {
				return controllerhost.Result{ExitCode: host.rebootExit}, host.rebootErr
			}
			return out("")
		}
		return controllerhost.Result{ExitCode: 1}, errors.New("unexpected command " + command)
	}
	return host
}

func TestHostRebootKeepsRefusingGuestsWithoutWithGuests(t *testing.T) {
	host := rebootHost(0)
	err := runHostRebootWith(host.deps(), []string{"--yes"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "empty guest inventory") || !strings.Contains(err.Error(), "--with-guests") || host.rebooted {
		t.Fatalf("err=%v rebooted=%v", err, host.rebooted)
	}
	for _, args := range [][]string{nil, {"--with-guests"}, {"--plan", "--yes"}, {"extra"}} {
		host := rebootHost(0)
		if err := runHostRebootWith(host.deps(), args, &bytes.Buffer{}); err == nil || host.lockCalls != 0 || len(host.commands) != 0 {
			t.Fatalf("%v: err=%v commands=%v", args, err, host.commands)
		}
	}
}

func TestHostRebootPlanShowsGuestBootPolicyWithoutRebooting(t *testing.T) {
	host := rebootHost(0)
	var out bytes.Buffer
	if err := runHostRebootWith(host.deps(), []string{"--with-guests", "--plan"}, &out); err != nil {
		t.Fatalf("plan: %v\n%s", err, out.String())
	}
	if host.rebooted || host.count(controllerhost.RebootCommand) != 0 {
		t.Fatalf("plan rebooted: %v", host.commands)
	}
	text := out.String()
	firewall, monitor, jupyter := strings.Index(text, "280   lab-firewall-01"), strings.Index(text, "120   lab-monitor-01"), strings.Index(text, "502   lab-jupyter-01")
	if firewall < 0 || monitor < firewall || jupyter < monitor {
		t.Fatalf("guests not in start order:\n%s", text)
	}
	for _, want := range []string{"ONBOOT ORDER", "WARNING  502 lab-jupyter-01 is running but onboot is disabled; it will NOT start after the reboot", "pve-guests.service enabled", "Plan only. The Host was not rebooted."} {
		if !strings.Contains(text, want) {
			t.Errorf("plan output missing %q:\n%s", want, text)
		}
	}
}

func TestHostRebootWithGuestsReconnectsThroughHomeWithinBudget(t *testing.T) {
	host := rebootHost(6)
	var out bytes.Buffer
	deps := host.deps()
	start := host.clock
	if err := runHostRebootWith(deps, []string{"--with-guests", "--yes"}, &out); err != nil {
		t.Fatalf("reboot: %v\n%s", err, out.String())
	}
	if host.count("lab: "+controllerhost.RebootCommand) != 1 || host.count("home: "+controllerhost.RebootCommand) != 0 {
		t.Fatalf("reboot must be issued once over the normal path: %v", host.commands)
	}
	if elapsed := host.clock.Sub(start); elapsed != 90*time.Second {
		t.Fatalf("measured wait=%s", elapsed)
	}
	text := out.String()
	for _, want := range []string{"Host returned after 1m10s via 192.168.4.5", "280   lab-firewall-01          running  running  PASS  running again", "502   lab-jupyter-01           running  stopped  ATTENTION  not started (onboot disabled)", "ATTENTION  Normal Host path 10.10.99.5 is not answering yet", "Host reboot: PASS"} {
		if !strings.Contains(text, want) {
			t.Errorf("reboot output missing %q:\n%s", want, text)
		}
	}
}

func TestHostRebootStopsAtReturnBudget(t *testing.T) {
	host := rebootHost(1 << 30)
	deps := host.deps()
	deps.rebootReturnBudget = 2 * time.Minute
	start := host.clock
	err := runHostRebootWith(deps, []string{"--with-guests", "--yes"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "did not return within 2m0s") || !strings.Contains(err.Error(), "192.168.4.5") {
		t.Fatalf("err=%v", err)
	}
	if elapsed := host.clock.Sub(start); elapsed > deps.rebootReturnBudget+deps.pollInterval {
		t.Fatalf("wait exceeded budget: %s", elapsed)
	}
}

func TestHostUpgradePlanWithProtectedRemovalFails(t *testing.T) {
	host := upgradeHost(testSources, testSimulation+"Remv proxmox-ve [9.1.0]\n")
	var out bytes.Buffer
	err := runHostUpgradeWith(host.deps(), []string{"--plan"}, nil, &out)
	if err == nil || !strings.Contains(err.Error(), "proxmox-ve") || !strings.Contains(out.String(), "Refused:") || host.upgraded {
		t.Fatalf("err=%v upgraded=%v\n%s", err, host.upgraded, out.String())
	}
}

func TestHostUpgradeRefusesWhilePackageSystemBusy(t *testing.T) {
	for name, busy := range map[string]string{
		"unit active":     "BOETTICHER_UPGRADE_UNIT=active\nBOETTICHER_DPKG_LOCK=held\n",
		"unit activating": "BOETTICHER_UPGRADE_UNIT=activating\nBOETTICHER_DPKG_LOCK=free\n",
		"dpkg lock":       "BOETTICHER_UPGRADE_UNIT=inactive\nBOETTICHER_DPKG_LOCK=held\n",
		"lock unknown":    "BOETTICHER_UPGRADE_UNIT=inactive\nBOETTICHER_DPKG_LOCK=unknown\n",
	} {
		for _, args := range [][]string{{"--plan"}, {"--yes"}} {
			host := upgradeHost(testSources, testSimulation)
			host.busy = busy
			err := runHostUpgradeWith(host.deps(), args, nil, &bytes.Buffer{})
			if err == nil || host.count(controllerhost.AptRefreshCommand) != 0 || host.count(testUpgradeCommand) != 0 {
				t.Fatalf("%s %v: err=%v commands=%v", name, args, err, host.commands)
			}
		}
	}
}

func TestHostUpgradeReportsLiveUnitStateAfterSSHDropOrSystemdRunFailure(t *testing.T) {
	timeout := errors.New("Proxmox SSH command timed out: context deadline exceeded")
	for name, tc := range map[string]struct {
		runErr     error
		outcome    string
		outcomeErr error
		want       []string
		reject     string
	}{
		"still running":   {timeout, "BOETTICHER_UPGRADE_UNIT=active\nUnpacking pve-manager ...\n", nil, []string{"still running", "is active", "systemctl status boetticher-host-upgrade"}, "Host upgrade: PASS"},
		"finished":        {timeout, "BOETTICHER_UPGRADE_UNIT=inactive\nSetting up pve-manager\nBOETTICHER_UPGRADE_RESULT=" + testRunID + ":success\n", nil, []string{"finished on the Host", "changed packages were not reported"}, "still running"},
		"failed":          {timeout, "BOETTICHER_UPGRADE_UNIT=inactive\nE: Sub-process /usr/bin/dpkg returned an error code (1)\nBOETTICHER_UPGRADE_RESULT=" + testRunID + ":failed\n", nil, []string{"Host full-upgrade failed", "dpkg returned an error"}, "still running"},
		"unreadable":      {timeout, "", errors.New("exit status 255: connect timed out"), []string{"outcome is unknown", "could not be read", "grep BOETTICHER_UPGRADE_RESULT="}, "still running"},
		"stale marker":    {errors.New("Proxmox SSH command failed: exit status 1: Failed to connect to bus"), "BOETTICHER_UPGRADE_UNIT=inactive\nBOETTICHER_UPGRADE_RESULT=ffffffffffffffff:success\nBOETTICHER_UPGRADE_RESULT=success\n", nil, []string{"outcome is unknown", "no result marker for run " + testRunID, "previous run"}, "finished on the Host"},
		"no marker":       {errors.New("Proxmox SSH command failed: exit status 1"), "BOETTICHER_UPGRADE_UNIT=inactive\n", nil, []string{"outcome is unknown", "no result marker"}, "still running"},
		"unit exists":     {errors.New("Proxmox SSH command failed: exit status 1: Failed to start transient service unit: Unit boetticher-host-upgrade.service was already loaded or has a fragment file."), "", nil, []string{"did not start", "already exists from another run"}, "still running"},
		"unit exists alt": {errors.New("Proxmox SSH command failed: exit status 1: Unit boetticher-host-upgrade.service already exists."), "", nil, []string{"did not start"}, "continues"},
	} {
		host := upgradeHost(testSources, testSimulation)
		host.upgradeErr, host.outcome, host.outcomeErr = tc.runErr, tc.outcome, tc.outcomeErr
		var out bytes.Buffer
		err := runHostUpgradeWith(host.deps(), []string{"--yes"}, nil, &out)
		if err == nil {
			t.Fatalf("%s: upgrade failure was reported as success", name)
		}
		for _, want := range tc.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error lacks %q: %v", name, want, err)
			}
		}
		if strings.Contains(err.Error()+out.String(), tc.reject) || host.count(testUpgradeCommand) != 1 || host.count(controllerhost.RebootCommand) != 0 {
			t.Errorf("%s: err=%v commands=%v\n%s", name, err, host.commands, out.String())
		}
		if strings.HasPrefix(name, "unit exists") && host.count(controllerhost.UpgradeOutcomeCommand) != 0 {
			t.Errorf("%s: read another run's log as this run's outcome", name)
		}
	}
}

func TestHostRebootRefusedWhileUpgradeRunsOrDpkgLocked(t *testing.T) {
	for _, busy := range []string{"BOETTICHER_UPGRADE_UNIT=active\nBOETTICHER_DPKG_LOCK=held\n", "BOETTICHER_UPGRADE_UNIT=inactive\nBOETTICHER_DPKG_LOCK=held\n"} {
		for _, args := range [][]string{{"--yes"}, {"--plan"}, {"--with-guests", "--plan"}, {"--with-guests", "--yes"}} {
			host := rebootHost(0)
			host.busy = busy
			err := runHostRebootWith(host.deps(), args, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), "Host reboot refused") || host.count(controllerhost.RebootCommand) != 0 || host.count("/config --output-format json") != 0 {
				t.Fatalf("%v busy=%q: err=%v commands=%v", args, busy, err, host.commands)
			}
		}
	}
}

func TestHostRebootRequestErrorWaitsOnlyWhenRebootMayHaveStarted(t *testing.T) {
	for name, tc := range map[string]struct {
		exit int
		err  error
	}{
		"timeout":  {-1, fmt.Errorf("Proxmox SSH command timed out: %w", context.DeadlineExceeded)},
		"exit 255": {255, errors.New("Proxmox SSH command failed: exit status 255")},
		"killed":   {-1, errors.New("Proxmox SSH command failed: signal: killed")},
	} {
		host := rebootHost(2)
		host.rebootErr, host.rebootExit = tc.err, tc.exit
		var out bytes.Buffer
		if err := runHostRebootWith(host.deps(), []string{"--with-guests", "--yes"}, &out); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out.String())
		}
		if !strings.Contains(out.String(), "waiting for a new Host boot to confirm") || !strings.Contains(out.String(), "Host reboot: PASS") {
			t.Fatalf("%s output:\n%s", name, out.String())
		}
	}
	host := rebootHost(0)
	host.rebootErr, host.rebootExit, host.rebootIgnored = errors.New("Proxmox SSH command failed: exit status 1: Failed to start transient timer unit"), 1, true
	definite := host.deps()
	start := host.clock
	err := runHostRebootWith(definite, []string{"--with-guests", "--yes"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "reboot was not scheduled") || host.clock != start || host.count(controllerhost.BootIDCommand) != 1 {
		t.Fatalf("definite failure err=%v waited=%s commands=%v", err, host.clock.Sub(start), host.commands)
	}
	host = rebootHost(0)
	host.rebootErr, host.rebootExit, host.rebootIgnored = errors.New("Proxmox SSH command failed: exit status 255"), 255, true
	deps := host.deps()
	deps.rebootReturnBudget = time.Minute
	err = runHostRebootWith(deps, []string{"--with-guests", "--yes"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "did not return within 1m0s") || !strings.Contains(err.Error(), "still running the previous boot") {
		t.Fatalf("unchanged boot err=%v", err)
	}
	if !strings.Contains(controllerhost.RebootCommand, "--collect") {
		t.Fatal("reboot unit must be collected")
	}
}

func TestHostRebootRetriesLaggingGuestStatus(t *testing.T) {
	host := rebootHost(0)
	host.guestLag = 2
	var out bytes.Buffer
	if err := runHostRebootWith(host.deps(), []string{"--with-guests", "--yes"}, &out); err != nil {
		t.Fatalf("lagging listing failed: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "280   lab-firewall-01          running  running  PASS  running again") || strings.Count(strings.Join(host.commands, "\n"), "/cluster/resources") < 4 {
		t.Fatalf("commands=%v\n%s", host.commands, out.String())
	}
	host = rebootHost(0)
	host.guestLag = 1 << 30
	deps := host.deps()
	deps.guestStartBudget = time.Minute
	err := runHostRebootWith(deps, []string{"--with-guests", "--yes"}, &out)
	if err == nil || !strings.Contains(err.Error(), "1 guest(s)") {
		t.Fatalf("persistent stop err=%v", err)
	}
}

func TestHostRebootNamesRegisteredSystemsThatDidNotReturn(t *testing.T) {
	host := rebootHost(0)
	deps := host.deps()
	load := deps.loadConfig
	deps.loadConfig = func() (controllerhost.LabConfig, error) {
		config, err := load()
		config.Modules.Systems = []clientservices.System{{Name: "jupyter", VMID: 502}, {Name: "monitor", VMID: 120}}
		return config, err
	}
	var out bytes.Buffer
	if err := runHostRebootWith(deps, []string{"--with-guests", "--yes"}, &out); err != nil {
		t.Fatalf("reboot: %v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "ATTENTION  registered system jupyter (VMID 502) is stopped; start it with: boetticher host start-system jupyter --plan") || strings.Contains(text, "registered system monitor") {
		t.Fatalf("reboot output:\n%s", text)
	}
}
