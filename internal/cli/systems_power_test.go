package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

// powerGuest scripts one registered guest's Proxmox power state. Every Host
// command is recorded so tests can prove which paths never mutate.
type powerGuest struct {
	kind     string
	state    string
	onboot   string
	lag      int // status reads that still report the old state after an action
	failWith error
	commands []string
	locks    int
}

func (g *powerGuest) tool() string {
	if g.kind == "lxc" {
		return "pct"
	}
	return "qm"
}

func (g *powerGuest) count(fragment string) int {
	total := 0
	for _, command := range g.commands {
		if strings.Contains(command, fragment) {
			total++
		}
	}
	return total
}

func powerFixture(t *testing.T, kind, state string) (*controllerhost.LabConfig, *powerGuest) {
	t.Helper()
	config, _ := systemsCommandFixture(t)
	config.Modules.Systems = []clientservices.System{{Name: "octoprint", VMID: 501, Kind: kind, GuestName: "octoprint", MAC: "02:00:00:00:20:61", Address: "10.10.20.61", Port: 5000, Monitoring: false}}
	guest := &powerGuest{kind: kind, state: state, onboot: `{"onboot":1,"startup":"order=30"}`}
	systemsAcquireLock = func() (func(), error) { guest.locks++; return func() {}, nil }
	systemsCollect = func(context.Context, controllerhost.Transport, bool) (controllerhost.Inventory, error) {
		return controllerhost.Inventory{Guests: []controllerhost.Guest{{VMID: 501, Type: guest.kind, Name: "octoprint", Status: guest.state, Node: "lab-proxmox-01"}}}, nil
	}
	systemsInspectGuest = func(_ context.Context, _ controllerhost.Transport, g controllerhost.Guest) (string, string, string, string, error) {
		return g.Type, "02:00:00:00:20:61", "vmbr1", "20", nil
	}
	pending := ""
	systemsRun = func(_ context.Context, _ controllerhost.Transport, command string) (controllerhost.Result, error) {
		guest.commands = append(guest.commands, command)
		switch command {
		case "pvesh get /nodes/lab-proxmox-01/" + guest.kind + "/501/config --output-format json":
			return controllerhost.Result{Stdout: []byte(guest.onboot)}, nil
		case guest.tool() + " status 501":
			if pending != "" {
				if guest.lag > 0 {
					guest.lag--
				} else {
					guest.state, pending = pending, ""
				}
			}
			return controllerhost.Result{Stdout: []byte("status: " + guest.state + "\n")}, nil
		case guest.tool() + " start 501":
			if guest.failWith != nil {
				return controllerhost.Result{ExitCode: 2}, guest.failWith
			}
			pending = "running"
			return controllerhost.Result{}, nil
		case guest.tool() + " shutdown 501 --timeout 60":
			if guest.failWith != nil {
				return controllerhost.Result{ExitCode: 2}, guest.failWith
			}
			pending = "stopped"
			return controllerhost.Result{}, nil
		}
		t.Errorf("unexpected Host command %q", command)
		return controllerhost.Result{ExitCode: 1}, errors.New("unexpected command")
	}
	return config, guest
}

func mutations(g *powerGuest) int {
	return g.count(" start ") + g.count(" shutdown ") + g.count(" stop ")
}

func TestStartSystemPlanShowsVerifiedActionWithoutMutation(t *testing.T) {
	_, guest := powerFixture(t, "lxc", "stopped")
	var out bytes.Buffer
	if err := runSystems([]string{"start-system", "octoprint", "--plan"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("plan: %v\n%s", err, out.String())
	}
	for _, want := range []string{"Identity  matches registration", "Power     stopped (onboot yes)", "Action    pct start 501", "Plan only. The guest was not changed."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plan output missing %q:\n%s", want, out.String())
		}
	}
	if mutations(guest) != 0 || guest.locks != 0 {
		t.Fatalf("plan mutated or locked: locks=%d commands=%v", guest.locks, guest.commands)
	}
}

func TestStartSystemYesStartsUnderLockAndWaitsForRunning(t *testing.T) {
	_, guest := powerFixture(t, "lxc", "stopped")
	guest.lag = 2
	var out bytes.Buffer
	if err := runSystems([]string{"start-system", "octoprint", "--yes"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("start: %v\n%s", err, out.String())
	}
	if guest.locks != 1 || guest.count("pct start 501") != 1 || guest.state != "running" || !strings.Contains(out.String(), "Start-system: PASS (system octoprint is running)") {
		t.Fatalf("locks=%d commands=%v\n%s", guest.locks, guest.commands, out.String())
	}
}

func TestStopSystemUsesGracefulBoundedShutdownForVM(t *testing.T) {
	config, guest := powerFixture(t, "qemu", "running")
	config.Modules.Systems[0].Monitoring = true
	var out bytes.Buffer
	if err := runSystems([]string{"stop-system", "octoprint", "--yes"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("stop: %v\n%s", err, out.String())
	}
	if guest.count("qm shutdown 501 --timeout 60") != 1 || guest.count(" stop ") != 0 || guest.state != "stopped" {
		t.Fatalf("commands=%v", guest.commands)
	}
	for _, want := range []string{"monitoring check reports it down", "onboot is enabled; Proxmox starts it again", "Stop-system: PASS (system octoprint is stopped)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stop output missing %q:\n%s", want, out.String())
		}
	}
}

func TestSystemPowerAlreadySettledIsNoOp(t *testing.T) {
	for _, tc := range []struct{ action, state string }{{"start-system", "running"}, {"stop-system", "stopped"}} {
		for _, mode := range []string{"--plan", "--yes"} {
			_, guest := powerFixture(t, "lxc", tc.state)
			var out bytes.Buffer
			if err := runSystems([]string{tc.action, "octoprint", mode}, strings.NewReader(""), &out, &out); err != nil {
				t.Fatalf("%s %s: %v", tc.action, mode, err)
			}
			if mutations(guest) != 0 || !strings.Contains(out.String(), "No change: system octoprint is already "+tc.state) {
				t.Fatalf("%s %s: commands=%v\n%s", tc.action, mode, guest.commands, out.String())
			}
		}
	}
}

func TestSystemPowerRefusesIdentityMismatchAndProductGuests(t *testing.T) {
	for name, adjust := range map[string]func(*powerGuest){
		"MAC": func(*powerGuest) {
			systemsInspectGuest = func(_ context.Context, _ controllerhost.Transport, g controllerhost.Guest) (string, string, string, string, error) {
				return g.Type, "02:00:00:00:20:62", "vmbr1", "20", nil
			}
		},
		"kind": func(g *powerGuest) { g.kind = "qemu" },
		"guest name": func(g *powerGuest) {
			systemsCollect = func(context.Context, controllerhost.Transport, bool) (controllerhost.Inventory, error) {
				return controllerhost.Inventory{Guests: []controllerhost.Guest{{VMID: 501, Type: "lxc", Name: "replacement", Status: "stopped"}}}, nil
			}
		},
		"missing": func(*powerGuest) {
			systemsCollect = func(context.Context, controllerhost.Transport, bool) (controllerhost.Inventory, error) {
				return controllerhost.Inventory{}, nil
			}
		},
		"product-owned": func(*powerGuest) {
			systemsInspectGuest = func(context.Context, controllerhost.Transport, controllerhost.Guest) (string, string, string, string, error) {
				return "", "", "", "", errors.New("product-owned guest cannot be registered")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, action := range []string{"start-system", "stop-system"} {
				_, guest := powerFixture(t, "lxc", "stopped")
				if action == "stop-system" {
					guest.state = "running"
				}
				adjust(guest)
				var out bytes.Buffer
				err := runSystems([]string{action, "octoprint", "--yes"}, strings.NewReader(""), &out, &out)
				if err == nil || !strings.Contains(err.Error(), "refused") || len(guest.commands) != 0 {
					t.Fatalf("%s: err=%v commands=%v", action, err, guest.commands)
				}
			}
		})
	}
}

func TestSystemPowerRejectsInvalidAndUnregisteredWithoutHostCalls(t *testing.T) {
	_, guest := powerFixture(t, "lxc", "stopped")
	for _, args := range [][]string{{"start-system"}, {"start-system", "octoprint"}, {"start-system", "octoprint", "--plan", "--yes"}, {"stop-system", "--yes"}, {"stop-system", "octoprint", "--yes", "extra"}, {"start-system", "other", "--yes"}} {
		if err := runSystems(args, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if len(guest.commands) != 0 {
		t.Fatalf("invalid invocations reached the Host: %v", guest.commands)
	}
}

func TestSystemPowerRefusesOtherStatesAndReportsFailures(t *testing.T) {
	_, guest := powerFixture(t, "qemu", "paused")
	err := runSystems([]string{"start-system", "octoprint", "--yes"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "guest is paused") || mutations(guest) != 0 {
		t.Fatalf("paused guest: err=%v commands=%v", err, guest.commands)
	}

	_, guest = powerFixture(t, "lxc", "running")
	guest.failWith = errors.New("shutdown timed out")
	var out bytes.Buffer
	err = runSystems([]string{"stop-system", "octoprint", "--yes"}, strings.NewReader(""), &out, &out)
	if err == nil || !strings.Contains(out.String(), "Stop-system: FAIL (guest is running)") || guest.count(" stop ") != 0 {
		t.Fatalf("failed shutdown: err=%v commands=%v\n%s", err, guest.commands, out.String())
	}

	_, guest = powerFixture(t, "lxc", "stopped")
	guest.lag = 1 << 30
	out.Reset()
	err = runSystems([]string{"start-system", "octoprint", "--yes"}, strings.NewReader(""), &out, &out)
	if err == nil || !strings.Contains(err.Error(), "did not become running") || !strings.Contains(out.String(), "Start-system: FAIL (guest is stopped)") {
		t.Fatalf("unsettled start: err=%v\n%s", err, out.String())
	}
}

func TestSystemStatusReportsStoppedGuestAsFail(t *testing.T) {
	_, guest := powerFixture(t, "lxc", "stopped")
	systemsLoadClientServiceContext = func() (clientServiceContext, error) { return clientServiceContext{}, errors.New("not needed") }
	var out bytes.Buffer
	if err := runSystems([]string{"system-status", "octoprint"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Power     stopped (onboot yes)", "Result    FAIL guest is stopped; start it with: boetticher host start-system octoprint --plan"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "PASS") || mutations(guest) != 0 {
		t.Fatalf("stopped guest reported PASS or mutated: %v\n%s", guest.commands, out.String())
	}

	// A running guest still needs provider evidence before PASS.
	guest.state = "running"
	out.Reset()
	if err := runSystems([]string{"system-status", "octoprint"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Power     running (onboot yes)") || !strings.Contains(out.String(), "Result    FAIL provider context unavailable") {
		t.Fatalf("running status:\n%s", out.String())
	}

	systemsCollect = func(context.Context, controllerhost.Transport, bool) (controllerhost.Inventory, error) {
		return controllerhost.Inventory{}, errors.New("ssh down")
	}
	out.Reset()
	if err := runSystems([]string{"system-status", "octoprint"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Power     unavailable") || !strings.Contains(out.String(), "Result    UNKNOWN Host unavailable") {
		t.Fatalf("unavailable status:\n%s", out.String())
	}
}

func TestListSystemsShowsPowerStateReadOnly(t *testing.T) {
	_, guest := powerFixture(t, "lxc", "stopped")
	var out bytes.Buffer
	if err := runSystems([]string{"list-systems"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "octoprint VMID=501 lxc 10.10.20.61:5000 check=false power=stopped onboot=yes") || mutations(guest) != 0 {
		t.Fatalf("list:\n%s\ncommands=%v", out.String(), guest.commands)
	}
	systemsCollect = func(context.Context, controllerhost.Transport, bool) (controllerhost.Inventory, error) {
		return controllerhost.Inventory{}, errors.New("ssh down")
	}
	out.Reset()
	if err := runSystems([]string{"list-systems"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "power=unavailable") || !strings.Contains(out.String(), "Power state unavailable: ssh down") {
		t.Fatalf("unavailable list:\n%s", out.String())
	}
}
