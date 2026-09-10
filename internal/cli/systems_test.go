package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/model"
)

func systemsCommandFixture(t *testing.T) (*controllerhost.LabConfig, *int) {
	t.Helper()
	yes := true
	config := &controllerhost.LabConfig{Name: "lab", Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}, Modules: clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &yes}, DHCP: &clientservices.DHCPConfig{Enabled: &yes}}}
	remoteCalls := 0
	oldLoad, oldSave := systemsLoadConfig, systemsSaveConfig
	oldTransport, oldCollect, oldInspect := systemsTransportFor, systemsCollect, systemsInspectGuest
	oldLeases, oldContext, oldLock := systemsReadNativeDHCPLeases, systemsLoadClientServiceContext, systemsAcquireLock
	t.Cleanup(func() {
		systemsLoadConfig, systemsSaveConfig = oldLoad, oldSave
		systemsTransportFor, systemsCollect, systemsInspectGuest = oldTransport, oldCollect, oldInspect
		systemsReadNativeDHCPLeases, systemsLoadClientServiceContext, systemsAcquireLock = oldLeases, oldContext, oldLock
	})
	systemsLoadConfig = func() (controllerhost.LabConfig, error) { return *config, nil }
	systemsTransportFor = func(controllerhost.LabConfig) (controllerhost.Transport, error) {
		return controllerhost.Transport{}, nil
	}
	systemsCollect = func(context.Context, controllerhost.Transport, bool) (controllerhost.Inventory, error) {
		remoteCalls++
		return controllerhost.Inventory{Guests: []controllerhost.Guest{{VMID: 501, Type: "lxc", Name: "print"}}}, nil
	}
	systemsInspectGuest = func(context.Context, controllerhost.Transport, controllerhost.Guest) (string, string, string, string, error) {
		remoteCalls++
		return "lxc", "02:00:00:00:20:61", "vmbr1", "20", nil
	}
	systemsReadNativeDHCPLeases = func(context.Context, firewallmodule.HostClient) ([]nativeDHCPLease, error) {
		return nil, errLeaseFileAbsent
	}
	systemsAcquireLock = func() (func(), error) { return func() {}, nil }
	return config, &remoteCalls
}

func TestRunSystemsRejectsInvalidInvocationWithoutMutation(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"list-systems", "extra"}, {"register-system", "x", "--plan", "--yes"}, {"unregister-system", "x"}} {
		if err := runSystems(args, strings.NewReader(""), &strings.Builder{}, &strings.Builder{}); err == nil {
			t.Fatalf("accepted invalid invocation %v", args)
		}
	}
}

func TestMonitoredSystemRequiresObservability(t *testing.T) {
	on := true
	modules := clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &on}, DHCP: &clientservices.DHCPConfig{Enabled: &on}, Systems: []clientservices.System{{Name: "print-server", VMID: 501, Kind: "lxc", GuestName: "print", MAC: "02:00:00:00:20:61", Address: "10.10.20.61", Port: 631, Monitoring: true}}}
	if err := clientservices.Validate(modules, model.NewSite("lab", "controller-local", model.GatewayModeManaged)); err == nil || !strings.Contains(err.Error(), "observability") {
		t.Fatalf("accepted monitored system without observability: %v", err)
	}
}

func TestRunSystemsPlanAndRefusalNeverSaveIntent(t *testing.T) {
	config, remoteCalls := systemsCommandFixture(t)
	saves := 0
	systemsSaveConfig = func(controllerhost.LabConfig) error { saves++; return nil }
	for index, args := range [][]string{
		{"register-system", "print", "--vmid", "501", "--address", "10.10.20.61", "--port", "631", "--plan"},
		{"register-system", "print", "--vmid", "501", "--address", "10.10.20.61", "--port", "631"},
	} {
		out := &strings.Builder{}
		err := runSystems(args, strings.NewReader(""), out, &strings.Builder{})
		if index == 0 && err != nil {
			t.Fatalf("plan failed: %v", err)
		}
		if index == 1 && err == nil {
			t.Fatalf("refusal unexpectedly succeeded")
		}
	}
	if saves != 0 || len(config.Modules.Systems) != 0 {
		t.Fatalf("plan/refusal mutated canonical intent: saves=%d systems=%#v", saves, config.Modules.Systems)
	}
	if *remoteCalls == 0 {
		t.Fatal("command fixture did not exercise guest identity reads")
	}
}

func TestRunSystemsSavesIntentBeforeProviderFailure(t *testing.T) {
	config, _ := systemsCommandFixture(t)
	saved := false
	systemsSaveConfig = func(next controllerhost.LabConfig) error { saved = true; *config = next; return nil }
	systemsLoadClientServiceContext = func() (clientServiceContext, error) {
		return clientServiceContext{}, errors.New("provider unavailable")
	}
	out := &strings.Builder{}
	err := runSystems([]string{"register-system", "print", "--vmid", "501", "--address", "10.10.20.61", "--port", "631", "--yes"}, strings.NewReader(""), out, &strings.Builder{})
	if err == nil || !saved || len(config.Modules.Systems) != 1 || strings.Contains(out.String(), "PASS") || !strings.Contains(out.String(), "saved; application deferred") {
		t.Fatalf("save-before-provider contract failed: err=%v saved=%t systems=%#v output=%s", err, saved, config.Modules.Systems, out.String())
	}
}

func TestRunSystemsReregistersIdenticalIdentityForRepair(t *testing.T) {
	config, _ := systemsCommandFixture(t)
	config.Modules.Systems = []clientservices.System{{Name: "print", VMID: 501, Kind: "lxc", GuestName: "print", MAC: "02:00:00:00:20:61", Address: "10.10.20.61", Port: 631}}
	saved := 0
	systemsSaveConfig = func(next controllerhost.LabConfig) error { saved++; *config = next; return nil }
	systemsLoadClientServiceContext = func() (clientServiceContext, error) {
		return clientServiceContext{}, errors.New("provider unavailable")
	}
	err := runSystems([]string{"register-system", "print", "--vmid", "501", "--address", "10.10.20.61", "--port", "631", "--yes"}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	if err == nil || saved != 1 || len(config.Modules.Systems) != 1 {
		t.Fatalf("identical re-registration did not reach saved repair path: err=%v saves=%d systems=%#v", err, saved, config.Modules.Systems)
	}
}

func TestRunSystemsRejectsChangedGuestIdentity(t *testing.T) {
	for name, adjust := range map[string]func(){
		"MAC": func() {
			systemsInspectGuest = func(context.Context, controllerhost.Transport, controllerhost.Guest) (string, string, string, string, error) {
				return "lxc", "02:00:00:00:20:62", "vmbr1", "20", nil
			}
		},
		"guest name": func() {
			systemsCollect = func(context.Context, controllerhost.Transport, bool) (controllerhost.Inventory, error) {
				return controllerhost.Inventory{Guests: []controllerhost.Guest{{VMID: 501, Type: "lxc", Name: "replacement-print"}}}, nil
			}
		},
		"kind": func() {
			systemsInspectGuest = func(context.Context, controllerhost.Transport, controllerhost.Guest) (string, string, string, string, error) {
				return "qemu", "02:00:00:00:20:61", "vmbr1", "20", nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := systemsCommandFixture(t)
			config.Modules.Systems = []clientservices.System{{Name: "print", VMID: 501, Kind: "lxc", GuestName: "print", MAC: "02:00:00:00:20:61", Address: "10.10.20.61", Port: 631}}
			saves := 0
			systemsSaveConfig = func(controllerhost.LabConfig) error { saves++; return nil }
			adjust()
			err := runSystems([]string{"register-system", "print", "--vmid", "501", "--address", "10.10.20.61", "--port", "631", "--yes"}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
			if err == nil || !strings.Contains(err.Error(), "unregister and register") || saves != 0 {
				t.Fatalf("changed %s identity was rebound: err=%v saves=%d", name, err, saves)
			}
		})
	}
}

func TestRunSystemsAllowsItsOwnActiveLeaseAndRejectsOtherIdentity(t *testing.T) {
	config, _ := systemsCommandFixture(t)
	systemsReadNativeDHCPLeases = func(context.Context, firewallmodule.HostClient) ([]nativeDHCPLease, error) {
		return []nativeDHCPLease{{Hostname: "print", MAC: "02:00:00:00:20:61", Address: "10.10.20.61"}}, nil
	}
	systemsSaveConfig = func(next controllerhost.LabConfig) error { *config = next; return errors.New("stop after admission") }
	err := runSystems([]string{"register-system", "print", "--vmid", "501", "--address", "10.10.20.61", "--port", "631", "--yes"}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	if err == nil || strings.Contains(err.Error(), "active DHCP lease conflicts") {
		t.Fatalf("own active lease was rejected: %v", err)
	}
	// Change only the lease identity; admission must reject before saving.
	config.Modules.Systems = nil
	systemsReadNativeDHCPLeases = func(context.Context, firewallmodule.HostClient) ([]nativeDHCPLease, error) {
		return []nativeDHCPLease{{Hostname: "print", MAC: "02:00:00:00:20:62", Address: "10.10.20.61"}}, nil
	}
	if err := runSystems([]string{"register-system", "print", "--vmid", "501", "--address", "10.10.20.61", "--port", "631", "--yes"}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "active DHCP lease conflicts") {
		t.Fatalf("other active lease was accepted: %v", err)
	}
}
