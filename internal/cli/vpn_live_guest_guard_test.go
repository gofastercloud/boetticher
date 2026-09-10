package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

type vpnGuardRunner struct {
	outputs map[string]string
	errs    map[string]error
	calls   []string
}

func (r *vpnGuardRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	if err := r.errs[command]; err != nil {
		return controllerhost.Result{}, err
	}
	return controllerhost.Result{Stdout: []byte(r.outputs[command])}, nil
}

func guardedVPNModules() clientservices.Modules {
	enabled := true
	return clientservices.Modules{
		DHCP: &clientservices.DHCPConfig{Reservations: []clientservices.Reservation{{Name: "protected-peer", Zone: "SERVERS", MAC: "02:00:00:00:20:e1", Address: "10.10.20.225"}}},
		VPN:  &clientservices.VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{"protected-peer"}},
	}
}

func TestVPNStopGuardRefusesNonProductQEMUBeforeAnyMutation(t *testing.T) {
	runner := &vpnGuardRunner{outputs: map[string]string{
		"pvesh get /cluster/resources --type vm --output-format json": `[{"vmid":901,"type":"qemu","status":"running","node":"pve"}]`,
		"qm config 901": "net0: e1000-82545em=02:00:00:00:20:e1,bridge=vmbr1\n",
	}}
	err := refuseVPNStopWithLiveProtectedGuests(context.Background(), runner, "pve", guardedVPNModules())
	if err == nil || !strings.Contains(err.Error(), "901 (qemu unnamed)") {
		t.Fatalf("guard error = %v", err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "uci ") || strings.Contains(call, "systemctl") {
			t.Fatalf("guard mutated provider before refusal: %q", call)
		}
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "qm config 901") {
		t.Fatalf("guard did not use the native QEMU command: %#v", runner.calls)
	}
}

func TestVPNStopGuardFindsLXCSecondNICAndIgnoresOtherNode(t *testing.T) {
	runner := &vpnGuardRunner{outputs: map[string]string{
		"pvesh get /cluster/resources --type vm --output-format json": `{"data":[{"vmid":902,"name":"container","type":"lxc","status":"running","node":"pve"},{"vmid":903,"name":"other-node","type":"qemu","status":"running","node":"other"}]}`,
		"pct config 902": "net0: name=eth0,hwaddr=02:00:00:00:20:e2,bridge=vmbr1\nnet1: name=eth1,hwaddr=02:00:00:00:20:e1,bridge=vmbr1\n",
	}}
	err := refuseVPNStopWithLiveProtectedGuests(context.Background(), runner, "pve", guardedVPNModules())
	if err == nil || !strings.Contains(err.Error(), "902 (lxc container)") {
		t.Fatalf("guard error = %v", err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "903") {
			t.Fatalf("guard inspected a different cluster node: %q", call)
		}
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "pct config 902") {
		t.Fatalf("guard did not use the native LXC command: %#v", runner.calls)
	}
}

func TestVPNStopGuardPermitsStoppedGuests(t *testing.T) {
	runner := &vpnGuardRunner{outputs: map[string]string{
		"pvesh get /cluster/resources --type vm --output-format json": `[{"vmid":904,"name":"stopped","type":"qemu","status":"stopped","node":"pve"}]`,
	}}
	if err := refuseVPNStopWithLiveProtectedGuests(context.Background(), runner, "pve", guardedVPNModules()); err != nil {
		t.Fatalf("stopped protected guest blocked VPN stop: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("stopped guest config was inspected: %#v", runner.calls)
	}
}

func TestVPNStopGuardFailsClosedForUnknownAndUnreadableInventory(t *testing.T) {
	for name, runner := range map[string]*vpnGuardRunner{
		"unknown type": {outputs: map[string]string{"pvesh get /cluster/resources --type vm --output-format json": `[{"vmid":905,"name":"unknown","type":"other","status":"running","node":"pve"}]`}},
		"transport":    {errs: map[string]error{"pvesh get /cluster/resources --type vm --output-format json": errors.New("offline")}},
		"bad config":   {outputs: map[string]string{"pvesh get /cluster/resources --type vm --output-format json": `[{"vmid":906,"name":"bad","type":"qemu","status":"running","node":"pve"}]`, "qm config 906": "net0: bridge=vmbr1\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := refuseVPNStopWithLiveProtectedGuests(context.Background(), runner, "pve", guardedVPNModules()); err == nil {
				t.Fatal("unsafe inventory was accepted")
			}
		})
	}
}

func TestVPNStopGuardFailsClosedForMissingConfiguredReference(t *testing.T) {
	modules := guardedVPNModules()
	modules.VPN.Clients = []string{"missing"}
	if err := refuseVPNStopWithLiveProtectedGuests(context.Background(), &vpnGuardRunner{}, "pve", modules); err == nil || !strings.Contains(err.Error(), "no DHCP reservation") {
		t.Fatalf("missing reference error = %v", err)
	}
}
