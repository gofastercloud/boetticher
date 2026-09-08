package tailnet

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestTransportFailureIsNeverGuestAbsence(t *testing.T) {
	f := &fakeRunner{outputs: map[string]controllerhost.Result{"pct config 200": {ExitCode: 255}}}
	if _, err := InspectGuest(context.Background(), f); err == nil {
		t.Fatal("SSH failure was treated as a missing guest")
	}
}

func TestRuntimeReadyStateAllowsRepairAfterGuestProbeFailure(t *testing.T) {
	ready, err := RuntimeReadyState(context.Background(), fixedRunner{
		result: controllerhost.Result{ExitCode: 1},
		err:    errors.New("guest runtime probe failed"),
	})
	if err != nil {
		t.Fatalf("guest probe failure became transport error: %v", err)
	}
	if ready {
		t.Fatal("failed guest runtime probe was reported ready")
	}
}

func TestRuntimeReadyStatePreservesHostTransportFailure(t *testing.T) {
	_, err := RuntimeReadyState(context.Background(), fixedRunner{
		result: controllerhost.Result{ExitCode: 255},
		err:    errors.New("SSH connection failed"),
	})
	if err == nil || !strings.Contains(err.Error(), "inspect Tailnet runtime") {
		t.Fatalf("transport failure = %v, want preserved inspection error", err)
	}
}

func TestRuntimeReadyStateReportsHealthyGuest(t *testing.T) {
	ready, err := RuntimeReadyState(context.Background(), fixedRunner{})
	if err != nil || !ready {
		t.Fatalf("healthy guest probe = ready %v, err %v", ready, err)
	}
}

type fixedRunner struct {
	result controllerhost.Result
	err    error
}

func (r fixedRunner) Run(context.Context, string) (controllerhost.Result, error) {
	return r.result, r.err
}

func TestBootstrapShellQuoteRoundTrip(t *testing.T) {
	if got := shellQuote("a'b"); got != "'a'\"'\"'b'" {
		t.Fatalf("shell quote is not a literal round trip: %q", got)
	}
}

type fakeRunner struct {
	outputs map[string]controllerhost.Result
	calls   []string
}

func (f *fakeRunner) RunWithStdin(ctx context.Context, command string, _ io.Reader) (controllerhost.Result, error) {
	return f.Run(ctx, command)
}

func TestConfigureStoppedBackendReusesIdentityWithoutAuthKey(t *testing.T) {
	f := &fakeRunner{outputs: map[string]controllerhost.Result{
		inventoryCommand: {Stdout: []byte(`[{"vmid":200,"type":"lxc","status":"running"}]`)},
		"pct config 200": {Stdout: ownedConfig()},
		GuestCommand("tailscale status --json --peers=false"): {Stdout: []byte(`{"BackendState":"Stopped"}`)},
	}}
	if err := Configure(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "auth-key") {
			t.Fatalf("auth key exposed in call %q", call)
		}
	}
	if len(f.calls) == 0 || !strings.Contains(f.calls[len(f.calls)-1], "tailscale up") {
		t.Fatalf("calls = %#v, want identity-preserving tailscale up", f.calls)
	}
}

func TestConfigurePrettyStoppedBackendUsesIdentityPreservingUp(t *testing.T) {
	f := &fakeRunner{outputs: map[string]controllerhost.Result{
		inventoryCommand: {Stdout: []byte(`[{
  "vmid": 200,
  "type": "lxc",
  "status": "running"
}]`)},
		"pct config 200": {Stdout: ownedConfig()},
		GuestCommand("tailscale status --json --peers=false"): {Stdout: []byte(`{
  "BackendState": "Stopped",
  "Version": "1.102.3"
}`)},
	}}
	if err := Configure(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) == 0 || !strings.Contains(f.calls[len(f.calls)-1], "tailscale up --timeout=45s") {
		t.Fatalf("calls = %#v, want timeout-bounded identity-preserving tailscale up", f.calls)
	}
	if strings.Contains(f.calls[len(f.calls)-1], "tailscale set") {
		t.Fatalf("stopped backend used preference-only set: %q", f.calls[len(f.calls)-1])
	}
}

func TestConfigureDisconnectedBackendUsesIdentityPreservingUp(t *testing.T) {
	f := &fakeRunner{outputs: map[string]controllerhost.Result{
		"pct config 200": {Stdout: ownedConfig()},
		GuestCommand("tailscale status --json --peers=false"): {Stdout: []byte(`{"BackendState":"Running","Self":{"Online":false}}`)},
	}}
	if err := Configure(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) == 0 || !strings.Contains(f.calls[len(f.calls)-1], "tailscale up --timeout=45s") {
		t.Fatalf("disconnected backend did not use identity-preserving up: %#v", f.calls)
	}
}

func TestTailnetAuthScriptCleansTemporaryKeyOnSuccessAndFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			bin := t.TempDir()
			keyPath := filepath.Join(bin, "auth-key")
			logPath := filepath.Join(bin, "tailscale-args")
			write := func(name, body string) {
				t.Helper()
				path := filepath.Join(bin, name)
				if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			write("mktemp", "#!/bin/sh\n: >\"$FAKE_TAILNET_KEY\"\nprintf '%s\\n' \"$FAKE_TAILNET_KEY\"\n")
			write("tailscale", "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$FAKE_TAILNET_LOG\"\nif [ \"$FAKE_TAILNET_FAIL\" = 1 ]; then exit 7; fi\n")
			command := exec.Command("/bin/sh", "-c", tailnetAuthScript)
			command.Env = append(os.Environ(), "PATH="+bin+":/bin:/usr/bin", "FAKE_TAILNET_KEY="+keyPath, "FAKE_TAILNET_LOG="+logPath)
			if failed {
				command.Env = append(command.Env, "FAKE_TAILNET_FAIL=1")
			}
			command.Stdin = strings.NewReader("tskey-auth-synthetic")
			err := command.Run()
			if failed && err == nil {
				t.Fatal("failing tailscale command unexpectedly succeeded")
			}
			if !failed && err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
				t.Fatalf("temporary auth key remains after script exit: %v", err)
			}
			args, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(args), "up\n--timeout=45s\n--auth-key=file:"+keyPath) {
				t.Fatalf("tailscale received unexpected arguments: %q", args)
			}
		})
	}
}

func (f *fakeRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	f.calls = append(f.calls, command)
	result, ok := f.outputs[command]
	if !ok && command == inventoryCommand {
		return controllerhost.Result{Stdout: []byte(`[{"vmid":200,"type":"lxc","status":"running"}]`)}, nil
	}
	if !ok && strings.Contains(command, "tailscale up") {
		return controllerhost.Result{}, nil
	}
	if !ok && strings.Contains(command, "sysctl -n net.ipv4.ip_forward") && strings.Contains(command, "dpkg-query") {
		return controllerhost.Result{}, nil
	}
	if !ok {
		return controllerhost.Result{ExitCode: 1}, context.Canceled
	}
	if result.ExitCode != 0 {
		return result, context.Canceled
	}
	return result, nil
}

func ownedConfig() []byte {
	return []byte("hostname: lab-tailnet-01\nunprivileged: 1\nrootfs: boetticher-data:vm-200-disk-0,size=8G\nnet0: name=eth0,bridge=vmbr1,tag=5,ip=dhcp,ip6=manual,hwaddr=02:00:00:00:05:10,firewall=1\ndev0: path=/dev/net/tun,mode=0666\nnameserver: 10.10.5.1\nonboot: 1\ntags: boetticher;managed;module;boetticher-module-tailnet\n")
}

func TestInspectGuestRejectsWrongIdentityBeforeOtherRuntimeInspection(t *testing.T) {
	f := &fakeRunner{outputs: map[string]controllerhost.Result{"pct config 200": {Stdout: []byte("hostname: unrelated\ntags: boetticher;managed\n")}}}
	if _, err := InspectGuest(context.Background(), f); err == nil || !strings.Contains(err.Error(), "not the exact owned") {
		t.Fatalf("InspectGuest error = %v", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("runtime calls = %#v", f.calls)
	}
}

func TestReadStatusRequiresExactPreferencesAndRouteApproval(t *testing.T) {
	f := &fakeRunner{outputs: map[string]controllerhost.Result{
		"pct config 200": {Stdout: ownedConfig()},
		GuestCommand("tailscale status --json --peers=false"): {Stdout: []byte(`{"BackendState":"Running","Version":"1.102.3","TUN":true,"Self":{"Online":true,"PrimaryRoutes":["10.10.0.0/16"]}}`)},
		GuestCommand("tailscale debug prefs"):                 {Stdout: []byte(`{"AdvertiseRoutes":["10.10.0.0/16"],"NoSNAT":false,"RouteAll":false,"CorpDNS":false,"ExitNodeID":"","ExitNodeIP":"","WantRunning":true,"RunSSH":false}`)},
	}}
	status, err := ReadStatus(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != Healthy || status.Detail == "" {
		t.Fatalf("status = %s %q", status.State, status.Detail)
	}
	f.outputs[GuestCommand("tailscale debug prefs")] = controllerhost.Result{Stdout: []byte(`{"AdvertiseRoutes":["10.10.0.0/16"],"RouteAll":false}`)}
	status, err = ReadStatus(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != Failed {
		t.Fatalf("missing prefs state = %s, want failed", status.State)
	}
}

func TestGuestCommandDoesNotExposeAuthKeyAndQuotesTrap(t *testing.T) {
	command := GuestCommand("set -eu; trap 'rm -f /run/boetticher-tailnet-auth.XXXXXX' EXIT; printf %s 'a'\"'\"'b'")
	if strings.Contains(command, "auth-key=SECRET") || !strings.Contains(command, "trap") || !strings.Contains(command, "rm -f /run/boetticher-tailnet-auth") {
		t.Fatalf("unsafe bootstrap command = %s", command)
	}
}
