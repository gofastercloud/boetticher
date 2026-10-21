package firewallmodule

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func TestProviderStartupOrderedRequiresOrderOne(t *testing.T) {
	for startup, want := range map[string]bool{
		"order=1":        true,
		"order=1,up=60":  true,
		"up=30,order=1":  true,
		"1":              true,
		"":               false,
		"unset":          false,
		"order=10":       false,
		"order=2,down=1": false,
		"up=60":          false,
	} {
		if got := ProviderStartupOrdered(startup); got != want {
			t.Errorf("ProviderStartupOrdered(%q) = %v, want %v", startup, got, want)
		}
	}
	if !ProviderStartupOrdered(providerVMParams().Get("startup")) {
		t.Fatalf("API create params omit startup order: %v", providerVMParams())
	}
}

// fakeProviderHost scripts the Host SSH boundary for the owned provider. It
// records every remote command and applies the startup setter to the config.
func fakeProviderHost(t *testing.T, config string) (HostClient, func() []string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	configPath := write("config", config, 0600)
	if config == "" {
		write("absent", "", 0600)
	}
	absentPath := filepath.Join(dir, "absent")
	logPath := write("log", "", 0600)
	identity := write("identity", "", 0600)
	knownHosts := write("known_hosts", "", 0600)
	script := "#!/bin/sh\nfor arg; do command=$arg; done\nprintf '%s\\n' \"$command\" >> " + shellQuote(logPath) + "\ncase \"$command\" in\n" +
		"'set -eu; if qm status 280 '*) if [ -e " + shellQuote(absentPath) + " ]; then echo BOETTICHER_ABSENT; else printf 'BOETTICHER_QEMU\\nstatus: running\\n'; cat " + shellQuote(configPath) + "; fi;;\n" +
		"*\"qm create 280 \"*\"--onboot 1 --startup 'order=1' \"*) printf '%s' " + shellQuote(ownedProviderConfig+"startup: order=1\n") + " > " + shellQuote(configPath) + "; rm -f " + shellQuote(absentPath) + ";;\n" +
		shellQuote(ProviderStartupCommand()) + ") printf 'startup: order=1\\n' >> " + shellQuote(configPath) + ";;\n" +
		"*) echo unexpected-command >&2; exit 99;;\nesac\n"
	ssh := write("ssh", script, 0700)
	host := HostClient{CopyTo: func(context.Context, string, string) error { return nil }, Transport: controllerhost.Transport{Address: "10.10.99.5", User: "root", Identity: identity, KnownHosts: knownHosts, SSHPath: ssh, Timeout: 10 * time.Second}}
	return host, func() []string {
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

const ownedProviderConfig = "name: lab-firewall-01\nonboot: 1\ntags: boetticher;managed;module;boetticher-module-firewall\nnet0: virtio=02:00:00:04:00:01,bridge=vmbr0,firewall=1\nnet1: virtio=02:00:00:04:00:02,bridge=vmbr1,firewall=1\nscsi0: boetticher-data:vm-280-disk-0,size=1G\n"

func TestEnsureHostProviderSetsMissingStartupOrderOnExistingVM(t *testing.T) {
	host, commands := fakeProviderHost(t, ownedProviderConfig)
	result, err := EnsureHostProvider(context.Background(), host, "boetticher-data", Image{})
	if err != nil {
		t.Fatalf("apply: %v (commands %v)", err, commands())
	}
	if !result.Changed || result.Created {
		t.Fatalf("result = %+v, want changed existing provider", result)
	}
	setters := 0
	for _, command := range commands() {
		if command == "qm set 280 --startup 'order=1'" {
			setters++
		} else if !strings.HasPrefix(command, "set -eu; if qm status 280 ") {
			t.Errorf("unexpected mutation %q", command)
		}
	}
	if setters != 1 {
		t.Fatalf("startup setter ran %d times: %v", setters, commands())
	}
}

func TestEnsureHostProviderCreatesVMWithStartupOrder(t *testing.T) {
	host, commands := fakeProviderHost(t, "")
	result, err := EnsureHostProvider(context.Background(), host, "boetticher-data", Image{Path: "/nonexistent/image", Name: ProviderImage, SHA256: "abc"})
	if err != nil {
		t.Fatalf("create: %v (commands %v)", err, commands())
	}
	if !result.Created {
		t.Fatalf("result = %+v, want created", result)
	}
	for _, command := range commands() {
		if strings.HasPrefix(command, "qm set 280 --startup") {
			t.Fatalf("created VM needed a separate startup setter: %v", commands())
		}
	}
}

func TestEnsureHostProviderLeavesOrderedStartupUntouched(t *testing.T) {
	host, commands := fakeProviderHost(t, ownedProviderConfig+"startup: order=1,up=60\n")
	result, err := EnsureHostProvider(context.Background(), host, "boetticher-data", Image{})
	if err != nil || result.Changed {
		t.Fatalf("result=%+v err=%v commands=%v", result, err, commands())
	}
	for _, command := range commands() {
		if !strings.HasPrefix(command, "set -eu; if qm status 280 ") {
			t.Fatalf("no-op apply ran %q", command)
		}
	}
}

func TestProviderStatusReportsStartupDrift(t *testing.T) {
	if got := (Status{Startup: "order=1"}).StartupLabel(); got != "order=1" {
		t.Fatalf("ordered label = %q", got)
	}
	got := (Status{Startup: ProviderStartupObserved(HostProviderStatus{Config: ownedProviderConfig})}).StartupLabel()
	if !strings.Contains(got, "drift (observed unset, expected order=1)") || !strings.Contains(got, "module firewall apply") {
		t.Fatalf("drift label = %q", got)
	}
}
