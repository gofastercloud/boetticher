package observability

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

type collectionRunner struct {
	calls       []string
	guestConfig string
}

func (r *collectionRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	if strings.HasPrefix(command, "pct config ") {
		return controllerhost.Result{Stdout: []byte(r.guestConfig)}, nil
	}
	return controllerhost.Result{}, nil
}

func (r *collectionRunner) RunWithStdin(_ context.Context, command string, input io.Reader) (controllerhost.Result, error) {
	r.calls = append(r.calls, command)
	_, _ = io.Copy(io.Discard, input)
	return controllerhost.Result{}, nil
}

func TestReconcileCollectionStagesConfigHelperAndExecutesOwnedGuest(t *testing.T) {
	payload := t.TempDir()
	helper := filepath.Join(payload, "controller", "proxmox", "libexec")
	if err := os.MkdirAll(helper, 0755); err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(payload, "controller", "observability", "assets")
	if err := os.MkdirAll(assets, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helper, "boetticher-install-observability-collection"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assets, "catalog.json"), []byte(`{"node-exporter-amd64":{"url":"https://example.invalid/node-exporter.tar.gz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	binding, _ := BindingFor("observability")
	runner := &collectionRunner{guestConfig: "hostname: " + binding.Hostname + "\ntags: boetticher;managed;module-observability;boetticher-module-observability\nnet0: name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24\n"}
	local := &collectionRunner{}
	if err := (HostClient{Transport: runner, LocalRunner: local}).ReconcileCollection(context.Background(), binding, payload, "example.com", DefaultCollectionConfig()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) < 9 || len(local.calls) < 3 {
		t.Fatalf("collection sequence did not provision all target installers: host=%#v local=%#v", runner.calls, local.calls)
	}
	if !strings.Contains(runner.calls[0], "pct config 120") {
		t.Fatalf("runtime ownership was not checked before staging: %s", runner.calls[0])
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), CollectionConfigPath) {
		t.Fatalf("scrape config was not staged in owned guest: %v", runner.calls)
	}
	joined := strings.Join(append(append([]string(nil), runner.calls...), local.calls...), "\n")
	for _, required := range []string{"https://ingest.example.com:443", "--read-token-hash"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("collection dispatch missing %q: %s", required, joined)
		}
	}
	if !strings.Contains(joined, "--name 'proxmox-host' --address '10.10.99.5'") {
		t.Fatalf("collection dispatch did not preserve the canonical Proxmox management address: %s", joined)
	}
}

func TestReconcileCollectionRejectsInvalidDomainBeforeRemoteIO(t *testing.T) {
	runner := &collectionRunner{}
	binding, _ := BindingFor("observability")
	if err := (HostClient{Transport: runner}).ReconcileCollection(context.Background(), binding, t.TempDir(), "bad..domain", DefaultCollectionConfig()); err == nil {
		t.Fatal("invalid collection domain accepted")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("invalid collection domain caused remote calls: %#v", runner.calls)
	}
}

func TestReconcileCollectionRejectsForeignRuntimeBeforeAnyWrite(t *testing.T) {
	binding, _ := BindingFor("observability")
	payload := t.TempDir()
	helperPath := filepath.Join(payload, "controller", "proxmox", "libexec")
	assetsPath := filepath.Join(payload, "controller", "observability", "assets")
	if err := os.MkdirAll(helperPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(assetsPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helperPath, "boetticher-install-observability-collection"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetsPath, "catalog.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	runner := &collectionRunner{guestConfig: "hostname: foreign\ntags: unrelated\nnet0: name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24\n"}
	local := &collectionRunner{}
	if err := (HostClient{Transport: runner, LocalRunner: local}).ReconcileCollection(context.Background(), binding, payload, "example.com", DefaultCollectionConfig()); err == nil {
		t.Fatal("foreign runtime was accepted")
	}
	if len(runner.calls) != 1 || len(local.calls) != 0 {
		t.Fatalf("foreign runtime caused writes: host=%#v local=%#v", runner.calls, local.calls)
	}
}

func TestTeardownCollectionRemovesOnlyMarkedFiles(t *testing.T) {
	binding, _ := BindingFor("observability")
	runner := &collectionRunner{guestConfig: "hostname: " + binding.Hostname + "\ntags: boetticher;managed;module-observability;boetticher-module-observability\nnet0: name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24\n"}
	local := &collectionRunner{}
	if err := (HostClient{Transport: runner, LocalRunner: local}).TeardownCollection(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(append(runner.calls, local.calls...), "\n")
	if !strings.Contains(runner.calls[0], "pct config 120") || !strings.Contains(joined, "journal-upload.service") || !strings.Contains(joined, "journal-upload.key.pem") || strings.Contains(joined, "rm -rf /var/log") {
		t.Fatalf("collection teardown was not ownership-scoped: host=%#v local=%#v", runner.calls, local.calls)
	}
}
