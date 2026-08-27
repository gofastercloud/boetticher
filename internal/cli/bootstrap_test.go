package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

func TestApplianceBuildSourceRootIsIndependentOfCallerDirectory(t *testing.T) {
	root, err := applianceBuildSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"scripts/build-images.sh", "scripts/scan-images.sh", "images/base/debian.yaml"} {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			t.Fatalf("build source root %q is missing %s: %v", root, relative, err)
		}
	}
}

func TestHonorRequestedPhysicalModeKeepsFreshVirtualOnlySiteUnclaimed(t *testing.T) {
	discovery := networkmodel.Discovery{
		Mode:        networkmodel.ModePhysicalTrunk,
		Status:      "PASS",
		Explanation: "one candidate",
		Trunk:       &networkmodel.Interface{Name: "enp5s0"},
	}
	got := honorRequestedPhysicalMode(discovery, model.ModeVirtualOnly, "", "")
	if got.Mode != networkmodel.ModeVirtualOnly || got.Trunk != nil || got.Status != "PASS" {
		t.Fatalf("fresh virtual-only mode claimed a trunk: %#v", got)
	}
	if got.Explanation == "" {
		t.Fatal("virtual-only decision lacks an operator-facing explanation")
	}
}

func TestHonorRequestedPhysicalModeAllowsExplicitTrunkSelection(t *testing.T) {
	discovery := networkmodel.Discovery{
		Mode:  networkmodel.ModePhysicalTrunk,
		Trunk: &networkmodel.Interface{Name: "enp5s0"},
	}
	got := honorRequestedPhysicalMode(discovery, model.ModeVirtualOnly, "", "enp5s0")
	if got.Mode != networkmodel.ModePhysicalTrunk || got.Trunk == nil || got.Trunk.Name != "enp5s0" {
		t.Fatalf("explicit trunk selection was discarded: %#v", got)
	}
}

func TestCreateBuilderKnownHostsUsesPrivateEphemeralFile(t *testing.T) {
	name, err := createBuilderKnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(name)
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("builder known_hosts mode = %o, want 600", info.Mode().Perm())
	}
	if strings.Contains(name, "boetticher") == false {
		t.Fatalf("builder known_hosts does not use the bounded temporary name: %s", name)
	}
}

func TestPersistBuilderDiagnosticsIsBoundedAndPrivate(t *testing.T) {
	runner := &diagnosticRunner{output: []byte(strings.Repeat("diagnostic ", maxBuilderDiagnosticOutput))}
	directory := t.TempDir()
	if err := persistBuilderDiagnostics(context.Background(), runner, "192.0.2.10", "labadmin", directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "generated", "runtime", "builder-failure.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxBuilderDiagnosticOutput*9+4096 {
		t.Fatalf("builder diagnostics were not bounded: %d bytes", len(data))
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("builder diagnostic permissions = %v %o", err, info.Mode().Perm())
	}
}

func TestPersistBuilderUnavailableDiagnosticsRecordsEarlyFailure(t *testing.T) {
	directory := t.TempDir()
	if err := persistBuilderUnavailableDiagnostics(directory, context.DeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "generated", "runtime", "builder-failure.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "unavailable before a guest address was observed") || !strings.Contains(string(data), "context deadline exceeded") {
		t.Fatalf("early builder failure evidence is incomplete: %s", data)
	}
}

type diagnosticRunner struct {
	output []byte
}

func (r *diagnosticRunner) Run(context.Context, string, string, string) ([]byte, error) {
	return r.output, nil
}
