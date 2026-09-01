package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestBoundedBuilderArchiveRejectsOversizedReturn(t *testing.T) {
	var buffer bytes.Buffer
	writer := &boundedBuilderArchive{writer: &buffer, limit: 4}
	if _, err := writer.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("5")); err == nil {
		t.Fatal("oversized builder archive return was accepted")
	}
	if buffer.String() != "1234" {
		t.Fatalf("oversized builder archive changed output: %q", buffer.String())
	}
}

func TestBuilderFailureOutputPreservesBoundedCommandError(t *testing.T) {
	output := &boundedBuilderOutput{}
	output.Write([]byte("stdout\n"))
	got := builderFailureOutput(output, errors.New("SSH bootstrap command failed: artifact contains baked SSH host identity: /tmp/rootfs/etc/ssh/ssh_host_rsa_key"))
	if !strings.Contains(got, "[builder-command-error]") || !strings.Contains(got, "artifact contains baked SSH host identity") {
		t.Fatalf("builder command error was not preserved: %q", got)
	}
	if len(got) > maxBuilderDiagnosticOutput {
		t.Fatalf("builder command diagnostic exceeded bound: %d", len(got))
	}
}

func TestBuilderBuildCommandStreamsThePersistentLog(t *testing.T) {
	for _, required := range []string{"tail -n 0 -F /var/log/boetticher-build.log", "/usr/local/sbin/boetticher-build", "trap"} {
		if !strings.Contains(builderBuildCommand, required) {
			t.Fatalf("builder command does not contain %q: %s", required, builderBuildCommand)
		}
	}
}

func TestBuilderProgressWriterForwardsOnlySafeProgressLines(t *testing.T) {
	var output bytes.Buffer
	writer := &builderProgressWriter{out: &output}
	if _, err := writer.Write([]byte("package output\ntiming stage=artifact_build duration_ms=10 artifact=boetticher-base\nmeasurement stage=artifact_compression artifact=boetticher-base\nboetticher package stage: boetticher-base archive\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "package output") || !strings.Contains(output.String(), "timing stage=artifact_build") || !strings.Contains(output.String(), "measurement stage=artifact_compression") || !strings.Contains(output.String(), "boetticher package stage: boetticher-base archive") {
		t.Fatalf("builder progress output = %q", output.String())
	}
}

func TestEmitTransferMeasurementReportsBytesDurationAndThroughput(t *testing.T) {
	var output bytes.Buffer
	emitTransferMeasurement(&output, "builder_source_transfer", "gzip", 2048, time.Now().Add(-2*time.Second))
	line := output.String()
	for _, required := range []string{
		"measurement stage=builder_source_transfer",
		"transport=gzip",
		"bytes=2048",
		"duration_ms=",
		"throughput_bytes_per_second=",
	} {
		if !strings.Contains(line, required) {
			t.Fatalf("transfer measurement missing %q: %q", required, line)
		}
	}
}

func TestEmitTransferMeasurementRejectsInvalidInputs(t *testing.T) {
	var output bytes.Buffer
	emitTransferMeasurement(&output, "", "gzip", 1, time.Now())
	emitTransferMeasurement(&output, "stage", "", 1, time.Now())
	emitTransferMeasurement(&output, "stage", "gzip", -1, time.Now())
	emitTransferMeasurement(&output, "stage", "gzip", 1, time.Time{})
	if output.Len() != 0 {
		t.Fatalf("invalid transfer measurement was emitted: %q", output.String())
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

func TestBuilderArtifactReturnCommandKeepsGzipDefaultAndSupportsPlainBenchmark(t *testing.T) {
	defaultCommand, err := builderArtifactReturnCommand("")
	if err != nil || defaultCommand != "tar -czf - -C /home/labadmin/build generated/artifacts" {
		t.Fatalf("default builder return command = %q, %v", defaultCommand, err)
	}
	plainCommand, err := builderArtifactReturnCommand("plain")
	if err != nil || plainCommand != "tar -cf - -C /home/labadmin/build generated/artifacts" {
		t.Fatalf("plain builder return command = %q, %v", plainCommand, err)
	}
	if _, err := builderArtifactReturnCommand("unsupported"); err == nil {
		t.Fatal("unsupported builder return compression was accepted")
	}
}

func TestProxmoxCredentialsExistDistinguishesRetryState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "proxmox.sops.yaml")
	exists, err := proxmoxCredentialsExist(path)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("missing Proxmox credentials were treated as present")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("encrypted credentials"), 0o600); err != nil {
		t.Fatal(err)
	}
	exists, err = proxmoxCredentialsExist(path)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("stored Proxmox credentials were treated as missing")
	}
}

type diagnosticRunner struct {
	output []byte
}

func (r *diagnosticRunner) Run(context.Context, string, string, string) ([]byte, error) {
	return r.output, nil
}
