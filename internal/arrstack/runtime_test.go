package arrstack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gofastercloud/boetticher/internal/clientservices"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateGuestConfigRequiresExactOwnedQEMUShape(t *testing.T) {
	config := map[string]string{
		"agent": "1", "cpu": GuestCPU, "boot": "order=scsi0", "cores": "4", "ide2": "boetticher-data:cloudinit",
		"memory": "8192", "name": GuestName, "net0": "virtio=" + GuestMAC + ",bridge=vmbr1,tag=20,firewall=1",
		"onboot": "0", "ostype": "l26", "scsi0": "boetticher-data:vm-290-disk-0,ssd=1,size=32G",
		"scsi1": "boetticher-data:vm-290-disk-1,format=raw,ssd=1,size=256G", "scsihw": "virtio-scsi-single",
		"serial0": "socket", "tags": "boetticher;managed;module;" + GuestOwnerTag,
		"ipconfig0": "ip=" + GuestAddress + "/24,gw=" + GuestGateway, "nameserver": GuestGateway,
	}
	if err := ValidateGuestConfig(config); err != nil {
		t.Fatalf("valid arrstack VM rejected: %v", err)
	}
	for name, value := range map[string]string{
		"wrong CPU":    "kvm64",
		"foreign disk": "other-storage:vm-290-disk-0,ssd=1,size=32G",
		"wrong bridge": "virtio=" + GuestMAC + ",bridge=vmbr0,tag=20,firewall=1",
		"wrong owner":  "boetticher;managed;module;boetticher-module-other",
	} {
		bad := cloneConfig(config)
		switch name {
		case "wrong CPU":
			bad["cpu"] = value
		case "foreign disk":
			bad["scsi0"] = value
		case "wrong bridge":
			bad["net0"] = value
		case "wrong owner":
			bad["tags"] = value
		}
		if err := ValidateGuestConfig(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestNewMediaGuestRequiresX8664V3HostFeatures(t *testing.T) {
	commandSource, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(commandSource)
	for _, feature := range []string{"avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe", "popcnt", "sse4_2", "xsave"} {
		if !strings.Contains(text, feature) {
			t.Fatalf("x86-64-v3 preflight missing %s", feature)
		}
	}
	if !strings.Contains(text, "requireGuestCPUFeatures(ctx, host)") {
		t.Fatal("new media guest creation does not run the CPU feature preflight")
	}
}

func TestGuestCPUFeatureParserAcceptsAbmAliasForLzcnt(t *testing.T) {
	flags := "flags : avx avx2 bmi1 bmi2 f16c fma abm movbe popcnt sse4_1 sse4_2 xsave"
	if !hasGuestCPUFeatures(flags) {
		t.Fatal("x86-64-v3 feature parser rejected the abm alias for lzcnt")
	}
	if hasGuestCPUFeatures(strings.Replace(flags, "abm", "", 1)) {
		t.Fatal("x86-64-v3 feature parser accepted missing lzcnt/abm")
	}
}

func TestMediaRuntimeRequiresDockerComposeBeforeAdapterTransfer(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "docker compose version >/dev/null") {
		t.Fatal("media runtime does not preflight Docker Compose")
	}
}

func TestMediaRuntimeRequiresGuestRenderNodeAndPropagatesVAAPIIdentity(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"/dev/dri/renderD128", "hardware-transcoding HOLD", "ARRSTACK_GPU_VENDOR=intel", "ARRSTACK_GPU_RENDER_GID", "ARRSTACK_GPU_VIDEO_GID"} {
		if !strings.Contains(text, required) {
			t.Fatalf("GPU contract missing %q", required)
		}
	}
	adapter, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-arrstack.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(adapter), `vendor: process.env.ARRSTACK_GPU_VENDOR === "intel" ? "intel" : "none"`) {
		t.Fatal("headless adapter does not fail closed to software transcoding")
	}
}

func TestMediaCategoryPathsAreReconciledIdempotently(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-arrstack.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"/api/v2/torrents/categories", "/api/v2/torrents/editCategory", "savePath: cat.savePath", "CATEGORIES"} {
		if !strings.Contains(text, required) {
			t.Fatalf("media category reconciliation missing %q", required)
		}
	}
}

func TestJellyfinAndJellyseerrStreamingFixesAreGenerated(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-arrstack.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"\"Authorization\": authHeader", "/api/v1/settings/network", "forceIpv4First: true"} {
		if !strings.Contains(text, required) {
			t.Fatalf("media streaming fix missing %q", required)
		}
	}
}

func TestJellyseerrReapplyUsesExistingAdminSession(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-arrstack.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"/api/v1/auth/jellyfin", "existingSession", "initialized !== false", "publicSettings.json"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Jellyseerr reapply fix missing %q", required)
		}
	}
}

func TestCaddyPersistenceAndDNSPropagationAreBuiltIntoHeadlessAdapter(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-arrstack.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"config/caddy-data", "dst: \"/data\"", "propagation_delay 30s", "propagation_timeout -1"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Caddy persistence/propagation contract missing %q", required)
		}
	}
}

func TestApplyChecksAdapterBytesBeforeHealthyRuntimeNoOp(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "cli", "arrstack.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "arrstack.AdapterBytesAgree(ctx, sc.Host)") {
		t.Fatal("arrstack apply can report a healthy no-op without checking adapter bytes")
	}
	if !strings.Contains(text, "verify arrstack adapter bytes") {
		t.Fatal("adapter agreement errors are not surfaced by arrstack apply")
	}
}

func TestMediaApplyOwnsAutomaticObservabilityReconciliation(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "cli", "arrstack.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Count(text, "reconcileMediaMonitoring(ctx, sc, proposed, out)") != 2 {
		t.Fatal("media apply does not reconcile monitoring on both normal and healthy no-op paths")
	}
	for _, required := range []string{"ReconcileGuestWithTLS", "MEDIA monitoring: reconciled"} {
		if !strings.Contains(text, required) {
			t.Fatalf("automatic media monitoring reconciliation missing %q", required)
		}
	}
}

func TestMediaDockerDependsOnFailClosedFirewallPolicy(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{"docker.service.d/boetticher-arrstack-firewall.conf", "Requires=boetticher-arrstack-firewall.service", "After=boetticher-arrstack-firewall.service", "systemctl enable docker.service"} {
		if !strings.Contains(text, want) {
			t.Fatalf("Docker recovery dependency missing %q", want)
		}
	}
	if strings.Contains(text, "Requires=docker.service") {
		t.Fatal("firewall policy must not require Docker")
	}
}

func TestGuestExecCommandsHaveBoundedNativeTimeouts(t *testing.T) {
	if !strings.Contains(guestExec("true"), "--synchronous 1 --timeout 30 --") {
		t.Fatal("short guest exec is not bounded")
	}
	if !strings.Contains(guestExecWithTimeout("true", GuestInstallTimeout), "--synchronous 1 --timeout 1200 --") {
		t.Fatal("installer guest exec does not use the 20-minute timeout")
	}
	if strings.Contains(guestExecWithTimeout("true", GuestInstallTimeout), "--synchronous 1 --pass-stdin") {
		t.Fatal("timeout helper unexpectedly implies stdin")
	}
}

func TestInstallerGuardRefusesOverlapAndBoundsChildTermination(t *testing.T) {
	command := installerGuardCommand("sleep 120", GuestInstallTimeout)
	for _, want := range []string{"flock -n /run/boetticher/arrstack-install.lock", "timeout --signal TERM --kill-after 30s 1200s", "sh -c"} {
		if !strings.Contains(command, want) {
			t.Fatalf("installer guard missing %q", want)
		}
	}
}

func TestInstallerTimeoutLeavesCleanupMarginAndCapsAtTwentyMinutes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	seconds, err := installerTimeoutSeconds(ctx)
	if err != nil || seconds < 525 || seconds > 545 {
		t.Fatalf("installer timeout = %d, err=%v; want about 540 seconds", seconds, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := installerTimeoutSeconds(ctx); err == nil {
		t.Fatal("installer timeout accepted a deadline without cleanup margin")
	}
}

func TestInstallerGuardLinuxBehavior(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker is unavailable")
	}
	const script = `set -eu
lock=/tmp/boetticher-installer.lock
flock -n "$lock" sh -c 'sleep 2' & first=$!
sleep .1
if flock -n "$lock" true; then exit 11; fi
wait "$first"
if timeout --signal TERM --kill-after 1s 1s sh -c 'trap "" TERM; while :; do :; done'; then exit 12; else status=$?; fi
test "$status" = 124 || test "$status" = 137
`
	cmd := exec.Command("docker", "run", "--rm", "--platform", "linux/amd64", "debian:13-slim", "sh", "-ec", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Linux installer guard behavior failed: %v: %s", err, output)
	}
}

func TestValidateGuestConfigRejectsUnknownConfigAndMissingMediaDisk(t *testing.T) {
	config := map[string]string{"name": GuestName, "scsi0": "boetticher-data:vm-290-disk-0,size=32G", "scsi1": "boetticher-data:vm-290-disk-1,size=256G"}
	config["unexpected"] = "foreign"
	if err := ValidateGuestConfig(config); err == nil {
		t.Fatal("unknown VM configuration was accepted")
	}
}

func TestRecoverableGuestAcceptsOnlyAnExactOwnedInterruptedImport(t *testing.T) {
	config := map[string]string{
		"agent": "1", "cpu": GuestCPU, "boot": "order=scsi0", "cores": "4", "ide2": "boetticher-data:cloudinit",
		"memory": "8192", "name": GuestName, "net0": "virtio=" + GuestMAC + ",bridge=vmbr1,tag=20,firewall=1",
		"onboot": "0", "ostype": "l26", "scsihw": "virtio-scsi-single", "serial0": "socket",
		"tags":      "boetticher;managed;module;" + GuestOwnerTag,
		"ipconfig0": "ip=" + GuestAddress + "/24,gw=" + GuestGateway, "nameserver": GuestGateway,
		"unused0": "boetticher-data:vm-290-disk-0",
	}
	if err := ValidateRecoverableGuestConfigForSize(config, MediaDiskGiB); err != nil {
		t.Fatalf("owned interrupted import rejected: %v", err)
	}
	if command := recoveryCommand(config, MediaDiskGiB); strings.Contains(command, "qm importdisk") {
		t.Fatal("recovery would import a second root instead of attaching the inspected owned unused root")
	}
	config["unused1"] = "other-data:vm-290-disk-1"
	if err := ValidateRecoverableGuestConfigForSize(config, MediaDiskGiB); err == nil {
		t.Fatal("unknown unused volume was accepted for recovery")
	}
}

func TestRuntimeProbeDoesNotTreatDeadServiceMarkersAsHealthy(t *testing.T) {
	if docker, app := parseRuntimeProbe("DOCKER_READY\nAPP_STATE_READY\nPOLICY_READY\nCADDY_TLS_READY\n"); !docker || app {
		t.Fatalf("dead service probe = docker=%v app=%v, want true false", docker, app)
	}
	if docker, app := parseRuntimeProbe("DOCKER_READY\nAPP_READY\nPOLICY_READY\nCADDY_TLS_READY\n"); !docker || !app {
		t.Fatalf("complete runtime probe = docker=%v app=%v, want true true", docker, app)
	}
}

func TestRuntimeProbeUsesConfiguredPeerPortAndExpectedServices(t *testing.T) {
	probe := runtimeProbeCommandWithConfig(40000, clientservices.MediaConfig{ApplicationDomain: "media.example.net", Aliases: clientservices.MediaAliases{Radarr: "movies"}})
	for _, want := range []string{"docker-compose.yml", "for expectation in caddy=ghcr.io/lavx/arrstack-caddy@sha256:d1c594877aa8f9f79f8fc10bb13c854a1f2219e54422fb3abc4dc3f845aaadd7 qbittorrent=", "ai-subtitle-translator", "recyclarr", "test \"$image\" = \"$expected\"", "caddy adapt", "--resolve 'movies.media.example.net':443:10.10.20.230", GuestPolicyReceipt, "test \"$recorded_rules\" = \"$actual_rules\"", "test \"$recorded_script\" = \"$actual_script\""} {
		if !strings.Contains(probe, want) {
			t.Fatalf("runtime probe missing %q", want)
		}
	}
	if strings.Contains(probe, "curl -k") || strings.Contains(probe, "media.example.com:443:127.0.0.1") {
		t.Fatal("runtime probe bypasses TLS or probes the wildcard apex on loopback")
	}
}

func TestRuntimeProbeUsesMonitoringPolicyIntent(t *testing.T) {
	config := clientservices.MediaConfig{ApplicationDomain: "media.example.net", Aliases: clientservices.MediaAliases{Radarr: "movies"}}
	disabled := runtimeProbeCommandWithConfigAndMonitoring(35796, config, false)
	enabled := runtimeProbeCommandWithConfigAndMonitoring(35796, config, true)
	if disabled == enabled || !strings.Contains(enabled, shellQuote(mustPolicyHash(35796, true))) {
		t.Fatal("monitoring runtime probe did not bind its policy intent")
	}
	if strings.Contains(disabled, shellQuote(mustPolicyHash(35796, true))) {
		t.Fatal("non-monitoring runtime probe unexpectedly includes monitoring policy")
	}
}

func mustPolicy(peerPort int, monitoring bool) string {
	policy, err := GuestPolicyScript(peerPort, monitoring)
	if err != nil {
		panic(err)
	}
	return policy
}

func mustPolicyHash(peerPort int, monitoring bool) string {
	digest := sha256.Sum256([]byte(mustPolicy(peerPort, monitoring)))
	return hex.EncodeToString(digest[:])
}

func TestPolicyReceiptCaptureAndProbeBindTheInstalledScriptAndRules(t *testing.T) {
	capture := policyReceiptCaptureCommand()
	for _, want := range []string{GuestPolicyPath, GuestPolicyReceipt, "nft --stateless list table inet boetticher_arrstack", "iptables -S DOCKER-USER", "iptables -S FORWARD", "grep -Fx -- '-A FORWARD -j DOCKER-USER'", "mv -f"} {
		if !strings.Contains(capture, want) {
			t.Fatalf("receipt capture missing %q", want)
		}
	}
	probe := policyAgreementCommand(35796)
	for _, want := range []string{GuestPolicyReceipt, GuestPolicyPath, "test -f", "test ! -L", "actual_script=", "recorded_script=", "actual_rules=", "recorded_rules=", "test \"$recorded_rules\" = \"$actual_rules\""} {
		if !strings.Contains(probe, want) {
			t.Fatalf("policy agreement probe missing %q", want)
		}
	}
	if strings.Contains(probe, "|| true") || strings.Contains(capture, "|| true") {
		t.Fatal("policy receipt commands conceal a failed rule inspection")
	}
}

func TestPolicyReceiptPersistsAcrossBootWhileScratchIsRuntimeOwned(t *testing.T) {
	unit, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	if !strings.Contains(text, "RuntimeDirectory=boetticher/arrstack") {
		t.Fatal("policy service does not recreate its runtime scratch directory")
	}
	if !strings.Contains(text, "GuestPolicyReceipt   = \"/var/lib/boetticher/arrstack/policy-receipt\"") {
		t.Fatal("policy receipt is still stored in volatile /run")
	}
	capture := policyReceiptCaptureCommand()
	if !strings.Contains(capture, "mktemp /var/lib/boetticher/arrstack/policy.XXXXXX") || !strings.Contains(capture, "mv -f") {
		t.Fatal("persistent policy receipt is not written atomically in its destination directory")
	}
}

func TestPolicyReceiptIsCapturedOnlyAfterTheInstallerSucceeds(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	installer := strings.Index(text, "if err := guestExecLongJSON(ctx, host, installerGuardCommand(command, installTimeout), installTimeout+35); err != nil {")
	capture := strings.Index(text, "if err := guestExecJSON(ctx, host, policyReceiptCaptureCommand()); err != nil {")
	if installer < 0 || capture < installer {
		t.Fatalf("policy receipt capture must follow successful adapter installation: installer=%d capture=%d", installer, capture)
	}
}

func TestPolicyInstallDoesNotAddAHashChangingBlankLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy")
	policy := "#!/bin/sh\nprintf test\n"
	command := "cat > " + shellQuote(path) + " <<'ARRSTACK_POLICY'\n" + policyHeredoc(policy) + "sha256sum " + shellQuote(path)
	output, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(policy))
	if got := strings.Fields(string(output))[0]; got != hex.EncodeToString(want[:]) {
		t.Fatalf("rendered policy hash = %s, want %s", got, hex.EncodeToString(want[:]))
	}
}

func TestPolicyReapplyRestartsAlreadyActiveRemainAfterExitUnit(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	reload := strings.Index(text, "systemctl daemon-reload; systemctl enable boetticher-arrstack-firewall.service;")
	restart := strings.Index(text, "systemctl restart boetticher-arrstack-firewall.service;")
	startDocker := strings.Index(text, "systemctl start docker;")
	if reload < 0 || restart < reload || startDocker < restart {
		t.Fatalf("policy installation must reload, explicitly restart the policy unit, then start Docker: reload=%d restart=%d docker=%d", reload, restart, startDocker)
	}
	if strings.Contains(text, "systemctl enable --now boetticher-arrstack-firewall.service") {
		t.Fatal("policy installation relies on enable --now for a RemainAfterExit unit")
	}
}

func TestCloudflareTokenStagingUsesPrivateAtomicTemporaryFile(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{"mktemp /run/boetticher-cloudflare-token.XXXXXX", "chmod 0600", "trap 'rm -f \\\"$tmp\\\"'", "CF_API_TOKEN=\\\"$(cat \\\"$tmp\\\")\\\""} {
		if !strings.Contains(text, want) {
			t.Fatalf("private token staging missing %q", want)
		}
	}
}

func TestMediaFormattingRequiresPendingMarkerAndBlankOwnedDisk(t *testing.T) {
	format := mediaMountScript(true)
	for _, want := range []string{"wipefs -n", "cmp -n 1048576", "mkfs.ext4 -F"} {
		if !strings.Contains(format, want) {
			t.Fatalf("pending media preparation missing %q", want)
		}
	}
	if strings.Contains(mediaMountScript(false), "mkfs.ext4") {
		t.Fatal("existing media preparation may not format an unmarked disk")
	}
	command := recoveryCommand(map[string]string{
		"agent": "1", "cpu": GuestCPU, "boot": "order=scsi0", "cores": "4", "ide2": "boetticher-data:cloudinit",
		"memory": "8192", "name": GuestName, "net0": "virtio=" + GuestMAC + ",bridge=vmbr1,tag=20,firewall=1",
		"onboot": "0", "ostype": "l26", "scsihw": "virtio-scsi-single", "serial0": "socket",
		"tags":      "boetticher;managed;module;" + GuestOwnerTag,
		"ipconfig0": "ip=" + GuestAddress + "/24,gw=" + GuestGateway, "nameserver": GuestGateway,
		"scsi0": "boetticher-data:vm-290-disk-0,ssd=1,size=32G",
	}, MediaDiskGiB)
	guard := strings.Index(command, "case \";$tags;\"")
	attach := strings.Index(command, "qm set 290 --scsi1")
	if !strings.Contains(command, GuestMediaPendingTag) || guard < 0 || attach < 0 || guard > attach {
		t.Fatalf("unmarked media allocation is not guarded before attachment: guard=%d attach=%d command=%s", guard, attach, command)
	}
	if failure := strings.Index(command[guard:attach], "exit 1"); failure < 0 {
		t.Fatal("unmarked media allocation has no failing guard branch")
	}
}

func TestMediaPreparationUsesPathNeutralGuestAgentCheck(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "command -v qemu-ga >/dev/null") {
		t.Fatal("media preparation does not use a path-neutral qemu-agent check")
	}
	if strings.Contains(text, "test -x /usr/bin/qemu-ga") {
		t.Fatal("media preparation relies on a distro-specific qemu-agent path")
	}
}

func TestAdapterTransferDoesNotChangeRunPermissions(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, "chmod 0700 /run") || strings.Contains(text, "install -d -m 0700 /run\"") {
		t.Fatal("adapter transfer changes /run permissions")
	}
	for _, want := range []string{"/run/boetticher/arrstack-transfer", "rmdir \"+transferDir", "context.WithTimeout(context.Background(), 15*time.Second)", "cleanup guest adapter transfer", "stat -c '%u %a'", "sha256sum \"+shellQuote(GuestAdapterPath)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("adapter transfer missing bounded cleanup %q", want)
		}
	}
}

func TestAdapterTransferUsesMeasuredChunkBoundAndRetainsSizeChecksumGuards(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "const chunkSize = 512 << 10") {
		t.Fatal("adapter transfer does not use the measured 512 KiB RPC chunk")
	}
	for _, want := range []string{"info.Size() > 256<<20", "sha256.New()", "adapter checksum changed during guest transfer"} {
		if !strings.Contains(text, want) {
			t.Fatalf("adapter transfer guard missing %q", want)
		}
	}
}

func TestMediaBlankCheckAcceptsOnlyBoundedZeroDevice(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{
		"blkid":  "#!/bin/sh\nexit 2\n",
		"wipefs": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name string
		data []byte
		pass bool
	}{
		{name: "exact zero", data: make([]byte, 1<<20), pass: true},
		{name: "nonzero", data: append([]byte{1}, make([]byte, (1<<20)-1)...), pass: false},
		{name: "short", data: make([]byte, 1<<19), pass: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "disk")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			command := "set -eu; device=" + shellQuote(path) + "; " + mediaBlankCheckCommand("\"$device\"")
			cmd := exec.Command("sh", "-c", command)
			cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
			err := cmd.Run()
			if (err == nil) != tc.pass {
				t.Fatalf("blank check error=%v, pass=%v", err, tc.pass)
			}
		})
	}
	badBin := t.TempDir()
	for name, body := range map[string]string{
		"blkid":  "#!/bin/sh\nexit 2\n",
		"wipefs": "#!/bin/sh\nexit 7\n",
	} {
		if err := os.WriteFile(filepath.Join(badBin, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "set -eu; device="+shellQuote(path)+"; "+mediaBlankCheckCommand("\"$device\""))
	cmd.Env = append(os.Environ(), "PATH="+badBin+":/usr/bin:/bin")
	if cmd.Run() == nil {
		t.Fatal("wipefs error was treated as a blank disk")
	}
}

func TestMediaFormatDoesNotReformatExistingFilesystem(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "blkid"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	called := filepath.Join(t.TempDir(), "called")
	if err := os.WriteFile(filepath.Join(bin, "mkfs.ext4"), []byte("#!/bin/sh\nprintf called >\"$MKFS_CALLED\"\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "device=/dev/owned; "+mediaFormatCommand("\"$device\""))
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "MKFS_CALLED="+called)
	if err := cmd.Run(); err != nil {
		t.Fatalf("existing filesystem formatting failed: %v", err)
	}
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatalf("existing filesystem invoked mkfs: stat error=%v", err)
	}
}

func TestMediaFormatFormatsVerifiedBlankDiskOnce(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{
		"blkid":     "#!/bin/sh\nexit 2\n",
		"wipefs":    "#!/bin/sh\nexit 0\n",
		"mkfs.ext4": "#!/bin/sh\nprintf called >\"$MKFS_CALLED\"\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0600); err != nil {
		t.Fatal(err)
	}
	called := filepath.Join(t.TempDir(), "called")
	cmd := exec.Command("sh", "-c", "device="+shellQuote(path)+"; "+mediaFormatCommand("\"$device\""))
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "MKFS_CALLED="+called)
	if err := cmd.Run(); err != nil {
		t.Fatalf("verified blank formatting failed: %v", err)
	}
	if _, err := os.Stat(called); err != nil {
		t.Fatalf("verified blank disk did not invoke mkfs: %v", err)
	}
}

func TestMediaMountReadbackRequiresExactMountpointUUID(t *testing.T) {
	bin := t.TempDir()
	findmnt := filepath.Join(bin, "findmnt")
	if err := os.WriteFile(findmnt, []byte("#!/bin/sh\ncase \"$*\" in *--mountpoint*/var/lib/arrstack/media*) ;; *) exit 7;; esac\nprintf '%s\\n' \"$FINDMNT_UUID\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		got  string
		pass bool
	}{
		{name: "unmounted directory", got: "", pass: false},
		{name: "correct mount", got: "uuid-good", pass: true},
		{name: "wrong mount", got: "uuid-foreign", pass: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", mediaMountUUIDCheckCommand("uuid-good"))
			cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "FINDMNT_UUID="+tc.got)
			if (cmd.Run() == nil) != tc.pass {
				t.Fatalf("mount UUID %q pass=%v, want %v", tc.got, tc.pass, tc.pass)
			}
		})
	}
}

func TestRuntimeProbeChecksQBitTorrentListenerPreferencesAndPublishedBindings(t *testing.T) {
	probe := runtimeProbeCommand(40000)
	for _, want := range []string{"docker port", "40000/tcp", "40000/udp", "/proc/net/tcp", "/proc/net/udp", "set -eu; hex=", "Connection\\PortRangeMin=40000", "Connection\\PortRangeMax=40000"} {
		if !strings.Contains(probe, want) {
			t.Fatalf("runtime probe missing qBittorrent readiness check %q", want)
		}
	}
}

func TestQBitSocketReadinessFailuresPropagate(t *testing.T) {
	tests := []struct {
		name string
		tcp  string
		udp  string
		pass bool
	}{
		{name: "both listeners", tcp: "  0: 00000000:9C40 00000000:0000 0A\n", udp: "  0: 00000000:9C40 00000000:0000 07\n", pass: true},
		{name: "missing tcp", udp: "  0: 00000000:9C40 00000000:0000 07\n", pass: false},
		{name: "missing udp", tcp: "  0: 00000000:9C40 00000000:0000 0A\n", pass: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tcpPath, udpPath := filepath.Join(t.TempDir(), "tcp"), filepath.Join(t.TempDir(), "udp")
			if err := os.WriteFile(tcpPath, []byte(tc.tcp), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(udpPath, []byte(tc.udp), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", "set -eu; "+qbitSocketReadinessCommandForPaths(40000, tcpPath, udpPath)+"; true")
			if (cmd.Run() == nil) != tc.pass {
				t.Fatalf("socket readiness pass=%v, want %v", tc.pass, tc.pass)
			}
		})
	}
}

func TestPolicyAgreementRunsWithErrexitInsideReadinessCondition(t *testing.T) {
	probe := runtimeProbeCommand(40000)
	if !strings.Contains(probe, "if sh -ec ") {
		t.Fatal("policy agreement is not isolated in an explicit errexit shell")
	}
}

func TestRetainedCaddyCredentialProbeDistinguishesPresentFromMissingWithoutReadingToken(t *testing.T) {
	if !parseRetainedCredentialProbe("present") || parseRetainedCredentialProbe("missing") {
		t.Fatal("retained credential probe did not distinguish present from missing")
	}
	probe := retainedCredentialProbeCommand()
	for _, want := range []string{"test -s", "stat -c %a", "grep -q"} {
		if !strings.Contains(probe, want) {
			t.Fatalf("credential probe missing %q", want)
		}
	}
}

func cloneConfig(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
