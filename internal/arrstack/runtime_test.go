package arrstack

import (
	"os"
	"strings"
	"testing"
)

func TestValidateGuestConfigRequiresExactOwnedQEMUShape(t *testing.T) {
	config := map[string]string{
		"agent": "1", "boot": "order=scsi0", "cores": "4", "ide2": "boetticher-data:cloudinit",
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
		"foreign disk": "other-storage:vm-290-disk-0,ssd=1,size=32G",
		"wrong bridge": "virtio=" + GuestMAC + ",bridge=vmbr0,tag=20,firewall=1",
		"wrong owner":  "boetticher;managed;module;boetticher-module-other",
	} {
		bad := cloneConfig(config)
		switch name {
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

func TestValidateGuestConfigRejectsUnknownConfigAndMissingMediaDisk(t *testing.T) {
	config := map[string]string{"name": GuestName, "scsi0": "boetticher-data:vm-290-disk-0,size=32G", "scsi1": "boetticher-data:vm-290-disk-1,size=256G"}
	config["unexpected"] = "foreign"
	if err := ValidateGuestConfig(config); err == nil {
		t.Fatal("unknown VM configuration was accepted")
	}
}

func TestRecoverableGuestAcceptsOnlyAnExactOwnedInterruptedImport(t *testing.T) {
	config := map[string]string{
		"agent": "1", "boot": "order=scsi0", "cores": "4", "ide2": "boetticher-data:cloudinit",
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
	probe := runtimeProbeCommand(40000)
	for _, want := range []string{"docker-compose.yml", "for expectation in caddy=ghcr.io/lavx/arrstack-caddy@sha256:d1c594877aa8f9f79f8fc10bb13c854a1f2219e54422fb3abc4dc3f845aaadd7 qbittorrent=", "ai-subtitle-translator", "recyclarr", "test \"$image\" = \"$expected\"", "caddy adapt", "--resolve oscar.davebarton.cc:443:10.10.20.230", GuestPolicyReceipt, "test \"$recorded_rules\" = \"$actual_rules\"", "test \"$recorded_script\" = \"$actual_script\""} {
		if !strings.Contains(probe, want) {
			t.Fatalf("runtime probe missing %q", want)
		}
	}
	if strings.Contains(probe, "curl -k") || strings.Contains(probe, "davebarton.cc:443:127.0.0.1") {
		t.Fatal("runtime probe bypasses TLS or probes the wildcard apex on loopback")
	}
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

func TestPolicyReceiptIsCapturedOnlyAfterTheInstallerSucceeds(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	installer := strings.Index(text, "if err := guestExecJSON(ctx, host, command); err != nil {")
	capture := strings.Index(text, "if err := guestExecJSON(ctx, host, policyReceiptCaptureCommand()); err != nil {")
	if installer < 0 || capture < installer {
		t.Fatalf("policy receipt capture must follow successful adapter installation: installer=%d capture=%d", installer, capture)
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

func TestMediaFormattingRequiresPendingMarkerAndBlankOwnedDisk(t *testing.T) {
	format := mediaMountScript(true)
	for _, want := range []string{"wipefs -n", "dd if=", "mkfs.ext4 -F"} {
		if !strings.Contains(format, want) {
			t.Fatalf("pending media preparation missing %q", want)
		}
	}
	if strings.Contains(mediaMountScript(false), "mkfs.ext4") {
		t.Fatal("existing media preparation may not format an unmarked disk")
	}
	command := recoveryCommand(map[string]string{
		"agent": "1", "boot": "order=scsi0", "cores": "4", "ide2": "boetticher-data:cloudinit",
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
