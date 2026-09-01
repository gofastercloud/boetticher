package proxmox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
)

func TestFirewallCloudInitUsesStableInterfaceIdentities(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{
		{Name: "wan0", MAC: "02:00:00:00:01:01", Method: "dhcp"},
		{Name: "trusted0", MAC: "02:00:00:00:01:02", Method: "static", Address: "10.10.30.1"},
		{Name: "servers0", MAC: "02:00:00:00:01:03", Method: "static", Address: "10.10.20.1"},
		{Name: "sandbox0", MAC: "02:00:00:00:01:04", Method: "static", Address: "10.10.40.1"},
		{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"},
		{Name: "transit0", MAC: "02:00:00:00:01:06", Method: "static", Address: "10.10.5.1"},
		{Name: "infra0", MAC: "02:00:00:00:01:07", Method: "static", Address: "10.10.10.1"},
	}}
	files, err := RenderFirewallCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"set-name: wan0", "set-name: trusted0", "set-name: servers0", "set-name: sandbox0", "set-name: mgmt0", "set-name: transit0", "set-name: infra0", "net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0"} {
		if !strings.Contains(files.NetworkConfig+files.UserData, value) {
			t.Fatalf("cloud-init omitted %q", value)
		}
	}
	if strings.Contains(files.UserData, "ssh-ed25519") || strings.Contains(files.UserData, "password:") {
		t.Fatal("firewall cloud-init embedded operator or password material")
	}
	if strings.Contains(files.UserData, "sudo:") || strings.Contains(files.UserData, "groups: [sudo]") || !strings.Contains(files.UserData, "disable_root: true") {
		t.Fatalf("firewall cloud-init grants durable labadmin privilege: %s", files.UserData)
	}
}

func TestFirewallCloudInitInjectsOperatorKeyOnlyAtDeployment(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"}}}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator #1"
	files, err := RenderFirewallCloudInitWithKey(guest, key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files.UserData, "ssh_authorized_keys:") || !strings.Contains(files.UserData, key) {
		t.Fatalf("firewall bootstrap key was not injected into deployment-only NoCloud data: %s", files.UserData)
	}
	var document struct {
		Users       []any `yaml:"users"`
		DisableRoot bool  `yaml:"disable_root"`
	}
	if err := yaml.Unmarshal([]byte(files.UserData), &document); err != nil {
		t.Fatalf("firewall cloud-init is not valid YAML: %v", err)
	}
	found := false
	for _, rawUser := range document.Users {
		user, ok := rawUser.(map[string]any)
		if !ok || user["name"] != "labadmin" {
			continue
		}
		keys, ok := user["ssh_authorized_keys"].([]any)
		if !ok || len(keys) != 1 || keys[0] != key {
			t.Fatalf("firewall bootstrap key was not preserved as one YAML scalar: %#v", user["ssh_authorized_keys"])
		}
		found = true
		break
	}
	if !found {
		t.Fatal("firewall cloud-init does not configure labadmin")
	}
	if document.DisableRoot {
		t.Fatal("deployment cloud-init disables the temporary root transport")
	}
	rootFound := false
	for _, rawUser := range document.Users {
		user, ok := rawUser.(map[string]any)
		if !ok || user["name"] != "root" {
			continue
		}
		keys, ok := user["ssh_authorized_keys"].([]any)
		if !ok || len(keys) != 1 || keys[0] != key {
			t.Fatalf("temporary root key was not preserved as one YAML scalar: %#v", user["ssh_authorized_keys"])
		}
		rootFound = true
	}
	if !rootFound {
		t.Fatal("deployment cloud-init does not configure temporary root access")
	}
	if strings.Contains(files.MetaData+files.NetworkConfig, key) {
		t.Fatal("operator key leaked into unrelated NoCloud documents")
	}
}

func TestFirewallCloudInitRejectsInvalidOperatorKey(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"}}}
	if _, err := RenderFirewallCloudInitWithKey(guest, "not-a-key"); err == nil {
		t.Fatal("invalid operator key was accepted")
	}
}

func TestFirewallCloudInitDoesNotDuplicateStaticPrefixLength(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{
		{Name: "trusted0", MAC: "02:00:00:00:01:02", Method: "static", Address: "10.10.30.1"},
	}}
	files, err := RenderFirewallCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files.NetworkConfig, "addresses: [10.10.30.1/24]") || strings.Contains(files.NetworkConfig, "/24/24") {
		t.Fatalf("invalid static address rendered: %s", files.NetworkConfig)
	}
}

func TestFirewallCloudInitRejectsUnstableNICIdentity(t *testing.T) {
	if _, err := RenderFirewallCloudInit(GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{{Name: "wan0", Method: "dhcp"}}}); err == nil {
		t.Fatal("cloud-init accepted a NIC without a stable MAC")
	}
}

func TestFirewallCloudInitMountsDeclaredVolumesByStableDiskIdentity(t *testing.T) {
	guest := GuestPlan{
		Name: "lab-fw-01", Address: "10.10.99.1",
		NICs: []GuestNIC{{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"}},
		Volumes: []model.PersistentVolumeDeclaration{
			{Name: "ssh-identity", Module: "firewall", Guest: "lab-fw-01", MountPath: "/var/lib/boetticher/identity/ssh"},
			{Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", MountPath: "/var/lib/kea"},
			{Name: "firewall-telemetry", Module: "firewall", Guest: "lab-fw-01", MountPath: "/var/lib/boetticher/firewall-telemetry"},
		},
	}
	files, err := RenderFirewallCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(files.UserData, "fs_setup:") != 1 || strings.Count(files.UserData, "mounts:") != 1 {
		t.Fatalf("firewall cloud-init emitted duplicate storage sections: %s", files.UserData)
	}
	var document struct {
		FSSetup []struct {
			Label    string `yaml:"label"`
			Device   string `yaml:"device"`
			Override bool   `yaml:"overwrite"`
		} `yaml:"fs_setup"`
		Mounts [][]string `yaml:"mounts"`
	}
	if err := yaml.Unmarshal([]byte(files.UserData), &document); err != nil {
		t.Fatalf("firewall cloud-init is not valid YAML: %v", err)
	}
	if len(document.FSSetup) != 3 || len(document.Mounts) != 3 {
		t.Fatalf("unexpected persistent volume bootstrap: %#v", document)
	}
	if document.FSSetup[0].Label != "boetticher-ssh-identity" || document.FSSetup[1].Label != "boetticher-kea-leases" || document.FSSetup[2].Label != "boetticher-firewall-telemetry" {
		t.Fatalf("unexpected persistent volume labels: %#v", document.FSSetup)
	}
	if document.FSSetup[0].Device != "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1" {
		t.Fatalf("SSH identity device is not stable: %#v", document.FSSetup[0])
	}
	if document.Mounts[1][1] != "/var/lib/kea" || document.Mounts[1][3] != "defaults,nofail" {
		t.Fatalf("Kea volume mount is not explicit: %#v", document.Mounts[1])
	}
	if document.Mounts[2][1] != "/var/lib/boetticher/firewall-telemetry" || document.Mounts[2][3] != "defaults,nofail" {
		t.Fatalf("telemetry volume mount is not explicit: %#v", document.Mounts[2])
	}
}

func TestRenderBuilderCloudInitUsesPublicBuildInputsOnly(t *testing.T) {
	files := RenderBuilderCloudInit()
	for name, content := range map[string]string{"meta": files.MetaData, "user": files.UserData, "network": files.NetworkConfig} {
		if content == "" {
			t.Fatalf("builder %s cloud-init is empty", name)
		}
		if strings.Contains(content, "age1") || strings.Contains(content, "BEGIN PRIVATE KEY") || strings.Contains(content, "SOPS") {
			t.Fatalf("builder %s cloud-init contains secret authority material", name)
		}
	}
	if !strings.Contains(files.UserData, "boetticher-build") || !strings.Contains(files.UserData, "scripts/scan-images.sh scan-images") || !strings.Contains(files.UserData, "boetticher-builder-ready") || !strings.Contains(files.UserData, "ssh-keygen -A") {
		t.Fatal("builder cloud-init does not invoke the first-party build and qualification path")
	}
	if !strings.Contains(files.UserData, "./scripts/build-images.sh images image-base image-dns-blocky image-logging image-monitoring image-portal image-firewall") || !strings.Contains(files.UserData, "./scripts/scan-images.sh scan-images boetticher-base boetticher-dns-blocky boetticher-logging boetticher-monitoring boetticher-portal boetticher-firewall") {
		t.Fatalf("builder cloud-init does not select the default core artifact set: %s", files.UserData)
	}
	if strings.Contains(files.UserData, "image-tailnet-router") || strings.Contains(files.UserData, "image-litellm") {
		t.Fatal("default builder cloud-init selects disabled optional artifacts")
	}
	for _, required := range []string{
		"/usr/local/go/bin/go version",
		"go1.26.5.linux-amd64.tar.gz",
		"5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",
		"go version go1.26.5 linux/amd64",
	} {
		if !strings.Contains(files.UserData, required) {
			t.Fatalf("builder cloud-init does not pin and verify %q", required)
		}
	}
	for _, required := range []string{
		"BOETTICHER_CACHE_ROOT=/var/cache/boetticher",
		"GOCACHE=/var/cache/boetticher/go-build",
		"GOMODCACHE=/var/cache/boetticher/go-mod",
		"mkdir -p \"$BOETTICHER_CACHE_ROOT\"",
		"findmnt -n -o SOURCE --target \"$BOETTICHER_CACHE_ROOT\"",
		"HOLD: builder cache volume is not mounted",
		"LABEL=boetticher-builder-cache",
		"scsi-0QEMU_QEMU_HARDDISK_drive-scsi1",
	} {
		if !strings.Contains(files.UserData, required) {
			t.Fatalf("builder cloud-init does not configure persistent cache root %q", required)
		}
	}
	if strings.Contains(files.UserData, "package_update: true") || strings.Contains(files.UserData, "packages:") {
		t.Fatal("builder cloud-init uses unpinned cloud-init package installation")
	}
	if strings.Contains(files.UserData, "groups: [sudo]") || strings.Contains(files.UserData, "/etc/sudoers.d/boetticher-builder") {
		t.Fatal("builder cloud-init grants labadmin a root-capable sudo path")
	}
	for _, required := range []string{
		"https://snapshot.debian.org/archive/debian/20260825T000000Z/",
		"https://snapshot.debian.org/archive/debian-security/20260825T000000Z/",
		"apt-get -o Acquire::Check-Valid-Until=false update",
		"apt-get install --yes --no-install-recommends ca-certificates curl jq libguestfs-tools mmdebstrap",
	} {
		if !strings.Contains(files.UserData, required) {
			t.Fatalf("builder cloud-init does not pin package bootstrap input %q", required)
		}
	}
	if strings.Contains(files.UserData, "golang-go") {
		t.Fatal("builder cloud-init relies on an unqualified distro Go package")
	}
	if !strings.Contains(string(RenderBuilderCloudInit().UserData), "qemu-guest-agent") {
		t.Fatal("builder cloud-init does not enable the guest agent needed for address discovery")
	}
	if !strings.Contains(files.UserData, "qemu-guest-agent") || !strings.Contains(files.NetworkConfig, "dhcp4: true") || !strings.Contains(files.NetworkConfig, "macaddress: "+model.BuilderMAC) || !strings.Contains(files.NetworkConfig, "  ens18:") {
		t.Fatal("builder cloud-init lacks guest-agent or bootstrap network setup")
	}
	guestAgent := strings.Index(files.UserData, "- [systemctl, enable, --now, qemu-guest-agent]")
	goDownload := strings.Index(files.UserData, "archive=/tmp/go1.26.5.linux-amd64.tar.gz")
	if guestAgent < 0 || goDownload < 0 || guestAgent > goDownload {
		t.Fatal("builder cloud-init starts the guest agent after toolchain setup")
	}
	if !strings.Contains(files.UserData, "exec >/var/log/boetticher-build.log 2>&1") {
		t.Fatal("builder command does not retain bounded build diagnostics")
	}
	if !strings.Contains(files.UserData, "trivy_0.69.3_Linux-64bit.tar.gz") || !strings.Contains(files.UserData, "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75") {
		t.Fatal("builder cloud-init does not pin the Trivy qualification input")
	}
	for _, handoff := range []string{
		"chown -R labadmin:labadmin /home/labadmin/build/generated/artifacts",
		"find /home/labadmin/build/generated/artifacts -type d -exec chmod 0755 {} +",
		"find /home/labadmin/build/generated/artifacts -type f -exec chmod 0644 {} +",
	} {
		if !strings.Contains(files.UserData, handoff) {
			t.Fatalf("builder cloud-init does not make public qualification evidence retrievable: %q", handoff)
		}
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(files.UserData), &document); err != nil {
		t.Fatalf("builder cloud-init is not valid YAML: %v", err)
	}
	if _, ok := document["runcmd"]; !ok {
		t.Fatal("builder cloud-init has no runnable bootstrap commands")
	}
}

func TestRenderBuilderCloudInitWithKeyBootstrapsTemporaryRoot(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator #1"
	files, err := RenderBuilderCloudInitWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Users       []any `yaml:"users"`
		DisableRoot bool  `yaml:"disable_root"`
	}
	if err := yaml.Unmarshal([]byte(files.UserData), &document); err != nil {
		t.Fatalf("builder cloud-init is not valid YAML: %v", err)
	}
	var found bool
	for _, rawUser := range document.Users {
		user, ok := rawUser.(map[string]any)
		if !ok || user["name"] != "labadmin" {
			continue
		}
		found = true
		keys, ok := user["ssh_authorized_keys"].([]any)
		if !ok || len(keys) != 1 || keys[0] != key {
			t.Fatalf("labadmin bootstrap keys = %#v, want %q", user["ssh_authorized_keys"], key)
		}
	}
	if !found {
		t.Fatal("builder cloud-init does not explicitly configure labadmin")
	}
	if document.DisableRoot {
		t.Fatal("builder cloud-init disables the temporary root transport")
	}
	rootFound := false
	for _, rawUser := range document.Users {
		user, ok := rawUser.(map[string]any)
		if !ok || user["name"] != "root" {
			continue
		}
		keys, ok := user["ssh_authorized_keys"].([]any)
		if !ok || len(keys) != 1 || keys[0] != key {
			t.Fatalf("builder temporary root key = %#v, want %q", user["ssh_authorized_keys"], key)
		}
		rootFound = true
	}
	if !rootFound {
		t.Fatal("builder cloud-init does not explicitly configure temporary root access")
	}
	if strings.Contains(files.MetaData+files.NetworkConfig, key) {
		t.Fatal("builder operator key leaked into unrelated cloud-init documents")
	}
}

func TestRenderBuilderCloudInitWithKeyRejectsInvalidKey(t *testing.T) {
	if _, err := RenderBuilderCloudInitWithKey("not-a-key"); err == nil {
		t.Fatal("invalid builder operator key was accepted")
	}
}

func TestBuilderArtifactTargetsFollowResolvedPlan(t *testing.T) {
	plan := Plan{Guests: []GuestPlan{
		{Artifact: model.Artifact{Name: "boetticher-base"}},
		{Artifact: model.Artifact{Name: "boetticher-dns-blocky"}},
		{Artifact: model.Artifact{Name: "boetticher-logging"}},
		{Artifact: model.Artifact{Name: "boetticher-monitoring"}},
		{Artifact: model.Artifact{Name: "boetticher-portal"}},
		{Artifact: model.Artifact{Name: "boetticher-firewall"}},
	}}
	targets, err := builderArtifactTargets(plan)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"image-base", "image-dns-blocky", "image-logging", "image-monitoring", "image-firewall", "image-portal", "image-network-probe"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("builder targets = %#v, want %#v", targets, want)
	}
	scans, err := builderScanTargets(targets)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(scans, " "), "tailnet") || strings.Contains(strings.Join(scans, " "), "litellm") {
		t.Fatalf("disabled optional scans selected: %#v", scans)
	}
	if _, err := builderArtifactTargets(Plan{Guests: []GuestPlan{{Name: "unknown", Artifact: model.Artifact{Name: "unknown"}}}}); err == nil {
		t.Fatal("unknown builder artifact was accepted")
	}
}

func TestBuilderArtifactTargetsForMissingSkipsQualifiedArtifacts(t *testing.T) {
	root := t.TempDir()
	base := mustQualifiedTestArtifact(t, root, "base")
	probe := mustQualifiedTestArtifact(t, root, "network-probe")
	dns, err := artifacts.ArtifactFor("dns")
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{Guests: []GuestPlan{
		{Artifact: base},
		{Artifact: dns},
	}}
	targets, err := BuilderArtifactTargetsForMissing(root, plan)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"image-base", "image-dns-blocky"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("missing builder targets = %#v, want %#v", targets, want)
	}

	plan.Guests = append(plan.Guests, GuestPlan{Artifact: probe})
	plan.Guests[1].Artifact = mustQualifiedTestArtifact(t, root, "dns")
	targets, err = BuilderArtifactTargetsForMissing(root, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("fully cached builder targets = %#v, want none", targets)
	}
	if err := os.Remove(artifacts.EvidencePath(root, base.Name)); err != nil {
		t.Fatal(err)
	}
	targets, err = BuilderArtifactTargetsForMissing(root, plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(targets, ",") != "image-base" {
		t.Fatalf("missing base builder targets = %#v, want image-base", targets)
	}
}

func mustQualifiedTestArtifact(t *testing.T, root, module string) model.Artifact {
	t.Helper()
	artifact, err := artifacts.ArtifactFor(module)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "generated", "artifacts", artifact.Name, "artifact.bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(module+" cached artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := artifacts.EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	trivyPath := filepath.Join(filepath.Dir(path), "trivy.json")
	if err := os.WriteFile(trivyPath, []byte(`{"Results":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence.TrivyReportSHA256, err = artifacts.QualificationInputSHA256(trivyPath, "Trivy report")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = artifacts.QualifyEvidence(evidence, artifacts.ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := artifacts.WriteEvidence(root, artifact.Name, evidence); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func TestRenderBuilderCloudInitWithKeyAndTargetsUsesRequestedArtifacts(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator #1"
	files, err := RenderBuilderCloudInitWithKeyAndTargets(key, []string{"image-base", "image-dns-blocky"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files.UserData, "./scripts/build-images.sh images image-base image-dns-blocky") || !strings.Contains(files.UserData, "./scripts/scan-images.sh scan-images boetticher-base boetticher-dns-blocky") {
		t.Fatalf("requested builder target set was not rendered: %s", files.UserData)
	}
}
