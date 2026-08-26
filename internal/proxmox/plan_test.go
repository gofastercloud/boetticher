package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func TestFoundationPlanIsDeterministic(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	first, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) {
		t.Fatal("identical sites generated different Proxmox plans")
	}
	if len(first.Guests) != 6 || first.Guests[0].VMID != model.ProxmoxVMID {
		t.Fatalf("unexpected foundation plan: %#v", first.Guests)
	}
	if first.GatewayImageURL != model.QualifiedGatewayImageURL || first.GatewaySHA512 != model.QualifiedGatewayImageSHA512 {
		t.Fatalf("gateway image pin is incomplete: %#v", first)
	}
}

func TestFoundationPlanUsesGatewayFirstDeploymentOrder(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	order := make([]string, 0, len(plan.Guests))
	for _, guest := range plan.Guests {
		order = append(order, guest.Name)
	}
	want := []string{"lab-fw-01", "lab-dns-01", "lab-dns-02", "lab-log-01", "lab-monitor-01", "lab-portal-01"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("deployment order = %#v, want %#v", order, want)
	}
}

func TestComposedPlanUsesResolvedCapabilityOrder(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	order := make(map[string]int, len(plan.Guests))
	for index, guest := range plan.Guests {
		order[guest.Name] = index
	}
	for _, pair := range [][2]string{{"lab-fw-01", "lab-dns-01"}, {"lab-dns-01", "lab-log-01"}, {"lab-dns-01", "lab-monitor-01"}, {"lab-log-01", "lab-portal-01"}} {
		if order[pair[0]] >= order[pair[1]] {
			t.Fatalf("deployment order %q before %q was not respected: %#v", pair[0], pair[1], order)
		}
	}
}

func TestResolveQualifiedArtifactsRequiresMatchingEvidence(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	plan.Guests = plan.Guests[:1]
	guest := plan.Guests[0]
	artifactFile := filepath.Join(t.TempDir(), "appliance.tar.zst")
	if err := os.WriteFile(artifactFile, []byte("qualified appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := artifacts.EvidenceForFile(artifactFile, guest.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = artifactFile
	for filename, content := range map[string]string{"package-manifest.txt": "package: test\n", "sbom.json": "{}\n", "trivy.json": "{\"Results\":[]}\n"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(artifactFile), filename), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	evidence.PackageManifestSHA, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "package-manifest.txt"), "package manifest")
	evidence.SBOMSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "sbom.json"), "SBOM")
	evidence.TrivyReportSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "trivy.json"), "Trivy report")
	evidence, err = artifacts.QualifyEvidence(evidence, artifacts.ScanSummary{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := artifacts.WriteEvidence(root, guest.Artifact.Name, evidence); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveQualifiedArtifacts(root, plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Guests[0].Artifact.ContentSHA256 == "" {
		t.Fatal("qualified content checksum was not carried into the deployment plan")
	}
	if _, err := ResolveQualifiedArtifacts(t.TempDir(), plan, true); err == nil {
		t.Fatal("missing qualification evidence was accepted")
	}
}

func TestLXCBootstrapKeyUsesProxmoxRootInjectionContract(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator"
	params, err := lxcBootstrapKeyParams(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := params.Get("ssh-public-keys"); got != key {
		t.Fatalf("LXC bootstrap key parameter = %q, want %q", got, key)
	}
	if _, err := lxcBootstrapKeyParams("not-a-key"); err == nil {
		t.Fatal("invalid LXC bootstrap key was accepted")
	}
}

func TestLXCBootstrapKeyCanBeOmittedForPlanRendering(t *testing.T) {
	params, err := lxcBootstrapKeyParams("")
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 {
		t.Fatalf("empty bootstrap key produced Proxmox parameters: %#v", params)
	}
}

func TestManagedFirewallUsesTaggedPerZoneVNICs(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Guests) != 6 || plan.Guests[0].Kind != KindQEMU {
		t.Fatalf("unexpected managed guest plan: %#v", plan.Guests)
	}
	want := []struct {
		name   string
		bridge string
		vlan   int
	}{
		{"wan0", "vmbr0", 0}, {"trusted0", "vmbr1", 10}, {"servers0", "vmbr1", 20}, {"sandbox0", "vmbr1", 50}, {"mgmt0", "vmbr1", 99},
	}
	for index, expected := range want {
		nic := plan.Guests[0].NICs[index]
		if nic.Name != expected.name || nic.Bridge != expected.bridge || nic.VLAN != expected.vlan || nic.MAC == "" {
			t.Fatalf("gateway NIC %d = %#v, want %#v", index, nic, expected)
		}
	}
}

func TestExternalGatewayOmitsFirewallGuest(t *testing.T) {
	plan, err := PlanFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Guests) != 1 {
		t.Fatalf("uncomposed external gateway plan has %d guests, want 1", len(plan.Guests))
	}
	for _, guest := range plan.Guests {
		if guest.VMID == model.ProxmoxVMID {
			t.Fatal("external gateway plan retained VMID 100")
		}
	}
}

func TestGatewayForFoundationZones(t *testing.T) {
	for zone, expected := range map[string]string{
		"TRUSTED": "10.10.10.1", "SERVERS": "10.10.20.1", "SANDBOX": "10.10.50.1", "MGMT": "10.10.99.1",
	} {
		if got := gatewayFor(zone); got != expected {
			t.Fatalf("gatewayFor(%q) = %q, want %q", zone, got, expected)
		}
	}
}

func TestUserWorkloadNeverEntersPlatformPlan(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, model.Component{
		Name: "user-vm-550", VMID: 550, Hostname: "user-vm-550", Zone: "SANDBOX", Address: "10.10.50.50",
		Role: "user workload", ProductOwned: false,
	})
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Guests) != 6 {
		t.Fatalf("user workload changed platform guest count: %#v", plan.Guests)
	}
	for _, guest := range plan.Guests {
		if guest.VMID == 550 {
			t.Fatal("user workload entered the boetticher platform plan")
		}
	}
}

func TestQEMUPersistentVolumeParamsUseCoreResolvedStorage(t *testing.T) {
	guest := GuestPlan{Volumes: []model.PersistentVolumeDeclaration{{
		Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4,
		MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true,
	}}}
	params, err := qemuPersistentVolumeParams(Plan{}, guest)
	if err != nil {
		t.Fatal(err)
	}
	if got := params["scsi1"]; got != modelStorageIDForTest+":4,backup=1,serial=boetticher-firewall-lab-fw-01-kea-leases" {
		t.Fatalf("unexpected persistent QEMU disk: %q", got)
	}
}

func TestQEMUPersistentVolumeParamsRejectUnresolvedStorage(t *testing.T) {
	_, err := qemuPersistentVolumeParams(Plan{}, GuestPlan{Volumes: []model.PersistentVolumeDeclaration{{
		Name: "kea-leases", SizeGiB: 4, MountPath: "/var/lib/kea",
	}}})
	if err == nil {
		t.Fatal("unresolved persistent storage was accepted")
	}
}

const modelStorageIDForTest = "boetticher-thin"

func TestEnsureArtifactInStorageVerifiesPostUploadChecksum(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact.tar.zst")
	content := []byte("qualified appliance bytes")
	if err := os.WriteFile(artifactPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	filename := "boetticher-logging-1.0.0-amd64.tar.zst"
	storageReads := 0
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			storageReads++
			if storageReads == 1 {
				return response([]byte(`{"data":[]}`))
			}
			return response([]byte(`{"data":[{"volid":"local:vztmpl/boetticher-logging-1.0.0-amd64.tar.zst","filename":"boetticher-logging-1.0.0-amd64.tar.zst","checksum":"` + checksum + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected artifact storage request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureArtifactInStorage(context.Background(), client, "node", "local", "vztmpl", filename, checksum, artifactPath); err != nil {
		t.Fatalf("ensureArtifactInStorage() = %v", err)
	}
	if storageReads != 2 {
		t.Fatalf("storage reads = %d, want pre-upload and post-upload verification", storageReads)
	}
}

func TestEnsureArtifactInStorageHoldsOnPostUploadChecksumMismatch(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact.tar.zst")
	content := []byte("qualified appliance bytes")
	if err := os.WriteFile(artifactPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	filename := "boetticher-logging-1.0.0-amd64.tar.zst"
	storageReads := 0
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			storageReads++
			if storageReads == 1 {
				return response([]byte(`{"data":[]}`))
			}
			return response([]byte(`{"data":[{"filename":"` + filename + `","checksum":"` + strings.Repeat("a", 64) + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected artifact storage request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureArtifactInStorage(context.Background(), client, "node", "local", "vztmpl", filename, checksum, artifactPath); err == nil || !strings.Contains(err.Error(), "does not match qualified") {
		t.Fatalf("post-upload checksum mismatch was not rejected: %v", err)
	}
}

func TestPlatformGuestPlanCarriesTagsForBackupAndVisibility(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if !guest.Backup {
			t.Fatalf("platform guest %s is not marked for backup", guest.Name)
		}
		if !hasTag(guest.Tags, model.TagBoetticher) || !hasTag(guest.Tags, model.TagManaged) || !hasTag(guest.Tags, model.TagBackup) {
			t.Fatalf("platform guest %s has incomplete tags: %#v", guest.Name, guest.Tags)
		}
		if guest.Owner != "" && (guest.Artifact.DefinitionSHA256 == "" || len(guest.Persistent) == 0) {
			t.Fatalf("module guest lacks artifact or persistent-state contract: %#v", guest)
		}
	}
}

func hasTag(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

func TestExistingGuestTagsAreReconciled(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/lab-proxmox-01/qemu/100/config" {
			t.Errorf("unexpected tag update request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse tag update form: %v", err)
		}
		if got := canonicalTags(r.Form.Get("tags")); got != canonicalTags("backup;boetticher;boetticher-module-firewall;managed;module;module-firewall") {
			t.Errorf("tags = %q", got)
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureExistingGuestTags(context.Background(), client, plan, plan.Guests[0], map[string]any{"tags": "boetticher-module-firewall"}); err != nil {
		t.Fatal(err)
	}
}

func TestReservedModuleGuestsRequireOwnershipProofBeforeTagReconciliation(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if guest.Owner == "" || !strings.HasPrefix(guest.Owner, "boetticher/module/") {
			continue
		}
		if err := ensureExistingGuestTags(context.Background(), nil, plan, guest, map[string]any{"tags": "boetticher;managed"}); err == nil || !strings.Contains(err.Error(), "canonical tag") {
			t.Fatalf("guest %d accepted without canonical ownership proof: %v", guest.VMID, err)
		}
	}
}

func TestEveryFixedGuestIdentityRequiresCanonicalOwnershipProof(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		current := map[string]any{
			"name": guest.Name, "hostname": guest.Hostname,
			"description": artifactDescription(guest.Artifact),
			"tags":        "boetticher;managed",
		}
		if err := validateExistingGuestIdentity(current, guest); err == nil || !strings.Contains(err.Error(), "canonical ownership proof") {
			t.Fatalf("fixed guest %d was accepted without ownership proof: %v", guest.VMID, err)
		}
	}
}
