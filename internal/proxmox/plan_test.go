package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

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
	if !reflect.DeepEqual(first.Nameservers, []string{"10.10.10.10", "10.10.10.11"}) {
		t.Fatalf("platform nameservers = %#v, want the INFRA DNS pair", first.Nameservers)
	}
}

func TestWaitForQEMUIPv4UsesRoutableGuestAgentAddress(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node/qemu/190/agent/network-get-interfaces" {
			t.Fatalf("unexpected guest-agent request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":{"result":[{"name":"ens18","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4"},{"ip-address":"192.168.4.36","ip-address-type":"ipv4"}]}]}}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	address, err := WaitForQEMUIPv4(context.Background(), client, "node", 190, 1, time.Millisecond)
	if err != nil || address != "192.168.4.36" {
		t.Fatalf("WaitForQEMUIPv4() = %q, %v", address, err)
	}
}

func TestEnsureVirtualBridgeOmitsInvalidNonePort(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/proxmox/network" {
			return response([]byte(`{"data":[]}`))
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/proxmox/network" {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("bridge-ports"); got != "" {
				t.Fatalf("bridge-ports = %q, want omitted for a virtual-only bridge", got)
			}
			if r.Form.Get("iface") != "vmbr1" || r.Form.Get("type") != "bridge" || r.Form.Get("bridge_vlan_aware") != "1" {
				t.Fatalf("unexpected virtual bridge form: %v", r.Form)
			}
			return response([]byte(`{"data":null}`))
		}
		t.Fatalf("unexpected network request: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := EnsureVirtualBridge(context.Background(), client, "proxmox"); err != nil {
		t.Fatal(err)
	}
}

func TestAttachTrunkSendsRequiredBridgeType(t *testing.T) {
	networkReads := 0
	networkReloads := 0
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/proxmox/network" {
			networkReads++
			if networkReads == 2 {
				return response([]byte(`{"data":[
  {"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},
  {"iface":"vmbr1","type":"bridge","bridge_ports":"enxa0cec8a2b210","bridge_vlan_aware":true},
  {"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true},
  {"iface":"enxa0cec8a2b210","type":"eth","hwaddr":"00:aa:bb:cc:dd:ee","active":false}
]}`))
			}
			return response([]byte(`{"data":[
  {"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},
  {"iface":"vmbr1","type":"bridge","bridge_ports":"none","bridge_vlan_aware":true},
  {"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true},
  {"iface":"enxa0cec8a2b210","type":"eth","hwaddr":"00:aa:bb:cc:dd:ee","active":false}
]}`))
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/proxmox/network/vmbr1" {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("type") != "bridge" || r.Form.Get("bridge_ports") != "enxa0cec8a2b210" || r.Form.Get("bridge_vlan_aware") != "1" {
				t.Fatalf("unexpected trunk attach form: %v", r.Form)
			}
			return response([]byte(`{"data":null}`))
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/proxmox/network" {
			networkReloads++
			return response([]byte(`{"data":null}`))
		}
		t.Fatalf("unexpected network request: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := AttachTrunk(context.Background(), client, "proxmox", "enxa0cec8a2b210", "192.0.2.73"); err != nil {
		t.Fatal(err)
	}
	if networkReloads != 1 {
		t.Fatalf("network reloads = %d, want 1", networkReloads)
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

func TestComposedDNSGuestsReceiveOnlyTheirOwnPersistentVolumes(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if guest.Name != "lab-dns-01" && guest.Name != "lab-dns-02" {
			continue
		}
		if len(guest.Persistent) != 2 || len(guest.Volumes) != 2 {
			t.Fatalf("DNS guest %s received shared declaration state: persistent=%#v volumes=%#v", guest.Name, guest.Persistent, guest.Volumes)
		}
		for _, state := range guest.Persistent {
			if state.Guest != guest.Name {
				t.Fatalf("DNS guest %s received persistent state for %s", guest.Name, state.Guest)
			}
		}
		for _, volume := range guest.Volumes {
			if volume.Guest != guest.Name {
				t.Fatalf("DNS guest %s received volume for %s", guest.Name, volume.Guest)
			}
		}
	}
}

func TestComposedFirewallGuestCarriesTelemetryStateAcrossRootfsReplacement(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if guest.Name != "lab-fw-01" {
			continue
		}
		foundState, foundVolume := false, false
		for _, state := range guest.Persistent {
			if state.Name == "firewall-telemetry" && state.Path == "/var/lib/boetticher/firewall-telemetry" && state.Backup && state.Replacement == "retain-across-rootfs-replacement" {
				foundState = true
			}
		}
		for _, volume := range guest.Volumes {
			if volume.Name == "firewall-telemetry" && volume.MountPath == "/var/lib/boetticher/firewall-telemetry" && volume.SizeGiB == 2 && volume.Backup {
				foundVolume = true
			}
		}
		if !foundState || !foundVolume {
			t.Fatalf("firewall telemetry persistence is incomplete: %#v", guest)
		}
		return
	}
	t.Fatal("managed firewall guest is missing")
}

func TestComposedPlanRejectsMissingModuleDeclaration(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	site.Declarations = nil
	if _, err := PlanFromSite(site); err == nil || !strings.Contains(err.Error(), "composed module guest") {
		t.Fatalf("composed plan accepted missing declarations: %v", err)
	}
}

func TestComposedFirewallKindComesFromDeclaredArtifact(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	for index := range site.Declarations {
		if site.Declarations[index].Module == "firewall" {
			site.Declarations[index].Artifact.Kind = string(KindLXC)
		}
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if guest.Name == "lab-fw-01" && guest.Kind != KindLXC {
			t.Fatalf("firewall kind was inferred from its name instead of its artifact: %#v", guest)
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
	for filename, content := range map[string]string{"package-manifest.txt": "package: test\n", "sbom.json": "{}\n", "trivy.json": "{\"Results\":[]}\n", "builder-provenance.json": "{\"platform\":\"debian-13-amd64\",\"input_image\":\"debian-13-genericcloud-amd64-20260327-2429\",\"kernel\":\"6.1.0\",\"go\":\"go version go1.26.5 linux/amd64\",\"trivy\":\"Version: 0.69.3\",\"mmdebstrap\":\"mmdebstrap 1.5.0\",\"architecture\":\"amd64\",\"boetticher_version\":\"0.4.0\"}\n"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(artifactFile), filename), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	evidence.PackageManifestSHA, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "package-manifest.txt"), "package manifest")
	evidence.SBOMSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "sbom.json"), "SBOM")
	evidence.TrivyReportSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "trivy.json"), "Trivy report")
	evidence.BuilderProvenanceSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "builder-provenance.json"), "builder provenance")
	evidence.Builder = artifacts.BuilderProvenance{Platform: "debian-13-amd64", InputImage: "debian-13-genericcloud-amd64-20260327-2429", Kernel: "6.1.0", Go: "go version go1.26.5 linux/amd64", Trivy: "Version: 0.69.3", MMDebstrap: "mmdebstrap 1.5.0", Architecture: "amd64", BoetticherVersion: "0.4.0"}
	evidence, err = artifacts.QualifyEvidence(evidence, artifacts.ScanSummary{Completed: true})
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

func TestEnsureBuilderArmsCleanupWhenCreateTaskFails(t *testing.T) {
	plan := Plan{
		Node:            "node",
		Storage:         "local",
		GatewayImage:    "debian-13-builder-input",
		GatewayImageURL: "https://example.invalid/debian-13-builder-input.qcow2",
		GatewaySHA512:   strings.Repeat("a", 128),
	}
	snippetsDeleted := 0
	createSSHKeys := ""
	bootOrder := ""
	builderNet0 := ""
	builderSCSIHW := ""
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/190/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/190/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			return response([]byte(`{"data":[{"volid":"local:iso/debian-13-builder-input.qcow2","filename":"debian-13-builder-input.qcow2","checksum":"` + strings.Repeat("a", 128) + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
			_, _ = io.Copy(io.Discard, r.Body)
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			createSSHKeys = r.Form.Get("sshkeys")
			bootOrder = r.Form.Get("boot")
			builderNet0 = r.Form.Get("net0")
			builderSCSIHW = r.Form.Get("scsihw")
			return response([]byte(`{"data":"UPID:pve:create-builder"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:create-builder/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"create failed"}}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node/storage/local/content/snippets/boetticher-190-"):
			snippetsDeleted++
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected builder creation request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	created, err := EnsureBuilderVM(context.Background(), client, plan, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator")
	if err == nil || !strings.Contains(err.Error(), "create temporary builder") {
		t.Fatalf("EnsureBuilderVM() error = %v, want create-task failure", err)
	}
	if !created {
		t.Fatal("EnsureBuilderVM did not arm caller cleanup after submitting a potentially-created VM")
	}
	if snippetsDeleted != 3 {
		t.Fatalf("builder snippets deleted = %d, want 3", snippetsDeleted)
	}
	if createSSHKeys != "" {
		t.Fatalf("builder create unexpectedly sent sshkeys outside custom user-data: %q", createSSHKeys)
	}
	if bootOrder != "order=scsi0;ide2;net0" {
		t.Fatalf("builder boot order = %q, want scsi0 before cloud-init and network", bootOrder)
	}
	if builderNet0 != "virtio,bridge=vmbr0,macaddr="+model.BuilderMAC {
		t.Fatalf("builder network = %q, want no Proxmox firewall bridge", builderNet0)
	}
	if builderSCSIHW != "virtio-scsi-single" {
		t.Fatalf("builder SCSI controller = %q, want virtio-scsi-single", builderSCSIHW)
	}
}

func TestEnsureBuilderCleansPartialSnippetUploads(t *testing.T) {
	for failAt := 1; failAt <= 3; failAt++ {
		t.Run(fmt.Sprintf("upload-%d", failAt), func(t *testing.T) {
			plan := Plan{
				Node:            "node",
				Storage:         "local",
				GatewayImage:    "debian-13-builder-input",
				GatewayImageURL: "https://example.invalid/debian-13-builder-input.qcow2",
				GatewaySHA512:   strings.Repeat("a", 128),
			}
			uploads := 0
			deletes := 0
			transport := roundTripFunc(func(r *http.Request) *http.Response {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/190/config":
					return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
				case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/190/config":
					return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
				case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
					return response([]byte(`{"data":[{"volid":"local:iso/debian-13-builder-input.qcow2","filename":"debian-13-builder-input.qcow2","checksum":"` + strings.Repeat("a", 128) + `"}]}`))
				case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
					uploads++
					_, _ = io.Copy(io.Discard, r.Body)
					if uploads == failAt {
						return apiResponse(http.StatusInternalServerError, `{"errors":{"upload":"failed"}}`)
					}
					return response([]byte(`{"data":null}`))
				case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node/storage/local/content/snippets/boetticher-190-"):
					deletes++
					return response([]byte(`{"data":null}`))
				default:
					t.Fatalf("unexpected builder request: %s %s", r.Method, r.URL.Path)
					return nil
				}
			})
			client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
			_, err := EnsureBuilderVM(context.Background(), client, plan, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator")
			if err == nil {
				t.Fatal("partial snippet upload unexpectedly succeeded")
			}
			if uploads != failAt {
				t.Fatalf("snippet uploads = %d, want failure at %d", uploads, failAt)
			}
			if deletes != 3 {
				t.Fatalf("snippet cleanup requests = %d, want all 3 exact names", deletes)
			}
		})
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
		{"wan0", "vmbr0", 0}, {"trusted0", "vmbr1", 30}, {"servers0", "vmbr1", 20}, {"sandbox0", "vmbr1", 40}, {"mgmt0", "vmbr1", 99}, {"transit0", "vmbr1", model.TransitVLAN}, {"infra0", "vmbr1", 10},
	}
	if len(plan.Guests[0].NICs) != len(want) {
		t.Fatalf("got %d firewall NICs, want exact WAN plus six internal VLANs", len(plan.Guests[0].NICs))
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
		"INFRA": "10.10.10.1", "SERVERS": "10.10.20.1", "TRUSTED": "10.10.30.1", "SANDBOX": "10.10.40.1", "MGMT": "10.10.99.1", "TRANSIT": model.TransitGateway,
	} {
		if got := gatewayFor(zone); got != expected {
			t.Fatalf("gatewayFor(%q) = %q, want %q", zone, got, expected)
		}
	}
}

func TestUserWorkloadNeverEntersPlatformPlan(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, model.Component{
		Name: "user-vm-550", VMID: 550, Hostname: "user-vm-550", Zone: "SANDBOX", Address: "10.10.40.50",
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
	if got := params["scsi1"]; got != modelStorageIDForTest+":4,backup=1,serial=boetticher-131072f5f225f1be9bdcc358d" {
		t.Fatalf("unexpected persistent QEMU disk: %q", got)
	}
}

func TestEnsureQEMUMigratesLegacyPersistentVolumeSerial(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", Volumes: []model.PersistentVolumeDeclaration{{
		Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4,
		MountPath: "/var/lib/kea", Storage: "local", Backup: true,
	}}}
	legacy := "local:100/vm-100-disk-0.raw,backup=1,serial=boetticher-firewall-lab-fw-01-kea-leases,size=4G"
	updated := ""
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			return response([]byte(`{"data":{"name":"test-fw","scsi1":"` + legacy + `"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			updated = r.Form.Get("scsi1")
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected QEMU migration request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest); err != nil {
		t.Fatalf("ensureQEMU() = %v", err)
	}
	want := "local:4,backup=1,serial=boetticher-131072f5f225f1be9bdcc358d"
	if updated != want {
		t.Fatalf("migrated QEMU disk = %q, want %q", updated, want)
	}
}

func TestEnsureQEMURequiresConfirmationToReplaceOwnedArtifact(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", Artifact: model.Artifact{
		Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "new-content",
	}}
	currentDescription := artifactDescription(model.Artifact{Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "old-content"})
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config" {
			return response([]byte(`{"data":{"name":"test-fw","description":"` + currentDescription + `"}}`))
		}
		t.Fatalf("unexpected request before replacement confirmation: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "requires --confirm") {
		t.Fatalf("artifact replacement without confirmation = %v", err)
	}
}

func TestEnsureLXCRequiresConfirmationToReplaceOwnedArtifact(t *testing.T) {
	guest := GuestPlan{VMID: 110, Name: "test-dns", Hostname: "test-dns", Artifact: model.Artifact{
		Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "new-content",
	}}
	currentDescription := artifactDescription(model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "old-content"})
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config" {
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config" {
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","description":"` + currentDescription + `","tags":"boetticher;managed;boetticher-module-dns"}}`))
		}
		t.Fatalf("unexpected request before replacement confirmation: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureLXC(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "requires --confirm") {
		t.Fatalf("artifact replacement without confirmation = %v", err)
	}
}

func TestExistingLXCReconcilesPlatformNameservers(t *testing.T) {
	plan := Plan{Node: "node", Nameservers: []string{"10.10.10.10", "10.10.10.11"}}
	guest := GuestPlan{
		VMID: 110, Name: "test-dns", Hostname: "test-dns", Owner: "boetticher/module/dns",
		Tags: []string{"boetticher-module-dns"},
	}
	updated := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","tags":"boetticher-module-dns"}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("nameserver"); got != "10.10.10.10 10.10.10.11" {
				t.Fatalf("nameserver update = %q", got)
			}
			updated = true
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected existing LXC request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureLXC(context.Background(), client, plan, guest); err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("existing LXC nameserver was not reconciled")
	}
}

func TestReplaceLXCDetachesPersistentVolumesBeforeDestroy(t *testing.T) {
	var detached []string
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			detached = append(detached, r.Form["delete"]...)
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/nodes/node/lxc/110":
			if r.URL.Query().Get("purge") != "0" || r.URL.Query().Get("destroy-unreferenced-disks") != "0" {
				t.Fatalf("replacement destroy query = %v", r.URL.Query())
			}
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected LXC replacement request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	guest := GuestPlan{VMID: 110, Name: "test-dns", Volumes: []model.PersistentVolumeDeclaration{
		{Name: "powerdns-database", Guest: "lab-dns-01", Module: "dns", SizeGiB: 8, MountPath: "/var/lib/powerdns"},
		{Name: "ssh-identity", Guest: "lab-dns-01", Module: "dns", SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh"},
	}}
	if err := replaceLXC(context.Background(), client, Plan{Node: "node"}, guest); err != nil {
		t.Fatalf("replaceLXC() = %v", err)
	}
	if !reflect.DeepEqual(detached, []string{"mp0", "mp1"}) {
		t.Fatalf("detached mount points = %#v, want [mp0 mp1]", detached)
	}
}

func TestExistingLXCArtifactAcceptsProxmoxEncodedDescriptionNewline(t *testing.T) {
	guest := GuestPlan{VMID: 110, Name: "test-dns", Hostname: "test-dns", Artifact: model.Artifact{
		Name: "boetticher-dns-blocky", Version: "1.0.0", ContentSHA256: "content",
	}}
	current := map[string]any{
		"name": guest.Name, "hostname": guest.Name,
		"description": artifactDescription(guest.Artifact) + "%0A",
		"tags":        "boetticher;managed;boetticher-module-dns",
	}
	if err := validateExistingGuestIdentity(current, guest); err != nil {
		t.Fatalf("encoded Proxmox description was rejected: %v", err)
	}
}

func TestUploadFirewallCloudInitRefreshesAllReplacementSnippets(t *testing.T) {
	var uploaded []string
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/node/storage/local/upload" {
			t.Fatalf("unexpected cloud-init upload request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseMultipartForm(1024 * 1024); err != nil {
			t.Fatal(err)
		}
		files := r.MultipartForm.File["filename"]
		if len(files) != 1 {
			t.Fatalf("uploaded filename parts = %#v", files)
		}
		uploaded = append(uploaded, files[0].Filename)
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	plan := Plan{
		Node:           "node",
		CloudInitFiles: CloudInitFiles{MetaData: "meta", UserData: "user", NetworkConfig: "network"},
	}
	if err := uploadFirewallCloudInit(context.Background(), client, plan, 100); err != nil {
		t.Fatalf("uploadFirewallCloudInit() = %v", err)
	}
	sort.Strings(uploaded)
	want := []string{"boetticher-100-meta.yaml", "boetticher-100-network.yaml", "boetticher-100-user.yaml"}
	if !reflect.DeepEqual(uploaded, want) {
		t.Fatalf("replacement cloud-init snippets = %#v, want %#v", uploaded, want)
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

func TestExistingQEMUPersistentVolumesRequireStableIdentity(t *testing.T) {
	guest := GuestPlan{Volumes: []model.PersistentVolumeDeclaration{{
		Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4,
		MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true,
	}}}
	plan := Plan{}
	expected, err := qemuPersistentVolumeParam(plan, guest.Volumes[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExistingQEMUVolumes(map[string]any{"scsi1": expected}, plan, guest); err != nil {
		t.Fatalf("stable QEMU volume identity was rejected: %v", err)
	}
	for _, observed := range []string{
		modelStorageIDForTest + ":4,backup=1",
		modelStorageIDForTest + ":4,backup=1,serial=boetticher-firewall-lab-fw-01-other",
	} {
		if err := validateExistingQEMUVolumes(map[string]any{"scsi1": observed}, plan, guest); err == nil || !strings.Contains(err.Error(), "HOLD") {
			t.Fatalf("QEMU volume without the expected stable identity was accepted: %q / %v", observed, err)
		}
	}
}

func TestExistingLXCPersistentVolumesRejectUndeclaredMountpoints(t *testing.T) {
	guest := GuestPlan{
		Name:    "lab-tailnet-01",
		Volumes: []model.PersistentVolumeDeclaration{{Storage: modelStorageIDForTest, SizeGiB: 4, MountPath: "/var/lib/tailscale", Placement: model.StorageDefault, Backup: true}},
	}
	current := map[string]any{
		"mp0": "boetticher-thin:4,mp=/var/lib/tailscale,backup=1,size=4G",
		"mp1": "boetticher-thin:1,mp=/unexpected,backup=1,size=1G",
	}
	if err := validateExistingGuestVolumes(current, guest); err == nil || !strings.Contains(err.Error(), "undeclared persistent volume") {
		t.Fatalf("undeclared LXC mountpoint was accepted: %v", err)
	}
}

func TestExistingLXCPersistentVolumesAcceptProxmoxCanonicalVolumeID(t *testing.T) {
	guest := GuestPlan{Name: "test-dns", Volumes: []model.PersistentVolumeDeclaration{{
		Storage: modelStorageIDForTest, SizeGiB: 8, MountPath: "/var/lib/powerdns", Backup: true,
	}}}
	current := map[string]any{"mp0": "boetticher-thin:110/vm-110-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=8G"}
	if err := validateExistingGuestVolumes(current, guest); err != nil {
		t.Fatalf("canonical Proxmox LXC volume was rejected: %v", err)
	}
	current["mp0"] = "boetticher-thin:110/vm-110-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=9G"
	if err := validateExistingGuestVolumes(current, guest); err == nil {
		t.Fatal("LXC volume with the wrong size was accepted")
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
			_, _ = io.Copy(io.Discard, r.Body)
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
			_, _ = io.Copy(io.Discard, r.Body)
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

func TestEnsureArtifactInStorageAcceptsChecksumlessVZTemplateAfterVerifiedUpload(t *testing.T) {
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
			return response([]byte(`{"data":[{"filename":"` + filename + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
			_, _ = io.Copy(io.Discard, r.Body)
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

func TestEnsureQEMUUploadsQcow2ThroughImportContent(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "firewall.qcow2")
	content := []byte("qualified firewall bytes")
	if err := os.WriteFile(artifactPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	guest := GuestPlan{VMID: 100, Name: "test-fw", Artifact: model.Artifact{
		Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: checksum,
	}}
	plan := Plan{Node: "node", Storage: modelStorageIDForTest, ArtifactFiles: map[string]string{
		artifactKey(guest.Artifact): artifactPath,
	}, OperatorPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator"}
	uploadContent := ""
	importDisk := ""
	createSSHKeys := ""
	storageReads := 0
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/100/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			storageReads++
			if storageReads == 1 {
				return response([]byte(`{"data":[{"volid":"local:import/boetticher-firewall-1.0.0-amd64.qcow2","filename":"boetticher-firewall-1.0.0-amd64.qcow2"}]}`))
			}
			return response([]byte(`{"data":[{"volid":"local:import/boetticher-firewall-1.0.0-amd64.qcow2","filename":"boetticher-firewall-1.0.0-amd64.qcow2"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
			reader, err := r.MultipartReader()
			if err != nil {
				t.Fatal(err)
			}
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if part.FormName() == "content" {
					value, err := io.ReadAll(part)
					if err != nil {
						t.Fatal(err)
					}
					uploadContent = string(value)
				}
			}
			return response([]byte(`{"data":"UPID:pve:upload"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:upload/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			createSSHKeys = r.Form.Get("sshkeys")
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			importDisk = r.Form.Get("scsi0")
			return response([]byte(`{"data":"UPID:pve:import"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:import/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected QEMU request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureQEMU(context.Background(), client, plan, guest); err != nil {
		t.Fatalf("ensureQEMU() = %v", err)
	}
	if uploadContent != "import" {
		t.Fatalf("qcow2 upload content = %q, want import", uploadContent)
	}
	wantImport := "boetticher-thin:0,import-from=local:import/boetticher-firewall-1.0.0-amd64.qcow2,format=qcow2"
	if importDisk != wantImport {
		t.Fatalf("QEMU import disk = %q, want %q", importDisk, wantImport)
	}
	if want := url.PathEscape(plan.OperatorPublicKey); createSSHKeys != want {
		t.Fatalf("QEMU sshkeys = %q, want URL-encoded key %q", createSSHKeys, want)
	}
}

func TestEnsureFirewallHoldsUnownedFixedIDBeforeArtifactUpload(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	var firewall GuestPlan
	for _, guest := range plan.Guests {
		if guest.Kind == KindQEMU {
			firewall = guest
			break
		}
	}
	if firewall.VMID == 0 {
		t.Fatal("test fixture has no firewall guest")
	}
	config, err := json.Marshal(map[string]any{
		"name":        firewall.Name,
		"hostname":    firewall.Hostname,
		"description": artifactDescription(firewall.Artifact),
		"tags":        "boetticher;managed",
	})
	if err != nil {
		t.Fatal(err)
	}
	uploadAttempted := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/qemu/100/config") {
			return response(append([]byte(`{"data":`), append(config, '}')...))
		}
		if strings.Contains(r.URL.Path, "/storage/local/") || strings.HasSuffix(r.URL.Path, "/upload") {
			uploadAttempted = true
			return response([]byte(`{"data":[]}`))
		}
		t.Fatalf("unexpected request while checking fixed-ID ownership: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err = EnsureFirewallVM(context.Background(), client, plan)
	if err == nil || !strings.Contains(err.Error(), "canonical ownership proof") {
		t.Fatalf("unowned firewall VM was not held: %v", err)
	}
	if uploadAttempted {
		t.Fatal("artifact storage was touched before fixed-ID ownership was proven")
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

func TestTailnetRouterPlanCarriesUnprivilegedExactTUNContract(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if guest.Name != "lab-tailnet-01" {
			continue
		}
		if guest.VMID != 200 || guest.Address != "10.10.5.10" || guest.VLAN != model.TransitVLAN || !guest.Security.Unprivileged || len(guest.Security.Devices) != 1 {
			t.Fatalf("tailnet guest identity/security = %#v", guest)
		}
		device := guest.Security.Devices[0]
		if device.Path != "/dev/net/tun" || device.Type != "c" || device.Major != 10 || device.Minor != 200 || device.Access != "rwm" {
			t.Fatalf("tailnet TUN contract = %#v", device)
		}
		if got := lxcDeviceParam(device); got != "path=/dev/net/tun,mode=0666" {
			t.Fatalf("Proxmox TUN parameter = %q", got)
		}
		return
	}
	t.Fatal("tailnet guest is missing")
}

func TestUnsupportedTUNContractHoldsBeforeAnyProxmoxMutation(t *testing.T) {
	guest := GuestPlan{Name: "lab-tailnet-01", Security: model.GuestSecurityDeclaration{Unprivileged: true, Devices: []model.DeviceRequirement{{Path: "/dev/net/tun", Type: "c", Major: 10, Minor: 201, Access: "rwm"}}}}
	if err := ensureLXC(context.Background(), nil, Plan{}, guest); err == nil || !strings.Contains(err.Error(), "HOLD") {
		t.Fatalf("unsupported TUN contract was not held before provider access: %v", err)
	}
}

func TestCreatedLXCIsNotStartedWhenProxmoxDropsTUNContract(t *testing.T) {
	artifactBytes := []byte("qualified tailnet-router artifact")
	artifactPath := filepath.Join(t.TempDir(), "tailnet-router.tar.zst")
	if err := os.WriteFile(artifactPath, artifactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	contentSum := sha256.Sum256(artifactBytes)
	artifact := model.Artifact{
		Name:             "boetticher-tailnet-router",
		Version:          "1.0.0",
		Architecture:     "amd64",
		Kind:             "lxc",
		DefinitionSHA256: strings.Repeat("a", 64),
		ContentSHA256:    hex.EncodeToString(contentSum[:]),
	}
	guest := GuestPlan{
		VMID:     200,
		Name:     "lab-tailnet-01",
		Hostname: "lab-tailnet-01",
		Kind:     KindLXC,
		Owner:    "boetticher/module/tailnet-router",
		Tags:     []string{"boetticher", "managed", "module", "module-tailnet-router", "boetticher-module-tailnet-router", "backup"},
		Artifact: artifact,
		Security: model.GuestSecurityDeclaration{Unprivileged: true, Devices: []model.DeviceRequirement{{Path: "/dev/net/tun", Type: "c", Major: 10, Minor: 200, Access: "rwm"}}},
	}
	plan := Plan{Node: "node", Storage: "local", Guests: []GuestPlan{guest}, ArtifactFiles: map[string]string{artifactKey(artifact): artifactPath}}
	var storageLookups, configLookups int
	started := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/200/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/200/config":
			configLookups++
			if configLookups == 1 {
				return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
			}
			return response([]byte(`{"data":{"name":"lab-tailnet-01","hostname":"lab-tailnet-01","description":"` + artifactDescription(artifact) + `","unprivileged":1,"tags":"boetticher;managed;module;module-tailnet-router;boetticher-module-tailnet-router;backup"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			storageLookups++
			if storageLookups == 1 {
				return response([]byte(`{"data":[]}`))
			}
			return response([]byte(`{"data":[{"volid":"local:vztmpl/boetticher-tailnet-router-1.0.0-amd64.tar.zst","filename":"boetticher-tailnet-router-1.0.0-amd64.tar.zst","checksum":"` + artifact.ContentSHA256 + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
			_, _ = io.Copy(io.Discard, r.Body)
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc":
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/200/status/start":
			started = true
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected LXC security verification request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ProvisionModule(context.Background(), client, plan, "tailnet-router")
	if err == nil || !strings.Contains(err.Error(), "HOLD") {
		t.Fatalf("created LXC without exact TUN contract was accepted: %v", err)
	}
	if started {
		t.Fatal("LXC start was requested after TUN contract verification failed")
	}
}

func TestExistingTailnetGuestMustProveUnprivilegedTUNConfiguration(t *testing.T) {
	guest := GuestPlan{Name: "lab-tailnet-01", Hostname: "lab-tailnet-01", Owner: "boetticher/module/tailnet-router", Security: model.GuestSecurityDeclaration{Unprivileged: true, Devices: []model.DeviceRequirement{{Path: "/dev/net/tun", Type: "c", Major: 10, Minor: 200, Access: "rwm"}}}}
	if err := validateExistingGuestIdentity(map[string]any{"name": guest.Name, "hostname": guest.Name, "unprivileged": float64(1), "dev0": "path=/dev/net/tun,mode=0666", "tags": "boetticher;managed"}, guest); err == nil || !strings.Contains(err.Error(), "canonical ownership proof") {
		t.Fatalf("existing guest without full ownership proof was accepted: %v", err)
	}
	if err := validateExistingGuestIdentity(map[string]any{"name": guest.Name, "hostname": guest.Name, "unprivileged": float64(0), "dev0": "path=/dev/net/tun,mode=0666", "tags": "boetticher-module-tailnet-router"}, guest); err == nil || !strings.Contains(err.Error(), "not unprivileged") {
		t.Fatalf("privileged existing guest was not held: %v", err)
	}
	if err := validateExistingGuestIdentity(map[string]any{"name": guest.Name, "hostname": guest.Name, "unprivileged": float64(1), "dev0": "path=/dev/net/tun,mode=0666", "dev1": "path=/dev/kvm,mode=0666", "tags": "boetticher;managed;boetticher-module-tailnet-router"}, guest); err == nil || !strings.Contains(err.Error(), "undeclared device") {
		t.Fatalf("existing guest with an extra device allowance was accepted: %v", err)
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

func TestEveryFixedGuestKindCollisionHoldsBeforeCreation(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range plan.Guests {
		expected := expected
		t.Run(fmt.Sprintf("%s-%d", expected.Name, expected.VMID), func(t *testing.T) {
			transport := roundTripFunc(func(r *http.Request) *http.Response {
				qemuPath := "/api2/json/nodes/lab-proxmox-01/qemu/" + strconv.Itoa(expected.VMID) + "/config"
				lxcPath := "/api2/json/nodes/lab-proxmox-01/lxc/" + strconv.Itoa(expected.VMID) + "/config"
				switch {
				case expected.Kind == KindQEMU && r.Method == http.MethodGet && r.URL.Path == qemuPath:
					return apiResponse(http.StatusNotFound, `{"errors":"missing qemu"}`)
				case expected.Kind == KindQEMU && r.Method == http.MethodGet && r.URL.Path == lxcPath:
					return response([]byte(`{"data":{"name":"user-lxc"}}`))
				case expected.Kind == KindLXC && r.Method == http.MethodGet && r.URL.Path == qemuPath:
					return response([]byte(`{"data":{"name":"user-qemu"}}`))
				default:
					t.Fatalf("unexpected request after fixed-ID collision: %s %s", r.Method, r.URL.Path)
					return nil
				}
			})
			client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
			var collisionErr error
			if expected.Kind == KindQEMU {
				collisionErr = ensureQEMU(context.Background(), client, plan, expected)
			} else {
				collisionErr = ensureLXC(context.Background(), client, plan, expected)
			}
			if collisionErr == nil || !strings.Contains(collisionErr.Error(), "HOLD") {
				t.Fatalf("fixed-ID kind collision was not held: %v", collisionErr)
			}
		})
	}
}

func TestManagedUSBDeviceValueAllowsOnlyRawUSBOrSerialCharacterDevices(t *testing.T) {
	for _, value := range []string{
		"/dev/bus/usb/001/041,uid=2200,gid=2200,mode=0660",
		"/dev/ttyUSB0,uid=2200,gid=2200,mode=0660",
		"/dev/ttyACM12,uid=2200,gid=2200,mode=0660",
	} {
		if !validManagedUSBDeviceValue(value) {
			t.Fatalf("safe managed USB device rejected: %q", value)
		}
	}
	for _, value := range []string{
		"/dev/sda,uid=2200,gid=2200,mode=0660",
		"/dev/ttyUSB0,uid=0,gid=0,mode=0666",
		"/dev/ttyUSB0",
	} {
		if validManagedUSBDeviceValue(value) {
			t.Fatalf("unsafe managed USB device accepted: %q", value)
		}
	}
}
