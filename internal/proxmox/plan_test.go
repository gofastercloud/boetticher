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

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

type recordingArgsRunner struct {
	address string
	user    string
	args    [][]string
	err     error
	errs    []error
	outputs [][]byte
}

func (r *recordingArgsRunner) RunArgs(_ context.Context, address, user string, args []string) ([]byte, error) {
	r.address = address
	r.user = user
	r.args = append(r.args, append([]string(nil), args...))
	var output []byte
	if len(r.outputs) > 0 {
		output = r.outputs[0]
		r.outputs = r.outputs[1:]
	}
	if len(r.errs) > 0 {
		err := r.errs[0]
		r.errs = r.errs[1:]
		return output, err
	}
	return output, r.err
}

func TestInspectGuestArtifactReadsExistingGuestConfigOnce(t *testing.T) {
	guest := GuestPlan{
		VMID: 100, Kind: KindQEMU,
		Artifact: model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64"},
	}
	reads := 0
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node/qemu/100/config" {
			t.Fatalf("unexpected guest artifact request: %s %s", r.Method, r.URL.Path)
		}
		reads++
		return response([]byte(`{"data":{"description":"` + artifactDescription(guest.Artifact) + `"}}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	exists, replacement, err := InspectGuestArtifact(context.Background(), client, "node", guest)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || replacement || reads != 1 {
		t.Fatalf("guest artifact state = exists:%t replacement:%t reads:%d", exists, replacement, reads)
	}
}

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
	if len(first.Guests) != 3 || first.Guests[0].VMID != model.ProxmoxVMID {
		t.Fatalf("unexpected foundation plan: %#v", first.Guests)
	}
	if first.GatewayImageURL != model.QualifiedGatewayImageURL || first.GatewaySHA512 != model.QualifiedGatewayImageSHA512 {
		t.Fatalf("gateway image pin is incomplete: %#v", first)
	}
	if !reflect.DeepEqual(first.Nameservers, []string{"10.10.10.10"}) {
		t.Fatalf("platform nameservers = %#v, want the single INFRA DNS service", first.Nameservers)
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

func TestEnsureVirtualOnlyBridgeDetachesOneStaleMember(t *testing.T) {
	reads := 0
	detached := false
	reloads := 0
	initial := `{"data":[
  {"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},
  {"iface":"vmbr1","type":"bridge","bridge_ports":"enxa0cec8a2b210","bridge_vlan_aware":true},
  {"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true},
  {"iface":"enxa0cec8a2b210","type":"eth","hwaddr":"00:aa:bb:cc:dd:ee","active":false}
]}`
	cleared := `{"data":[
  {"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},
  {"iface":"vmbr1","type":"bridge","bridge_ports":"none","bridge_vlan_aware":true},
  {"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true},
  {"iface":"enxa0cec8a2b210","type":"eth","hwaddr":"00:aa:bb:cc:dd:ee","active":false}
]}`
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/proxmox/network":
			reads++
			if detached {
				return response([]byte(cleared))
			}
			return response([]byte(initial))
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/proxmox/network/vmbr1":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("type") != "bridge" || r.Form.Get("delete") != "bridge_ports" || r.Form.Get("bridge_ports") != "" || r.Form.Get("bridge_vlan_aware") != "1" {
				t.Fatalf("unexpected virtual-only detach form: %v", r.Form)
			}
			detached = true
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/proxmox/network":
			reloads++
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected network request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := EnsureVirtualOnlyBridge(context.Background(), client, "proxmox", "192.0.2.73"); err != nil {
		t.Fatal(err)
	}
	if !detached || reloads != 1 || reads < 4 {
		t.Fatalf("virtual-only bridge reconciliation did not verify its detach: detached=%t reloads=%d reads=%d", detached, reloads, reads)
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
	want := []string{"lab-fw-01", "lab-dns-01", "lab-monitor-01"}
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
	for _, pair := range [][2]string{{"lab-fw-01", "lab-dns-01"}, {"lab-dns-01", "lab-monitor-01"}} {
		if order[pair[0]] >= order[pair[1]] {
			t.Fatalf("deployment order %q before %q was not respected: %#v", pair[0], pair[1], order)
		}
	}
}

func TestArrPlanUsesDeclarationOwnedDHCPIdentity(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	config.StorageProfile = "dedicated-data-disk"
	config.StorageDevice = "/dev/disk/by-id/ata-example-data"
	enabled := true
	config.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "europe"}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if guest.Name == "lab-arr-01" {
			if guest.MAC != model.ArrGuestMAC || lxcNetworkParam(guest) != "name=eth0,bridge=vmbr1,tag=20,firewall=1,macaddr="+model.ArrGuestMAC+",ip=dhcp" {
				t.Fatalf("arr guest network identity = %#v", guest)
			}
			return
		}
	}
	t.Fatal("arr guest is missing")
}

func TestAirVPNBifrostPlanUsesStableMACFilterIdentity(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "europe"}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled: &enabled, Network: model.ModuleNetworkAirVPN,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected", Upstream: "provider", Model: "provider/model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range plan.Guests {
		if guest.Name == "lab-bifrost-01" {
			if guest.MAC != networkmodel.ManagedModuleMAC(210) || !strings.Contains(lxcNetworkParam(guest), "macaddr="+networkmodel.ManagedModuleMAC(210)+",ip=10.10.20.60/24") {
				t.Fatalf("AirVPN Bifrost network identity = %#v", guest)
			}
			return
		}
	}
	t.Fatal("AirVPN Bifrost guest is missing")
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
		if guest.Name != "lab-dns-01" {
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

func TestLXCNetworkParamUsesStaticMACForAirVPNGuest(t *testing.T) {
	guest := GuestPlan{VLAN: 20, Address: "10.10.20.60", Gateway: "10.10.20.1", MAC: networkmodel.ManagedModuleMAC(210)}
	want := "name=eth0,bridge=vmbr1,tag=20,firewall=1,macaddr=02:00:00:03:00:d2,ip=10.10.20.60/24,gw=10.10.20.1"
	if got := lxcNetworkParam(guest); got != want {
		t.Fatalf("lxcNetworkParam() = %q, want %q", got, want)
	}
}

func TestResolveQualifiedArtifactsRequiresMatchingEvidence(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	plan.Guests = plan.Guests[:1]
	guest := plan.Guests[0]
	root := t.TempDir()
	artifactFile := filepath.Join(root, "appliance.tar.zst")
	if err := os.WriteFile(artifactFile, []byte("qualified appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := artifacts.EvidenceForFile(artifactFile, guest.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = artifactFile
	for filename, content := range map[string]string{"package-manifest.txt": "package: test\n", "sbom.json": "{}\n", "trivy.json": "{\"Results\":[]}\n", "builder-provenance.json": "{\"platform\":\"debian-13-amd64\",\"input_image\":\"debian-13-genericcloud-amd64-20260327-2429\",\"kernel\":\"6.1.0\",\"go\":\"go version go1.26.5 linux/amd64\",\"trivy\":\"Version: 0.69.3\",\"mmdebstrap\":\"mmdebstrap 1.5.0\",\"architecture\":\"amd64\",\"boetticher_version\":\"0.1.0\"}\n"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(artifactFile), filename), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	evidence.PackageManifestSHA, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "package-manifest.txt"), "package manifest")
	evidence.SBOMSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "sbom.json"), "SBOM")
	evidence.TrivyReportSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "trivy.json"), "Trivy report")
	evidence.BuilderProvenanceSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactFile), "builder-provenance.json"), "builder provenance")
	evidence.Builder = artifacts.BuilderProvenance{Platform: "debian-13-amd64", InputImage: "debian-13-genericcloud-amd64-20260327-2429", Kernel: "6.1.0", Go: "go version go1.26.5 linux/amd64", Trivy: "Version: 0.69.3", MMDebstrap: "mmdebstrap 1.5.0", Architecture: "amd64", BoetticherVersion: "0.1.0"}
	evidence, err = artifacts.QualifyEvidence(evidence, artifacts.ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
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
	if len(plan.Guests) != 3 || plan.Guests[0].Kind != KindQEMU {
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
	if len(plan.Guests) != 0 {
		t.Fatalf("uncomposed external gateway plan has %d guests, want none", len(plan.Guests))
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
	if len(plan.Guests) != 3 {
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

func TestEnsureQEMUMigratesVerifiedPersistentVolumesToDeclaredStorage(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", Volumes: []model.PersistentVolumeDeclaration{{
		Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4,
		MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true,
	}}}
	serial, err := persistentVolumeSerial(guest.Volumes[0])
	if err != nil {
		t.Fatal(err)
	}
	before := "local:100/vm-100-disk-0.raw,backup=1,serial=" + serial + ",size=4G"
	after := modelStorageIDForTest + ":100/vm-100-disk-0,backup=1,serial=" + serial + ",size=4G"
	configReads := 0
	moved := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			configReads++
			if moved {
				return response([]byte(`{"data":{"name":"test-fw","digest":"0123456789abcdef0123456789abcdef01234568","scsi1":"` + after + `"}}`))
			}
			return response([]byte(`{"data":{"name":"test-fw","digest":"0123456789abcdef0123456789abcdef01234567","scsi1":"` + before + `"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/move_disk":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got, want := r.Form.Get("disk"), "scsi1"; got != want {
				t.Fatalf("disk = %q, want %q", got, want)
			}
			if got, want := r.Form.Get("storage"), modelStorageIDForTest; got != want {
				t.Fatalf("storage = %q, want %q", got, want)
			}
			if got, want := r.Form.Get("delete"), "1"; got != want {
				t.Fatalf("delete = %q, want %q", got, want)
			}
			moved = true
			return response([]byte(`{"data":"UPID:pve:move-disk"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:move-disk/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected persistent-volume migration request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest); err != nil {
		t.Fatalf("ensureQEMU() = %v", err)
	}
	if !moved || configReads < 3 {
		t.Fatalf("persistent volume migration did not refresh provider configuration: moved=%t reads=%d", moved, configReads)
	}
}

func TestEnsureQEMURefusesPersistentVolumeMigrationWithoutExactIdentity(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", Volumes: []model.PersistentVolumeDeclaration{{
		Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4,
		MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true,
	}}}
	moveRequested := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config" {
			return response([]byte(`{"data":{"name":"test-fw","scsi1":"local:100/vm-100-disk-0.raw,backup=1,serial=boetticher-other,size=4G"}}`))
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/move_disk" {
			moveRequested = true
		}
		t.Fatalf("unexpected request while rejecting persistent-volume migration: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "refusing to migrate") {
		t.Fatalf("unproven persistent volume migration = %v", err)
	}
	if moveRequested {
		t.Fatal("unproven persistent volume was moved")
	}
}

func TestEnsureQEMURestoresRunningGuestAfterPersistentVolumeMigrationFailure(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", Volumes: []model.PersistentVolumeDeclaration{{
		Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4,
		MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true,
	}}}
	serial, err := persistentVolumeSerial(guest.Volumes[0])
	if err != nil {
		t.Fatal(err)
	}
	observed := "local:100/vm-100-disk-0.raw,backup=1,serial=" + serial + ",size=4G"
	stopped, restored := false, false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			return response([]byte(`{"data":{"name":"test-fw","digest":"0123456789abcdef0123456789abcdef01234567","scsi1":"` + observed + `"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/current":
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/stop":
			stopped = true
			return response([]byte(`{"data":"UPID:pve:stop"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:stop/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/move_disk":
			return response([]byte(`{"data":"UPID:pve:move-disk"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:move-disk/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"ERROR: copy failed"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/start":
			restored = true
			return response([]byte(`{"data":"UPID:pve:start"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:start/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected failure-recovery request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err = ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "copy failed") {
		t.Fatalf("failed persistent-volume move = %v", err)
	}
	if !stopped || !restored {
		t.Fatalf("running guest was not safely restored: stopped=%t restored=%t", stopped, restored)
	}
}

func TestEnsureLXCMigratesVerifiedPersistentVolumesToDeclaredStorage(t *testing.T) {
	guest := GuestPlan{
		VMID: 110, Name: "test-dns", Hostname: "test-dns", Owner: "boetticher/module/dns",
		Tags:     []string{"boetticher-module-dns"},
		Artifact: model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content"},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "powerdns-database", Module: "dns", Guest: "test-dns", SizeGiB: 8,
			MountPath: "/var/lib/powerdns", Storage: modelStorageIDForTest, Backup: true,
		}},
	}
	before := "local:110/vm-110-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=8G"
	after := modelStorageIDForTest + ":vm-110-disk-1,mp=/var/lib/powerdns,backup=1,size=8G"
	moved := false
	legacyPath := "/var/lib/vz/images/110/vm-110-disk-1.raw"
	privilegedRunner := &recordingArgsRunner{outputs: [][]byte{[]byte(legacyPath + "\n"), []byte("/dev/loop15\n"), []byte(legacyPath + "\n"), nil}}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			mount := before
			digest := "0123456789abcdef0123456789abcdef01234567"
			if moved {
				mount = after
				digest = "0123456789abcdef0123456789abcdef01234568"
			}
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","description":"` + artifactDescription(guest.Artifact) + `","tags":"boetticher-module-dns","digest":"` + digest + `","mp0":"` + mount + `"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/move_volume":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got, want := r.Form.Get("volume"), "mp0"; got != want {
				t.Fatalf("volume = %q, want %q", got, want)
			}
			if got, want := r.Form.Get("storage"), modelStorageIDForTest; got != want {
				t.Fatalf("storage = %q, want %q", got, want)
			}
			if got, want := r.Form.Get("delete"), "1"; got != want {
				t.Fatalf("delete = %q, want %q", got, want)
			}
			moved = true
			return response([]byte(`{"data":"UPID:pve:move-volume"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:move-volume/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected LXC persistent-volume migration request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	plan := Plan{Node: "node", PrivilegedRunner: privilegedRunner, PrivilegedAddress: "192.0.2.10", PrivilegedUser: "root"}
	if err := ensureLXC(context.Background(), client, plan, guest); err != nil {
		t.Fatalf("ensureLXC() = %v", err)
	}
	if !moved {
		t.Fatal("verified LXC persistent volume was not migrated")
	}
	if got, want := privilegedRunner.args, [][]string{{"/usr/sbin/pvesm", "path", "local:110/vm-110-disk-1.raw"}, {"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", legacyPath}, {"/usr/sbin/losetup", "--noheadings", "--output", "BACK-FILE", "/dev/loop15"}, {"/usr/sbin/losetup", "--detach", "/dev/loop15"}, {"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", legacyPath}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy loop release commands = %#v, want %#v", got, want)
	}
}

func TestEnsureLXCRefusesPersistentVolumeMigrationWithoutExactIdentity(t *testing.T) {
	guest := GuestPlan{
		VMID: 110, Name: "test-dns", Hostname: "test-dns", Owner: "boetticher/module/dns",
		Tags:     []string{"boetticher-module-dns"},
		Artifact: model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content"},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "powerdns-database", Module: "dns", Guest: "test-dns", SizeGiB: 8,
			MountPath: "/var/lib/powerdns", Storage: modelStorageIDForTest, Backup: true,
		}},
	}
	moved := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","description":"` + artifactDescription(guest.Artifact) + `","tags":"boetticher-module-dns","mp0":"local:110/vm-110-disk-1.raw,mp=/var/lib/not-powerdns,backup=1,size=8G"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/move_volume":
			moved = true
			return nil
		default:
			t.Fatalf("unexpected request while rejecting LXC persistent-volume migration: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureLXC(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "refusing to migrate") {
		t.Fatalf("unproven LXC persistent volume migration = %v", err)
	}
	if moved {
		t.Fatal("unproven LXC persistent volume was moved")
	}
}

func TestMigrateLXCPersistentVolumesRestoresRunningGuestAfterMoveFailure(t *testing.T) {
	guest := GuestPlan{VMID: 110, Name: "test-dns", Volumes: []model.PersistentVolumeDeclaration{{
		Name: "powerdns-database", Module: "dns", Guest: "test-dns", SizeGiB: 8,
		MountPath: "/var/lib/powerdns", Storage: modelStorageIDForTest, Backup: true,
	}}}
	before := "local:110/vm-110-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=8G"
	stopped, restored := false, false
	legacyPath := "/var/lib/vz/images/110/vm-110-disk-1.raw"
	privilegedRunner := &recordingArgsRunner{outputs: [][]byte{[]byte(legacyPath + "\n"), []byte("/dev/loop15\n"), []byte(legacyPath + "\n"), nil}}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/current":
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/stop":
			stopped = true
			return response([]byte(`{"data":"UPID:pve:stop"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:stop/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"digest":"0123456789abcdef0123456789abcdef01234567","mp0":"` + before + `"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/move_volume":
			return response([]byte(`{"data":"UPID:pve:move-volume"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:move-volume/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"ERROR: copy failed"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/start":
			restored = true
			return response([]byte(`{"data":"UPID:pve:start"}`))
		default:
			t.Fatalf("unexpected LXC persistent-volume recovery request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	plan := Plan{Node: "node", PrivilegedRunner: privilegedRunner, PrivilegedAddress: "192.0.2.10", PrivilegedUser: "root"}
	err := migrateLXCPersistentVolumes(context.Background(), client, plan, guest, map[string]any{"mp0": before})
	if err == nil || !strings.Contains(err.Error(), "copy failed") {
		t.Fatalf("failed LXC persistent-volume move = %v", err)
	}
	if !stopped || !restored {
		t.Fatalf("running LXC was not safely restored: stopped=%t restored=%t", stopped, restored)
	}
	if got, want := privilegedRunner.args, [][]string{{"/usr/sbin/pvesm", "path", "local:110/vm-110-disk-1.raw"}, {"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", legacyPath}, {"/usr/sbin/losetup", "--noheadings", "--output", "BACK-FILE", "/dev/loop15"}, {"/usr/sbin/losetup", "--detach", "/dev/loop15"}, {"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", legacyPath}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy loop release commands = %#v, want %#v", got, want)
	}
}

func TestReleaseLegacyLXCLoopMappingFailsClosedWhenDetachFails(t *testing.T) {
	legacyPath := "/var/lib/vz/images/110/vm-110-disk-1.raw"
	runner := &recordingArgsRunner{
		outputs: [][]byte{[]byte(legacyPath + "\n"), []byte("/dev/loop15\n"), []byte(legacyPath + "\n")},
		errs:    []error{nil, nil, nil, fmt.Errorf("device busy")},
	}
	guest := GuestPlan{VMID: 110, Name: "test-dns"}
	plan := Plan{Node: "node", PrivilegedRunner: runner, PrivilegedAddress: "192.0.2.10", PrivilegedUser: "root"}
	err := releaseLegacyLXCLoopMapping(context.Background(), plan, guest, "local:110/vm-110-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=8G")
	if err == nil || !strings.Contains(err.Error(), "detach inactive legacy loop mapping") {
		t.Fatalf("failed loop release was not held: %v", err)
	}
	if got, want := runner.args, [][]string{{"/usr/sbin/pvesm", "path", "local:110/vm-110-disk-1.raw"}, {"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", legacyPath}, {"/usr/sbin/losetup", "--noheadings", "--output", "BACK-FILE", "/dev/loop15"}, {"/usr/sbin/losetup", "--detach", "/dev/loop15"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy loop release commands = %#v, want %#v", got, want)
	}
}

func TestWaitForLegacyLXCLoopReleaseFailsClosedWhenLoopRemainsAttached(t *testing.T) {
	legacyPath := "/var/lib/vz/images/110/vm-110-disk-1.raw"
	runner := &recordingArgsRunner{outputs: [][]byte{[]byte("/dev/loop15\n")}}
	plan := Plan{Node: "node", PrivilegedRunner: runner, PrivilegedAddress: "192.0.2.10", PrivilegedUser: "root"}
	err := waitForLegacyLXCLoopRelease(context.Background(), plan, "local:110/vm-110-disk-1.raw", legacyPath, "/dev/loop15", 1, 0)
	if err == nil || !strings.Contains(err.Error(), "remained attached") {
		t.Fatalf("retained loop mapping was not held: %v", err)
	}
	if got, want := runner.args, [][]string{{"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", legacyPath}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy loop release probe = %#v, want %#v", got, want)
	}
}

func TestLegacyLXCLocalRawVolumeIDRejectsUnprovenVolume(t *testing.T) {
	for _, observed := range []string{
		"local:110/vm-111-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=8G",
		"local:110/not-a-managed-volume.raw,mp=/var/lib/powerdns,backup=1,size=8G",
		"local:110/vm-110-disk--1.raw,mp=/var/lib/powerdns,backup=1,size=8G",
		"boetticher-thin:vm-110-disk-1,mp=/var/lib/powerdns,backup=1,size=8G",
	} {
		if _, err := legacyLXCLocalRawVolumeID(observed, 110); err == nil {
			t.Fatalf("unproven legacy volume %q was accepted", observed)
		}
	}
}

func TestEnsureLXCRejectsUndeclaredPersistentVolumeBeforeMigration(t *testing.T) {
	guest := GuestPlan{
		VMID: 110, Name: "test-dns", Hostname: "test-dns", Owner: "boetticher/module/dns",
		Tags:     []string{"boetticher-module-dns"},
		Artifact: model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content"},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "powerdns-database", Module: "dns", Guest: "test-dns", SizeGiB: 8,
			MountPath: "/var/lib/powerdns", Storage: modelStorageIDForTest, Backup: true,
		}},
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","description":"` + artifactDescription(guest.Artifact) + `","tags":"boetticher-module-dns","mp0":"local:110/vm-110-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=8G","mp1":"local:110/vm-110-disk-2.raw,mp=/unexpected,backup=1,size=1G"}}`))
		default:
			t.Fatalf("unexpected request while rejecting undeclared LXC volume: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureLXC(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "undeclared persistent volume") {
		t.Fatalf("undeclared LXC persistent volume was not held before migration: %v", err)
	}
}

func TestEnsureLXCRejectsUnownedGuestBeforeMutation(t *testing.T) {
	guest := GuestPlan{
		VMID: 110, Name: "test-dns", Hostname: "test-dns", Owner: "boetticher/module/dns",
		Tags: []string{"boetticher", "managed", "module", "module-dns", "boetticher-module-dns", "backup"},
	}
	mutations := 0
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"name":"user-lxc","hostname":"user-lxc","tags":"user-managed"}}`))
		default:
			mutations++
			t.Fatalf("unowned LXC triggered mutation: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureLXC(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "unowned container") {
		t.Fatalf("unowned LXC was not held before mutation: %v", err)
	}
	if mutations != 0 {
		t.Fatalf("unowned LXC issued %d mutation requests", mutations)
	}
}

func TestEnsureLXCRetainsVerifiedPersistentVolumeAcrossRootReplacement(t *testing.T) {
	guest := GuestPlan{
		VMID: 110, Name: "test-dns", Hostname: "test-dns", Owner: "boetticher/module/dns",
		Tags:     []string{"boetticher-module-dns"},
		Artifact: model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64", DefinitionSHA256: strings.Repeat("a", 64), ContentSHA256: strings.Repeat("b", 64)},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "powerdns-database", Module: "dns", Guest: "test-dns", SizeGiB: 8,
			MountPath: "/var/lib/powerdns", Storage: modelStorageIDForTest, Backup: true,
		}},
	}
	oldDescription := artifactDescription(model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64", DefinitionSHA256: strings.Repeat("a", 64), ContentSHA256: strings.Repeat("c", 64)})
	retained := modelStorageIDForTest + ":vm-110-disk-1,mp=/var/lib/powerdns,backup=1,size=8G"
	destroyed := false
	created := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			if !destroyed {
				return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","description":"` + oldDescription + `","tags":"boetticher-module-dns","mp0":"` + retained + `"}}`))
			}
			if !created {
				return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
			}
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","description":"` + artifactDescription(guest.Artifact) + `","tags":"boetticher-module-dns","mp0":"` + retained + `"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			if got, want := r.URL.Query().Get("content"), "vztmpl"; got != want {
				t.Fatalf("storage content filter = %q, want %q", got, want)
			}
			return response([]byte(`{"data":[{"volid":"local:vztmpl/boetticher-dns-blocky-1.0.0-amd64.tar.zst","checksum":"` + guest.Artifact.ContentSHA256 + `"}]}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got, want := r.Form["delete"], []string{"mp0"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("detached mount points = %#v, want %#v", got, want)
			}
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/nodes/node/lxc/110":
			if got, want := r.URL.Query().Get("destroy-unreferenced-disks"), "0"; got != want {
				t.Fatalf("destroy-unreferenced-disks = %q, want %q", got, want)
			}
			destroyed = true
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got, want := r.Form.Get("mp0"), retained; got != want {
				t.Fatalf("retained mount = %q, want exact existing reference %q", got, want)
			}
			created = true
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected LXC root replacement request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureLXC(context.Background(), client, Plan{Node: "node", Storage: modelStorageIDForTest, DestructiveConfirmed: true}, guest); err != nil {
		t.Fatalf("ensureLXC() = %v", err)
	}
}

func TestEnsureQEMUReconcilesDeclaredNetworkInterfacesBeforeStart(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", NICs: []GuestNIC{{
		Name: "wan0", Bridge: "vmbr0", Method: "dhcp", MAC: "02:00:00:00:01:01",
	}}}
	stale := "virtio=02:00:00:00:ff:ff,bridge=vmbr0,firewall=1"
	current := "virtio=02:00:00:00:01:01,bridge=vmbr0,firewall=1"
	updated := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			if updated {
				return response([]byte(`{"data":{"name":"test-fw","net0":"` + current + `"}}`))
			}
			return response([]byte(`{"data":{"name":"test-fw","net0":"` + stale + `"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got, want := r.Form.Get("net0"), "virtio,bridge=vmbr0,firewall=1,macaddr=02:00:00:00:01:01"; got != want {
				t.Fatalf("network reconciliation = %q, want %q", got, want)
			}
			updated = true
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected QEMU network reconciliation request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest); err != nil {
		t.Fatalf("ensureQEMU() = %v", err)
	}
	if !updated {
		t.Fatal("stale owned network interface was not reconciled")
	}
}

func TestEnsureQEMUHoldsUndeclaredNetworkInterfaceBeforeMutation(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", NICs: []GuestNIC{{
		Name: "wan0", Bridge: "vmbr0", Method: "dhcp", MAC: "02:00:00:00:01:01",
	}}}
	mutation := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config" {
			return response([]byte(`{"data":{"name":"test-fw","net0":"virtio=02:00:00:00:01:01,bridge=vmbr0,firewall=1","net1":"virtio=02:00:00:00:01:02,bridge=vmbr1,firewall=1"}}`))
		}
		mutation = true
		t.Fatalf("unexpected request while holding undeclared network interface: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "undeclared network interface") {
		t.Fatalf("undeclared network interface was accepted: %v", err)
	}
	if mutation {
		t.Fatal("undeclared network interface was mutated")
	}
}

func TestEnsureQEMURestoresRunningGuestAfterNetworkReconciliationFailure(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", NICs: []GuestNIC{{
		Name: "wan0", Bridge: "vmbr0", Method: "dhcp", MAC: "02:00:00:00:01:01",
	}}}
	stale := "virtio=02:00:00:00:ff:ff,bridge=vmbr0,firewall=1"
	stopped, restored := false, false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			return response([]byte(`{"data":{"name":"test-fw","net0":"` + stale + `"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/current":
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/stop":
			stopped = true
			return response([]byte(`{"data":"UPID:pve:stop"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:stop/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			return apiResponse(http.StatusBadRequest, `{"errors":{"net0":"rejected"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/start":
			restored = true
			return response([]byte(`{"data":"UPID:pve:start"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:start/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected network failure-recovery request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureQEMU(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "reconcile network interfaces") {
		t.Fatalf("failed network reconciliation = %v", err)
	}
	if !stopped || !restored {
		t.Fatalf("running guest was not safely restored: stopped=%t restored=%t", stopped, restored)
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

func TestEnsureQEMURequiresConfirmationToForceFirewallRootReplacement(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "lab-fw-01", Artifact: model.Artifact{
		Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content",
	}}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config" {
			return response([]byte(`{"data":{"name":"lab-fw-01","description":"` + artifactDescription(guest.Artifact) + `"}}`))
		}
		t.Fatalf("unexpected request before forced replacement confirmation: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureQEMU(context.Background(), client, Plan{Node: "node", ForceFirewallRootReplacement: true}, guest)
	if err == nil || !strings.Contains(err.Error(), "firewall root replacement requires --confirm") {
		t.Fatalf("forced firewall replacement without confirmation = %v", err)
	}
}

func TestEnsureQEMUForceFirewallRootReplacementPreservesVerifiedPersistentVolumes(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "firewall.qcow2")
	content := []byte("qualified firewall bytes")
	if err := os.WriteFile(artifactPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	guest := GuestPlan{
		VMID: 100, Name: "lab-fw-01",
		Artifact: model.Artifact{Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: checksum},
		Volumes: []model.PersistentVolumeDeclaration{
			{Name: "ssh-identity", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Storage: modelStorageIDForTest, Backup: true},
			{Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4, MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true},
			{Name: "firewall-telemetry", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 2, MountPath: "/var/lib/boetticher/firewall-telemetry", Storage: modelStorageIDForTest, Backup: true},
		},
	}
	plan := Plan{
		Node: "node", Storage: modelStorageIDForTest, DestructiveConfirmed: true, ForceFirewallRootReplacement: true,
		ArtifactFiles:  map[string]string{artifactKey(guest.Artifact): artifactPath},
		CloudInitFiles: CloudInitFiles{MetaData: "meta", UserData: "user", NetworkConfig: "network"},
	}
	persistent, err := qemuPersistentVolumeParams(plan, guest)
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"name": guest.Name, "description": artifactDescription(guest.Artifact)}
	for index, volume := range guest.Volumes {
		key := fmt.Sprintf("scsi%d", index+1)
		config[key] = strings.Replace(persistent[key], fmt.Sprintf("%s:%d", modelStorageIDForTest, volume.SizeGiB), fmt.Sprintf("%s:100/vm-100-disk-%d", modelStorageIDForTest, index+1), 1) + fmt.Sprintf(",size=%dG", volume.SizeGiB)
	}
	encodedConfig, err := json.Marshal(map[string]any{"data": config})
	if err != nil {
		t.Fatal(err)
	}
	cloudInitUploads := 0
	rootReplaced := false
	descriptionUpdated := false
	persistentMutation := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			return response(encodedConfig)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/upload":
			cloudInitUploads++
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			return response([]byte(`{"data":[{"volid":"local:import/boetticher-firewall-1.0.0-amd64.qcow2","filename":"boetticher-firewall-1.0.0-amd64.qcow2","checksum":"` + checksum + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			for index := range guest.Volumes {
				if r.Form.Get(fmt.Sprintf("scsi%d", index+1)) != "" {
					persistentMutation = true
				}
			}
			if r.Form.Get("scsi0") != "" {
				rootReplaced = true
				return response([]byte(`{"data":"UPID:pve:replace-root"}`))
			}
			if r.Form.Get("description") != "" {
				descriptionUpdated = true
				return response([]byte(`{"data":null}`))
			}
			t.Fatalf("unexpected QEMU config mutation: %v", r.Form)
			return nil
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:replace-root/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected forced firewall replacement request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureQEMU(context.Background(), client, plan, guest); err != nil {
		t.Fatalf("ensureQEMU() = %v", err)
	}
	if !rootReplaced || !descriptionUpdated || cloudInitUploads != 3 {
		t.Fatalf("forced root replacement incomplete: root=%t description=%t cloud-init=%d", rootReplaced, descriptionUpdated, cloudInitUploads)
	}
	if persistentMutation {
		t.Fatal("forced firewall root replacement changed a persistent volume")
	}
}

func TestEnsureQEMUForceFirewallRootReplacementHoldsWithoutVerifiedPersistentVolumes(t *testing.T) {
	guest := GuestPlan{
		VMID: 100, Name: "lab-fw-01", Artifact: model.Artifact{Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content"},
		Volumes: []model.PersistentVolumeDeclaration{{Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4, MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true}},
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config" {
			return response([]byte(`{"data":{"name":"lab-fw-01","description":"` + artifactDescription(guest.Artifact) + `","scsi1":"boetticher-thin:100/vm-100-disk-1,backup=1,serial=boetticher-other,size=4G"}}`))
		}
		t.Fatalf("unverified persistent volume allowed a replacement request: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ensureQEMU(context.Background(), client, Plan{Node: "node", DestructiveConfirmed: true, ForceFirewallRootReplacement: true}, guest)
	if err == nil || !strings.Contains(err.Error(), "does not prove the declared contract") {
		t.Fatalf("unverified persistent volume was accepted for forced root replacement: %v", err)
	}
}

func TestEnsureQEMUForceFirewallRootReplacementHoldsUndeclaredPersistentVolumes(t *testing.T) {
	volume := model.PersistentVolumeDeclaration{Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", SizeGiB: 4, MountPath: "/var/lib/kea", Storage: modelStorageIDForTest, Backup: true}
	serial, err := persistentVolumeSerial(volume)
	if err != nil {
		t.Fatal(err)
	}
	guest := GuestPlan{
		VMID: 100, Name: "lab-fw-01", Artifact: model.Artifact{Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content"},
		Volumes: []model.PersistentVolumeDeclaration{volume},
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/config" {
			return response([]byte(`{"data":{"name":"lab-fw-01","description":"` + artifactDescription(guest.Artifact) + `","scsi1":"boetticher-thin:100/vm-100-disk-1,backup=1,serial=` + serial + `,size=4G","scsi2":"boetticher-thin:100/vm-100-disk-2,backup=1,serial=boetticher-unknown,size=1G"}}`))
		}
		t.Fatalf("undeclared persistent volume allowed a replacement request: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err = ensureQEMU(context.Background(), client, Plan{Node: "node", DestructiveConfirmed: true, ForceFirewallRootReplacement: true}, guest)
	if err == nil || !strings.Contains(err.Error(), "undeclared persistent volume scsi2") {
		t.Fatalf("undeclared persistent volume was accepted for forced root replacement: %v", err)
	}
}

func TestEnsureQEMUForceFirewallRootReplacementDoesNotTargetOtherGuests(t *testing.T) {
	guest := GuestPlan{VMID: 101, Name: "test-fw", Artifact: model.Artifact{Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content"}}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/101/config" {
			return response([]byte(`{"data":{"name":"test-fw","description":"` + artifactDescription(guest.Artifact) + `"}}`))
		}
		t.Fatalf("forced firewall root replacement targeted another guest: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ensureQEMU(context.Background(), client, Plan{Node: "node", DestructiveConfirmed: true, ForceFirewallRootReplacement: true}, guest); err != nil {
		t.Fatalf("ensureQEMU() targeted a non-firewall guest: %v", err)
	}
}

func TestReplaceQEMURootDiskRestoresRunningGuestAfterFailure(t *testing.T) {
	guest := GuestPlan{VMID: 100, Name: "test-fw", Artifact: model.Artifact{Name: "boetticher-firewall", Version: "1.0.0", Architecture: "amd64", ContentSHA256: "content"}}
	stopped := false
	restored := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/current":
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/stop":
			stopped = true
			return response([]byte(`{"data":"UPID:pve:stop"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:stop/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			return response([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/100/status/start":
			restored = true
			return response([]byte(`{"data":"UPID:pve:start"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:start/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected root-replacement recovery request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := replaceQEMURootDisk(context.Background(), client, Plan{Node: "node", Storage: modelStorageIDForTest}, guest)
	if err == nil || !strings.Contains(err.Error(), "no local artifact bytes") {
		t.Fatalf("replacement preparation failure = %v", err)
	}
	if !stopped || !restored {
		t.Fatalf("running guest was not restored after root replacement failure: stopped=%t restored=%t", stopped, restored)
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

func TestValidateLegacyLXCRecreationRequiresExactOwnedRawState(t *testing.T) {
	guest := GuestPlan{
		VMID: 110, Name: "lab-dns-01", Hostname: "lab-dns-01", Owner: "boetticher/module/dns", DiskGiB: 8,
		Tags:     []string{"boetticher", "managed", "module", "module-dns", "boetticher-module-dns", "backup"},
		Security: model.GuestSecurityDeclaration{Unprivileged: true},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "ssh-identity", Module: "dns", Guest: "lab-dns-01", Storage: modelStorageIDForTest,
			SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Backup: true,
		}},
	}
	current := map[string]any{
		"name": guest.Name, "hostname": guest.Hostname, "unprivileged": 1, "tags": strings.Join(guest.Tags, ";"),
		"rootfs": "local:110/vm-110-disk-0.raw,size=8G",
		"mp0":    "local:110/vm-110-disk-1.raw,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G",
	}
	if err := validateLegacyLXCRecreation(current, guest); err != nil {
		t.Fatalf("validated legacy LXC state = %v", err)
	}
	current["mp0"] = "local:110/vm-110-disk-9.raw,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G"
	if err := validateLegacyLXCRecreation(current, guest); err == nil || !strings.Contains(err.Error(), "exact legacy") {
		t.Fatalf("non-canonical legacy volume was accepted: %v", err)
	}
}

func TestLegacyLXCRecreationAcceptsOnlyExactRetiredLiteLLMPredecessor(t *testing.T) {
	guest := GuestPlan{
		VMID: 210, Name: "lab-bifrost-01", Hostname: "lab-bifrost-01", Owner: "boetticher/module/bifrost", DiskGiB: 8,
		Tags:     []string{"boetticher", "managed", "module", "module-bifrost", "boetticher-module-bifrost", "backup"},
		Artifact: model.Artifact{Name: "boetticher-bifrost"}, Security: model.GuestSecurityDeclaration{Unprivileged: true},
		Volumes: []model.PersistentVolumeDeclaration{
			{Name: "ssh-identity", Module: "bifrost", Guest: "lab-bifrost-01", Storage: modelStorageIDForTest, SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Backup: true},
			{Name: "tls-identity", Module: "bifrost", Guest: "lab-bifrost-01", Storage: modelStorageIDForTest, SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/tls", Backup: true},
		},
	}
	current := map[string]any{
		"name": "lab-litellm-01", "hostname": "lab-litellm-01", "unprivileged": 1,
		"tags":        "backup;boetticher;boetticher-module-litellm;managed;module;module-litellm",
		"description": "boetticher-artifact=boetticher-litellm@1.0.0 definition=" + strings.Repeat("a", 64) + " content=" + strings.Repeat("b", 64),
		"rootfs":      "local:210/vm-210-disk-0.raw,size=8G",
		"mp0":         "local:210/vm-210-disk-1.raw,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G",
		"mp1":         "local:210/vm-210-disk-2.raw,mp=/var/lib/boetticher/identity/tls,backup=1,size=1G",
	}
	recreate, err := legacyLXCRecreationRequired(current, guest)
	if err != nil || !recreate {
		t.Fatalf("exact retired LiteLLM predecessor recreation = %t, %v", recreate, err)
	}
	current["description"] = "boetticher-artifact=boetticher-bifrost@1.0.0 definition=" + strings.Repeat("a", 64) + " content=" + strings.Repeat("b", 64)
	if _, err := legacyLXCRecreationRequired(current, guest); err == nil || !strings.Contains(err.Error(), "retired LiteLLM") {
		t.Fatalf("non-LiteLLM artifact predecessor was accepted: %v", err)
	}
	current["description"] = "boetticher-artifact=boetticher-litellm@1.0.0 definition=" + strings.Repeat("a", 64) + " content=" + strings.Repeat("b", 64)
	current["tags"] = "backup;boetticher;boetticher-module-bifrost;managed;module;module-bifrost"
	if _, err := legacyLXCRecreationRequired(current, guest); err == nil || !strings.Contains(err.Error(), "retired LiteLLM") {
		t.Fatalf("noncanonical LiteLLM predecessor was accepted: %v", err)
	}
}

func TestValidateLegacyLXCRecreationChecksEveryCandidateBeforeDiscard(t *testing.T) {
	legacyGuest := func(vmid int, name, module string) GuestPlan {
		return GuestPlan{
			VMID: vmid, Name: name, Hostname: name, Kind: KindLXC, Owner: "boetticher/module/" + module, DiskGiB: 8,
			Tags:     []string{"boetticher", "managed", "module", "module-" + module, "boetticher-module-" + module, "backup"},
			Security: model.GuestSecurityDeclaration{Unprivileged: true},
			Volumes: []model.PersistentVolumeDeclaration{{
				Name: "ssh-identity", Module: module, Guest: name, Storage: modelStorageIDForTest,
				SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Backup: true,
			}},
		}
	}
	dns := legacyGuest(110, "lab-dns-01", "dns")
	printer := legacyGuest(230, "lab-printer-01", "printer")
	legacyConfig := func(guest GuestPlan) string {
		return `{"data":{"name":"` + guest.Name + `","hostname":"` + guest.Hostname + `","unprivileged":1,"tags":"` + strings.Join(guest.Tags, ";") + `","rootfs":"local:` + strconv.Itoa(guest.VMID) + `/vm-` + strconv.Itoa(guest.VMID) + `-disk-0.raw,size=8G","mp0":"local:` + strconv.Itoa(guest.VMID) + `/vm-` + strconv.Itoa(guest.VMID) + `-disk-1.raw,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G"}}`
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/api2/json/nodes/node/qemu/110/config" || r.URL.Path == "/api2/json/nodes/node/qemu/230/config"):
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(legacyConfig(dns)))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/230/config":
			return response([]byte(strings.Replace(legacyConfig(printer), `"hostname":"lab-printer-01"`, `"hostname":"unexpected-host"`, 1)))
		default:
			t.Fatalf("legacy recovery preflight must not mutate guests: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	_, err := ValidateLegacyLXCRecreation(context.Background(), client, Plan{Node: "node", ForceLegacyLXCRecreation: true, Guests: []GuestPlan{dns, printer}})
	if err == nil || !strings.Contains(err.Error(), "lab-printer-01") {
		t.Fatalf("later legacy LXC mismatch did not stop the full recovery preflight: %v", err)
	}
}

func TestLegacyLXCRecreationSkipsAlreadyMigratedState(t *testing.T) {
	guest := GuestPlan{
		VMID: 110, Name: "lab-dns-01", Hostname: "lab-dns-01", Owner: "boetticher/module/dns", DiskGiB: 8,
		Tags:     []string{"boetticher", "managed", "module", "module-dns", "boetticher-module-dns", "backup"},
		Security: model.GuestSecurityDeclaration{Unprivileged: true},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "ssh-identity", Module: "dns", Guest: "lab-dns-01", Storage: modelStorageIDForTest,
			SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Backup: true,
		}},
	}
	current := map[string]any{
		"rootfs": modelStorageIDForTest + ":8,size=8G",
		"mp0":    modelStorageIDForTest + ":1,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G",
	}
	recreate, err := legacyLXCRecreationRequired(current, guest)
	if err != nil || recreate {
		t.Fatalf("already migrated state recreation = %t, %v", recreate, err)
	}
}

func TestDiscardLegacyLXCRestoresRunningGuestAfterDestroyFailure(t *testing.T) {
	guest := GuestPlan{VMID: 110, Name: "lab-dns-01", Hostname: "lab-dns-01", Owner: "boetticher/module/dns", DiskGiB: 8,
		Tags:    []string{"boetticher", "managed", "module", "module-dns", "boetticher-module-dns", "backup"},
		Volumes: []model.PersistentVolumeDeclaration{{Name: "powerdns", Module: "dns", Guest: "lab-dns-01", Storage: modelStorageIDForTest, SizeGiB: 8, MountPath: "/var/lib/powerdns", Backup: true}}}
	stopped, restored := false, false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"name":"lab-dns-01","hostname":"lab-dns-01","tags":"boetticher;managed;module;module-dns;boetticher-module-dns;backup","unprivileged":1,"rootfs":"local:110/vm-110-disk-0.raw,size=8G","mp0":"local:110/vm-110-disk-1.raw,mp=/var/lib/powerdns,backup=1,size=8G"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/current":
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/stop":
			stopped = true
			return response([]byte(`{"data":"UPID:pve:stop"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:stop/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/nodes/node/lxc/110":
			if r.URL.Query().Get("purge") != "1" || r.URL.Query().Get("destroy-unreferenced-disks") != "1" {
				t.Fatalf("legacy LXC destroy query = %v", r.URL.Query())
			}
			return apiResponse(http.StatusInternalServerError, `{"errors":{"destroy":"failure"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/start":
			restored = true
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected legacy LXC recovery request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := discardLegacyLXC(context.Background(), client, Plan{Node: "node"}, guest)
	if err == nil || !strings.Contains(err.Error(), "discard legacy state") {
		t.Fatalf("discard legacy LXC error = %v", err)
	}
	if !stopped || !restored {
		t.Fatalf("running legacy LXC was not restored after failed recreation: stopped=%t restored=%t", stopped, restored)
	}
}

func TestEnsureLXCRecreatesExactLegacyStateBeforePersistentVolumeMigration(t *testing.T) {
	artifact := model.Artifact{
		Name: "boetticher-dns-blocky", Version: "1.0.0", Architecture: "amd64",
		DefinitionSHA256: strings.Repeat("a", 64), ContentSHA256: strings.Repeat("b", 64),
	}
	guest := GuestPlan{
		VMID: 110, Name: "lab-dns-01", Hostname: "lab-dns-01", Owner: "boetticher/module/dns", DiskGiB: 8,
		Tags:     []string{"boetticher", "managed", "module", "module-dns", "boetticher-module-dns", "backup"},
		Artifact: artifact, Security: model.GuestSecurityDeclaration{Unprivileged: true},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "ssh-identity", Module: "dns", Guest: "lab-dns-01", Storage: modelStorageIDForTest,
			SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Backup: true,
		}},
	}
	current := map[string]any{
		"name": guest.Name, "hostname": guest.Hostname, "unprivileged": 1, "tags": strings.Join(guest.Tags, ";"),
		"rootfs": "local:110/vm-110-disk-0.raw,size=8G",
		"mp0":    "local:110/vm-110-disk-1.raw,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G",
	}
	created := false
	lxcConfigReads := 0
	jsonResponse := func(value any) *http.Response {
		data, err := json.Marshal(map[string]any{"data": value})
		if err != nil {
			t.Fatal(err)
		}
		return response(data)
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			lxcConfigReads++
			switch lxcConfigReads {
			case 1:
				return jsonResponse(current)
			case 2:
				return jsonResponse(current)
			case 3:
				return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
			case 4:
				if !created {
					t.Fatal("created LXC identity was read before creation")
				}
				return jsonResponse(map[string]any{
					"name": guest.Name, "hostname": guest.Hostname, "description": artifactDescription(artifact), "unprivileged": 1,
					"tags": strings.Join(guest.Tags, ";"), "rootfs": modelStorageIDForTest + ":vm-110-disk-0,size=8G",
					"mp0": modelStorageIDForTest + ":vm-110-disk-1,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G",
				})
			default:
				t.Fatalf("unexpected LXC config read %d", lxcConfigReads)
				return nil
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			return response([]byte(`{"data":[{"filename":"boetticher-dns-blocky-1.0.0-amd64.tar.zst","checksum":"` + artifact.ContentSHA256 + `"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/nodes/node/lxc/110":
			if r.URL.Query().Get("purge") != "1" || r.URL.Query().Get("destroy-unreferenced-disks") != "1" {
				t.Fatalf("legacy LXC destroy query = %v", r.URL.Query())
			}
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got, want := r.Form.Get("rootfs"), modelStorageIDForTest+":8"; got != want {
				t.Fatalf("recreated rootfs = %q, want %q", got, want)
			}
			if got, want := r.Form.Get("mp0"), modelStorageIDForTest+":1,mp=/var/lib/boetticher/identity/ssh,backup=1"; got != want {
				t.Fatalf("recreated persistent volume = %q, want %q", got, want)
			}
			created = true
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected legacy LXC recreation request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	plan := Plan{Node: "node", Storage: modelStorageIDForTest, DestructiveConfirmed: true, ForceLegacyLXCRecreation: true}
	if err := ensureLXC(context.Background(), client, plan, guest); err != nil {
		t.Fatalf("ensureLXC() = %v", err)
	}
	if !created {
		t.Fatal("legacy LXC was not recreated")
	}
}

func TestExistingLXCReconcilesPlatformNameservers(t *testing.T) {
	plan := Plan{Node: "node", Nameservers: []string{"10.10.10.10"}}
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
			if got := r.Form.Get("nameserver"); got != "10.10.10.10" {
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
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","mp0":"boetticher-thin:vm-110-disk-1,mp=/var/lib/powerdns,backup=1,size=8G","mp1":"boetticher-thin:vm-110-disk-2,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G"}}`))
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
	guest := GuestPlan{VMID: 110, Name: "test-dns", Hostname: "test-dns", Volumes: []model.PersistentVolumeDeclaration{
		{Name: "powerdns-database", Guest: "lab-dns-01", Module: "dns", Storage: modelStorageIDForTest, SizeGiB: 8, MountPath: "/var/lib/powerdns", Backup: true},
		{Name: "ssh-identity", Guest: "lab-dns-01", Module: "dns", Storage: modelStorageIDForTest, SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Backup: true},
	}}
	current := map[string]any{
		"mp0": modelStorageIDForTest + ":vm-110-disk-1,mp=/var/lib/powerdns,backup=1,size=8G",
		"mp1": modelStorageIDForTest + ":vm-110-disk-2,mp=/var/lib/boetticher/identity/ssh,backup=1,size=1G",
	}
	if _, err := replaceLXC(context.Background(), client, Plan{Node: "node"}, guest, current); err != nil {
		t.Fatalf("replaceLXC() = %v", err)
	}
	if !reflect.DeepEqual(detached, []string{"mp0", "mp1"}) {
		t.Fatalf("detached mount points = %#v, want [mp0 mp1]", detached)
	}
}

func TestReplaceLXCRestoresRunningGuestAfterDetachFailure(t *testing.T) {
	guest := GuestPlan{VMID: 110, Name: "test-dns", Hostname: "test-dns", Volumes: []model.PersistentVolumeDeclaration{{
		Name: "powerdns-database", Guest: "lab-dns-01", Module: "dns", Storage: modelStorageIDForTest,
		SizeGiB: 8, MountPath: "/var/lib/powerdns", Backup: true,
	}}}
	current := map[string]any{
		"mp0": modelStorageIDForTest + ":vm-110-disk-1,mp=/var/lib/powerdns,backup=1,size=8G",
	}
	stopped, restored := false, false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/110/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return response([]byte(`{"data":{"name":"test-dns","hostname":"test-dns","mp0":"boetticher-thin:vm-110-disk-1,mp=/var/lib/powerdns,backup=1,size=8G"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/current":
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/stop":
			stopped = true
			return response([]byte(`{"data":"UPID:pve:stop"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:stop/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/node/lxc/110/config":
			return apiResponse(http.StatusInternalServerError, `{"errors":{"delete":"failure"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/110/status/start":
			restored = true
			return response([]byte(`{"data":"UPID:pve:start"}`))
		default:
			t.Fatalf("unexpected LXC root replacement recovery request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	_, err := replaceLXC(context.Background(), client, Plan{Node: "node"}, guest, current)
	if err == nil || !strings.Contains(err.Error(), "detach persistent volumes") {
		t.Fatalf("failed LXC persistent-volume detach = %v", err)
	}
	if !stopped || !restored {
		t.Fatalf("running LXC was not restored after detach failure: stopped=%t restored=%t", stopped, restored)
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
		VMID:    200,
		Name:    "lab-tailnet-01",
		Volumes: []model.PersistentVolumeDeclaration{{Storage: modelStorageIDForTest, SizeGiB: 4, MountPath: "/var/lib/tailscale", Placement: model.StorageDefault, Backup: true}},
	}
	current := map[string]any{
		"mp0": "boetticher-thin:vm-200-disk-1,mp=/var/lib/tailscale,backup=1,size=4G",
		"mp1": "boetticher-thin:vm-200-disk-2,mp=/unexpected,backup=1,size=1G",
	}
	if err := validateExistingGuestVolumes(current, guest); err == nil || !strings.Contains(err.Error(), "undeclared persistent volume") {
		t.Fatalf("undeclared LXC mountpoint was accepted: %v", err)
	}
}

func TestExistingLXCPersistentVolumesAcceptProxmoxCanonicalVolumeID(t *testing.T) {
	guest := GuestPlan{VMID: 110, Name: "test-dns", Volumes: []model.PersistentVolumeDeclaration{{
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
	current["mp0"] = "boetticher-thin:110/vm-110-disk-9.raw,mp=/var/lib/powerdns,backup=1,size=8G"
	if err := validateExistingGuestVolumes(current, guest); err == nil {
		t.Fatal("LXC volume with the wrong canonical VMID/slot identity was accepted")
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
	privilegedRunner := &recordingArgsRunner{}
	plan := Plan{
		Node:              "node",
		Storage:           "local",
		Guests:            []GuestPlan{guest},
		ArtifactFiles:     map[string]string{artifactKey(artifact): artifactPath},
		PrivilegedRunner:  privilegedRunner,
		PrivilegedAddress: "192.0.2.10",
		PrivilegedUser:    "root",
	}
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
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse create form: %v", err)
			}
			if got := r.Form.Get("dev0"); got != "" {
				t.Fatalf("scoped API create unexpectedly received dev0=%q", got)
			}
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
	if privilegedRunner.address != "192.0.2.10" || privilegedRunner.user != "root" || len(privilegedRunner.args) != 1 {
		t.Fatalf("unexpected privileged device configuration calls: %#v", privilegedRunner)
	}
	if got, want := privilegedRunner.args[0], []string{"/usr/sbin/pct", "set", "200", "--dev0", "path=/dev/net/tun,mode=0666"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("privileged device configuration args = %#v, want %#v", got, want)
	}
}

func TestDeviceBearingLXCMustHavePrivilegedAuthorityBeforeStorageMutation(t *testing.T) {
	artifact := model.Artifact{
		Name:             "boetticher-tailnet-router",
		Version:          "1.0.0",
		Architecture:     "amd64",
		Kind:             "lxc",
		DefinitionSHA256: strings.Repeat("a", 64),
		ContentSHA256:    strings.Repeat("b", 64),
	}
	guest := GuestPlan{
		VMID:     200,
		Name:     "lab-tailnet-01",
		Hostname: "lab-tailnet-01",
		Kind:     KindLXC,
		Owner:    "boetticher/module/tailnet-router",
		Artifact: artifact,
		Security: model.GuestSecurityDeclaration{
			Unprivileged: true,
			Devices:      []model.DeviceRequirement{{Path: "/dev/net/tun", Type: "c", Major: 10, Minor: 200, Access: "rwm"}},
		},
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && (r.URL.Path == "/api2/json/nodes/node/qemu/200/config" || r.URL.Path == "/api2/json/nodes/node/lxc/200/config") {
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		}
		t.Fatalf("unexpected request before privileged authority validation: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := ProvisionModule(context.Background(), client, Plan{Node: "node", Storage: "local", Guests: []GuestPlan{guest}}, "tailnet-router")
	if err == nil || !strings.Contains(err.Error(), "authorized root bootstrap path") {
		t.Fatalf("missing privileged authority was not held before mutation: %v", err)
	}
}

func TestCreatedLXCDeviceIsAppliedBeforeStart(t *testing.T) {
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
	privilegedRunner := &recordingArgsRunner{}
	plan := Plan{
		Node:              "node",
		Storage:           "local",
		Guests:            []GuestPlan{guest},
		ArtifactFiles:     map[string]string{artifactKey(artifact): artifactPath},
		PrivilegedRunner:  privilegedRunner,
		PrivilegedAddress: "192.0.2.10",
		PrivilegedUser:    "root",
	}
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
			return response([]byte(`{"data":{"name":"lab-tailnet-01","hostname":"lab-tailnet-01","description":"` + artifactDescription(artifact) + `","unprivileged":1,"dev0":"path=/dev/net/tun,mode=0666","tags":"boetticher;managed;module;module-tailnet-router;boetticher-module-tailnet-router;backup"}}`))
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
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse create form: %v", err)
			}
			if got := r.Form.Get("dev0"); got != "" {
				t.Fatalf("scoped API create unexpectedly received dev0=%q", got)
			}
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/200/status/current":
			return response([]byte(`{"data":{"status":"stopped"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc/200/status/start":
			started = true
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected LXC device provisioning request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := ProvisionModule(context.Background(), client, plan, "tailnet-router"); err != nil {
		t.Fatalf("ProvisionModule() = %v", err)
	}
	if !started {
		t.Fatal("LXC start was not requested after exact device verification")
	}
	if privilegedRunner.address != "192.0.2.10" || privilegedRunner.user != "root" || len(privilegedRunner.args) != 1 {
		t.Fatalf("unexpected privileged device configuration calls: %#v", privilegedRunner)
	}
	if got, want := privilegedRunner.args[0], []string{"/usr/sbin/pct", "set", "200", "--dev0", "path=/dev/net/tun,mode=0666"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("privileged device configuration args = %#v, want %#v", got, want)
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
