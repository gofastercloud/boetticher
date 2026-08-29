package portal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

func TestExternalPortalDoesNotPublishManagedGatewayOrBackupID(t *testing.T) {
	dir := t.TempDir()
	site := model.NewSite("installation", "age1example", model.GatewayModeExternal)
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	networkPage, err := os.ReadFile(filepath.Join(dir, "portal", "network.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(networkPage), "managed gateway vNICs") || strings.Contains(string(networkPage), "Debian lab-fw-01") {
		t.Fatal("external portal published managed gateway details")
	}
	recoveryPage, err := os.ReadFile(filepath.Join(dir, "portal", "recovery.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(recoveryPage), "100, 110") {
		t.Fatal("external portal published the absent firewall VMID")
	}
}

func TestManagedPortalPublishesGatewayDetails(t *testing.T) {
	dir := t.TempDir()
	site := model.NewDefaultSite("installation", "age1example")
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	networkPage, err := os.ReadFile(filepath.Join(dir, "portal", "network.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(networkPage), "managed gateway vNICs") {
		t.Fatal("managed portal omitted gateway vNIC details")
	}
}

func TestPortalPublishesSupportedApplianceManagementBoundary(t *testing.T) {
	dir := t.TempDir()
	site := model.NewDefaultSite("installation", "age1example")
	site.BootstrapAddress = "192.0.2.10"
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "portal", "access.html"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, want := range []string{
		"Boetticher CLI",
		"native product UI/API",
		"generated portal/status surfaces",
		"Proxmox console/exec",
		"Routine operator SSH and hand mutation of Core appliances are unsupported",
		"internal controller",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("portal access page missing %q", want)
		}
	}
	if strings.Contains(page, "ProxyJump lab-bastion") || strings.Contains(page, "ssh lab-bastion") {
		t.Fatalf("portal access page presents routine appliance SSH: %s", page)
	}
}

func TestPortalServicesDoesNotPresentSSHAsOperatorInterface(t *testing.T) {
	dir := t.TempDir()
	if err := Build(model.NewDefaultSite("installation", "age1example"), filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "portal", "services.html"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	if strings.Contains(page, "<th>SSH</th>") || strings.Contains(page, "managed via lab-bastion") {
		t.Fatalf("portal services page presents SSH as an operator interface: %s", page)
	}
	if !strings.Contains(page, "internal controller transport") {
		t.Fatal("portal services page omitted the internal transport boundary")
	}
}

func TestPortalPublishesModuleArtifactAndLoggingSummary(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Modules = []model.ResolvedModule{
		{Name: "dns", Version: "1.0.0", Policy: "mandatory", Enabled: true, Reason: "mandatory", State: "Enabled"},
		{Name: "logging", Version: "1.0.0", Policy: "mandatory", Enabled: true, Reason: "mandatory", State: "Enabled"},
	}
	site.Declarations = []model.ModuleDeclaration{
		{Module: "dns", Artifact: model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", Provider: "blocky", DefinitionSHA256: strings.Repeat("a", 64)}},
		{Module: "logging", Artifact: model.Artifact{Name: "boetticher-logging", Version: "1.0.0", DefinitionSHA256: strings.Repeat("b", 64)}},
	}
	dir := t.TempDir()
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "portal", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, want := range []string{"boetticher-dns-blocky", "prefer-data-disk", "backup=false", "logs.lab.home.arpa:19532"} {
		if !strings.Contains(page, want) {
			t.Fatalf("portal omitted %q", want)
		}
	}
	if strings.Contains(page, "<th>Qualification</th>") {
		t.Fatal("portal exposed controller-only artifact qualification")
	}
	if strings.Contains(page, "content_sha256") || strings.Contains(page, "BEGIN PRIVATE KEY") {
		t.Fatal("portal exposed internal secret/evidence material")
	}
}

func TestPortalUsesModuleDeclarationForFirstPartyModuleSummary(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Modules = []model.ResolvedModule{{Name: "tailnet-router", Version: "1.0.0", Policy: "default-off", Enabled: true, State: "Enabled"}}
	site.Declarations = []model.ModuleDeclaration{{
		Module:   "tailnet-router",
		Artifact: model.Artifact{Name: "boetticher-tailnet-router", Version: "1.0.0", DefinitionSHA256: strings.Repeat("a", 64)},
		Portal:   []model.PortalEntry{{Name: "tailnet-router", Description: "Tailscale subnet router"}},
	}}
	dir := t.TempDir()
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "portal", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Tailscale subnet router") {
		t.Fatal("portal omitted the module declaration summary")
	}
}
