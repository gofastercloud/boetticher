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
