package portal

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
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

func TestPortalHomeUsesCanonicalSemanticStatus(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	canonical := statusmodel.Report{
		StatusModelVersion: statusmodel.ModelVersion,
		ModelRevision:      "revision",
		ObservedAt:         "2026-08-29T00:00:00Z",
		OverallState:       statusmodel.Healthy,
	}
	content := home(site, "revision", Evidence{
		GeneratedAt: "2026-08-29T00:00:00Z",
		Results:     []CheckResult{{Name: "legacy evidence", Status: "FAIL", Detail: "stale presentation"}},
		Status:      &canonical,
	}, time.Unix(0, 0))
	if !strings.Contains(content, "Lab result: PASS") {
		t.Fatalf("portal did not use canonical semantic status: %s", content)
	}
	if !strings.Contains(content, "Lab revision: <code>revision</code>") {
		t.Fatalf("portal home omitted the model revision: %s", content)
	}
}

func TestPortalHomeDoesNotChurnWithGenerationTime(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	evidence := Evidence{GeneratedAt: "2026-08-29T00:00:00Z"}
	first := home(site, "revision", evidence, time.Unix(1, 0))
	second := home(site, "revision", evidence, time.Unix(2, 0))
	if first != second {
		t.Fatal("portal home changed when only the generation time changed")
	}
	if !strings.Contains(first, "observed: 2026-08-29T00:00:00Z") {
		t.Fatalf("portal home omitted the recorded observation time: %s", first)
	}
}

func TestPortalRejectsSymlinkedOutputParentBeforePublication(t *testing.T) {
	dir := t.TempDir()
	external := t.TempDir()
	sentinel := filepath.Join(external, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(dir, "generated")); err != nil {
		t.Fatal(err)
	}
	err := Build(model.NewDefaultSite("installation", "age1example"), filepath.Join(dir, "generated", "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0))
	if err == nil {
		t.Fatal("portal accepted a symlinked output parent")
	}
	got, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(got) != "keep" {
		t.Fatalf("external portal sentinel changed: %q, %v", got, readErr)
	}
}

func TestPortalRejectsSymlinkedPreviousTree(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "portal")
	if err := Build(model.NewDefaultSite("installation", "age1example"), output, "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	sentinel := filepath.Join(external, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, output+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := Build(model.NewDefaultSite("installation", "age1example"), output, "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err == nil {
		t.Fatal("portal accepted a symlinked previous tree")
	}
	got, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(got) != "keep" {
		t.Fatalf("external previous sentinel changed: %q, %v", got, readErr)
	}
}

func TestPortalRejectsSymlinkedSourceDocument(t *testing.T) {
	dir := t.TempDir()
	docs := filepath.Join(dir, "docs")
	if err := os.Mkdir(docs, 0700); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(external, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(docs, "runbook.md")); err != nil {
		t.Fatal(err)
	}
	if err := Build(model.NewDefaultSite("installation", "age1example"), filepath.Join(dir, "portal"), docs, Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err == nil {
		t.Fatal("portal accepted a symlinked source document")
	}
}

func TestPortalGuideCopyOmitsSiteFrontMatter(t *testing.T) {
	dir := t.TempDir()
	docs := filepath.Join(dir, "docs")
	if err := os.Mkdir(docs, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "guide.md"), []byte("---\nlayout: default\ntitle: A guide\n---\n\n# Hello from the guide\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Build(model.NewDefaultSite("installation", "age1example"), filepath.Join(dir, "portal"), docs, Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "portal", "docs", "guide.html"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	if strings.Contains(page, "layout: default") || strings.Contains(page, "title: A guide") {
		t.Fatalf("portal copied Jekyll front matter into the guide: %s", page)
	}
	if !strings.Contains(page, "# Hello from the guide") {
		t.Fatalf("portal lost the guide body: %s", page)
	}
}

func TestContentDigestIsStableAndChangesWithPortalContent(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "portal")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("one"), 0644); err != nil {
		t.Fatal(err)
	}
	first, err := ContentDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ContentDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("content digest was not stable: %q %q", first, second)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("two"), 0644); err != nil {
		t.Fatal(err)
	}
	third, err := ContentDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("content digest did not change after portal content changed")
	}
}

func TestContentDigestRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "portal")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside.html")
	if err := os.WriteFile(target, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	if _, err := ContentDigest(root); err == nil {
		t.Fatal("content digest accepted a symlink")
	}
}

func TestContentDigestUsesGlobalRelativePathOrder(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "portal")
	if err := os.MkdirAll(filepath.Join(root, "docs", "operations"), 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"docs/operations.html":      "sibling",
		"docs/operations/logs.html": "nested",
	}
	for relative, content := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(relative)), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	hash := sha256.New()
	for _, relative := range []string{"docs/operations.html", "docs/operations/logs.html"} {
		fmt.Fprintf(hash, "%s\x00", relative)
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = hash.Write(content)
	}
	want := hex.EncodeToString(hash.Sum(nil))
	got, err := ContentDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("content digest = %q, want globally sorted path digest %q", got, want)
	}
}

func TestContentArchiveIsDeterministicAndRootless(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "portal")
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("index"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "readme.html"), []byte("readme"), 0644); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(dir, "first.tar")
	secondPath := filepath.Join(dir, "second.tar")
	if err := ContentArchive(root, firstPath); err != nil {
		t.Fatal(err)
	}
	if err := ContentArchive(root, secondPath); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("portal archives were not deterministic")
	}
	reader := tar.NewReader(bytes.NewReader(first))
	seen := map[string]string{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if filepath.IsAbs(header.Name) || strings.HasPrefix(header.Name, "../") {
			t.Fatalf("portal archive contains an unsafe path %q", header.Name)
		}
		if header.Name != "docs" && header.Name != "docs/readme.html" && header.Name != "index.html" {
			t.Fatalf("portal archive contains unexpected path %q", header.Name)
		}
		if header.Typeflag == tar.TypeReg {
			content, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			seen[header.Name] = string(content)
		}
	}
	if seen["index.html"] != "index" || seen["docs/readme.html"] != "readme" {
		t.Fatalf("portal archive contents = %#v", seen)
	}
}

func TestContentArchiveRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "portal")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside.html")
	if err := os.WriteFile(target, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := ContentArchive(root, filepath.Join(dir, "portal.tar")); err == nil {
		t.Fatal("portal archive accepted a symlink")
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
		"native product UI or API",
		"quick lab overview and the latest check results",
		"Proxmox console or exec",
		"Normal SSH and hands-on changes to Boetticher appliances are not part of the everyday workflow",
		"internal deployment plumbing",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("portal access page missing %q", want)
		}
	}
	if strings.Contains(page, "ProxyJump lab-bastion") || strings.Contains(page, "ssh lab-bastion") {
		t.Fatalf("portal access page presents routine appliance SSH: %s", page)
	}
}

func TestExternalPortalKeepsExternalApplianceOperatorManaged(t *testing.T) {
	dir := t.TempDir()
	site := model.NewSite("installation", "age1example", model.GatewayModeExternal)
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: "virtual-only"}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "portal", "access.html"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	if !strings.Contains(page, "external firewall is yours to run") || !strings.Contains(page, "does not manage the appliance") {
		t.Fatalf("external portal omitted the external-appliance boundary: %s", page)
	}
	if strings.Contains(page, "hands-on changes to Boetticher appliances are not part of the everyday workflow") {
		t.Fatalf("external portal applied Core-only prohibition to external appliance: %s", page)
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
	if !strings.Contains(page, "internal deployment path") {
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
		{Module: "dns", Artifact: model.Artifact{Name: "boetticher-dns-blocky", Version: "1.0.0", DefinitionSHA256: strings.Repeat("a", 64)}},
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
	for _, want := range []string{"Enabled modules", "Action required:", "Useful links"} {
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
	if !strings.Contains(string(data), "tailnet-router") {
		t.Fatal("portal omitted the module summary")
	}
}
