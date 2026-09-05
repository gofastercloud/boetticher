package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/cli"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/storage"
)

func TestPublicDocumentationMatchesV03Model(t *testing.T) {
	root := repositoryRoot(t)
	read := func(path string) string {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}
	readme := read("README.md")
	home := read("docs/index.md")
	start := read("docs/start.md")
	lab := read("docs/lab.md")
	modules := read("docs/modules.md")
	commands := read("docs/commands.md")
	site := model.NewDefaultSite("contract-installation", "age1contract")

	for _, want := range []string{
		model.QualifiedGatewayImage,
		"Pulse Community " + model.PulseVersion,
		model.DefaultDomain,
		"VLAN 5 TRANSIT",
		"VLAN 10 INFRA",
		"VLAN 20 SERVERS",
		"VLAN 30 TRUSTED",
		"VLAN 40 SANDBOX",
		"VLAN 99 MGMT",
		"100–199",
		"200–499",
		"500–899",
		storage.VolumeGroup,
		storage.GuestStorageID,
		storage.BackupStorageID,
	} {
		if !strings.Contains(readme, want) && !strings.Contains(home, want) && !strings.Contains(start, want) && !strings.Contains(lab, want) {
			t.Errorf("public documentation is missing model contract %q", want)
		}
	}
	for _, component := range site.PlatformComponents() {
		if !strings.Contains(readme, component.Hostname) && !strings.Contains(lab, component.Hostname) {
			t.Errorf("public architecture is missing platform hostname %q", component.Hostname)
		}
		if component.URL != "" && !strings.Contains(readme, component.URL) && !strings.Contains(lab, component.URL) {
			t.Errorf("public architecture is missing platform URL %q", component.URL)
		}
	}
	for _, want := range []string{
		"boetticher deploy [--plan DIGEST] [--site DIR] [--age-identity PATH] [--only-module NAME] [--confirm]",
		"boetticher enroll [--site DIR] [--bootstrap-address ADDRESS] [--operator-key PATH] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--known-hosts PATH] [--proxmox-ca PATH] [--initial-user USER] [--insecure] [--trunk-interface IFACE] [--replace-scoped-credentials] [--dry-run]",
		"boetticher companion add|setup|status|migrate ...",
	} {
		if !strings.Contains(commands, want) {
			t.Errorf("command reference is missing %q", want)
		}
	}
	for _, want := range []string{"companion add --mac", model.CompanionHostname, model.CompanionAddress, "desired state only"} {
		if !strings.Contains(start, want) && !strings.Contains(lab, want) {
			t.Errorf("Companion documentation is missing %q", want)
		}
	}
	for name, document := range map[string]string{"README.md": readme, "docs/index.md": home, "docs/start.md": start, "docs/lab.md": lab, "docs/modules.md": modules, "docs/commands.md": commands} {
		if !strings.Contains(document, model.ReleaseVersion) {
			t.Errorf("%s is missing current release %s", name, model.ReleaseVersion)
		}
		if strings.Contains(document, "0.5.1") {
			t.Errorf("%s retains the internal 0.5.1 milestone as the public release", name)
		}
	}
	if strings.Contains(modules, "fresh 0.5 site") {
		t.Error("docs/modules.md retains the internal 0.5 milestone as the fresh-site release")
	}
}

func TestCommandReferenceIsGeneratedFromCLIContract(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "commands.md"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cli.CommandReferenceMarkdown(); string(data) != got {
		t.Fatal("docs/commands.md is stale; run make command-docs")
	}
}

func TestDocsSiteKeepsOneSmallGuideSet(t *testing.T) {
	root := repositoryRoot(t)
	guideNames := []string{"index.md", "start.md", "lab.md", "modules.md", "commands.md"}
	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatal(err)
	}
	guides := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, "docs", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(string(data), "---\nlayout: default\n") {
			guides++
		}
	}
	if guides != len(guideNames) {
		t.Fatalf("docs site has %d Jekyll guides, want %d", guides, len(guideNames))
	}
	for _, name := range guideNames {
		data, err := os.ReadFile(filepath.Join(root, "docs", name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(data), "---\nlayout: default\n") {
			t.Errorf("docs/%s is not a Jekyll site page", name)
		}
	}
	for _, path := range []string{
		"docs/_config.yml",
		"docs/_layouts/default.html",
		"docs/assets/site.css",
		"docs/images/boetticher-cover.jpg",
		"docs/images/workbench-hero.webp",
		"docs/images/build-bench.webp",
		"docs/images/network-lab.webp",
	} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Errorf("docs site asset %s: %v", path, err)
		}
	}
}

func TestV3SchemaMatchesRuntimeVersion(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "schemas", "site.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Const any `json:"const"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties["api_version"].Const != model.APIVersion {
		t.Fatalf("schema api_version does not match model: %#v", schema.Properties["api_version"].Const)
	}
	if schema.Properties["schema_version"].Const != float64(model.SchemaVersion) {
		t.Fatalf("schema_version does not match model: %#v", schema.Properties["schema_version"].Const)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("locate documentation contract test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
