package contract

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/storage"
)

func TestPublicDocumentationMatchesV01Model(t *testing.T) {
	root := repositoryRoot(t)
	read := func(path string) string {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}
	readme := read("README.md")
	architecture := read("docs/architecture.md")
	ownership := read("docs/platform-ownership.md")
	commands := read("docs/commands.md")
	site := model.NewDefaultSite("contract-installation", "age1contract")

	for _, want := range []string{
		"OPNsense " + model.QualifiedOPNsense,
		"Zabbix " + model.ZabbixSeries,
		model.DefaultDomain,
		"VLAN 10 TRUSTED",
		"VLAN 20 SERVERS",
		"VLAN 50 SANDBOX",
		"VLAN 99 MGMT",
		"100–199",
		"200–499",
		"500–899",
		storage.VolumeGroup,
		storage.GuestStorageID,
		storage.BackupStorageID,
	} {
		if !strings.Contains(readme, want) && !strings.Contains(architecture, want) && !strings.Contains(ownership, want) && !strings.Contains(read("docs/storage/dedicated-data-disk.md"), want) {
			t.Errorf("public documentation is missing model contract %q", want)
		}
	}
	for _, component := range site.PlatformComponents() {
		if !strings.Contains(readme, component.Hostname) && !strings.Contains(architecture, component.Hostname) {
			t.Errorf("public architecture is missing platform hostname %q", component.Hostname)
		}
		if component.URL != "" && !strings.Contains(readme, component.URL) && !strings.Contains(architecture, component.URL) {
			t.Errorf("public architecture is missing platform URL %q", component.URL)
		}
	}
	for _, want := range []string{
		"boetticher converge [--site DIR] [--age-identity PATH] [--opnsense-url URL] [--opnsense-ca PATH] [--proxmox-ca PATH] [--zabbix-url URL] [--insecure] [--ansible-playbook PATH] [--dry-run]",
		"boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--opnsense-iso PATH] [--trunk-interface IFACE] [--dry-run]",
	} {
		if !strings.Contains(commands, want) {
			t.Errorf("command reference is missing %q", want)
		}
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
