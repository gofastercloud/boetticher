package site

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPendingDNSDeletionsAreControllerLocalAndValidated(t *testing.T) {
	runtimeRoot := t.TempDir()
	t.Setenv("BOETTICHER_RUNTIME_DIR", runtimeRoot)
	s := model.NewDefaultSite("installation", "age1example")

	if got, err := LoadPendingDNSDeletions(t.TempDir(), s); err != nil || len(got) != 0 {
		t.Fatalf("missing pending state = %#v, %v", got, err)
	}
	input := []model.DNSDeletion{
		{Name: "old.lab.home.arpa.", Type: "cname"},
		{Name: "old.lab.home.arpa", Type: "CNAME"},
	}
	if err := SavePendingDNSDeletions(t.TempDir(), s, input); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPendingDNSDeletions(t.TempDir(), s)
	if err != nil || len(got) != 1 || got[0] != (model.DNSDeletion{Name: "old.lab.home.arpa", Type: "CNAME"}) {
		t.Fatalf("pending state = %#v, %v", got, err)
	}

	path := filepath.Join(RuntimeDir(s), pendingDNSDeletionsFile)
	if err := os.WriteFile(path, []byte(`[{"name":"bad.example","type":"TXT"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPendingDNSDeletions(t.TempDir(), s); err == nil {
		t.Fatal("invalid controller-local DNS state was silently accepted")
	}
	if err := SavePendingDNSDeletions(t.TempDir(), s, []model.DNSDeletion{{Name: "app.servers.lab.home.arpa", Type: "A"}, {Name: "proxmox.lab.home.arpa", Type: "A"}, {Name: "old.lab.home.arpa", Type: "A"}}); err != nil {
		t.Fatal(err)
	}
	got, err = LoadPendingDNSDeletions(t.TempDir(), s)
	if err != nil || len(got) != 1 || got[0].Name != "old.lab.home.arpa" {
		t.Fatalf("unsafe or platform-owned pending state was retained: %#v, %v", got, err)
	}
}

func TestLoadPendingDNSDeletionsRejectsSymlinkedRuntimeState(t *testing.T) {
	runtimeRoot := t.TempDir()
	t.Setenv("BOETTICHER_RUNTIME_DIR", runtimeRoot)
	s := model.NewDefaultSite("installation", "age1example")
	if err := SavePendingDNSDeletions(t.TempDir(), s, []model.DNSDeletion{{Name: "old.lab.home.arpa", Type: "A"}}); err != nil {
		t.Fatal(err)
	}

	dnsDir := filepath.Join(RuntimeDir(s), "dns")
	if err := os.Remove(filepath.Join(dnsDir, filepath.Base(pendingDNSDeletionsFile))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dnsDir); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "pending-deletions.json"), []byte(`[{"name":"old.lab.home.arpa","type":"A"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, dnsDir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPendingDNSDeletions(t.TempDir(), s); err == nil {
		t.Fatal("symlinked pending DNS state was followed")
	}
}
