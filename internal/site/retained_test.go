package site

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestRetainedModuleStateRoundTripsWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	want := []model.RetainedModule{{Module: "monitoring", Disposition: "retained", Guests: []model.Component{{Name: "lab-monitor-01", Hostname: "lab-monitor-01", Zone: "INFRA", Address: "10.10.10.20", VMID: model.MonitorVMID, Module: "monitoring", ProductOwned: true, SSHManaged: true, Tags: []string{model.TagBoetticher, model.TagManaged, model.TagModule, "module-monitoring", model.ModuleOwnershipTag("monitoring"), model.TagBackup}}}, Persistent: []model.PersistentState{{Name: "pulse-state", Replacement: "retain-across-rootfs-replacement"}}}}
	if err := SaveRetainedModules(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRetainedModules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Module != "monitoring" || got[0].Guests[0].VMID != model.MonitorVMID {
		t.Fatalf("unexpected retained state: %#v", got)
	}
}

func TestLoadRetainedModulesRejectsUnsafeGuestHostname(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal([]model.RetainedModule{{Module: "monitoring", Guests: []model.Component{{Name: "retained", Hostname: "retained;id", Zone: "INFRA", Address: "10.10.10.20"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, retainedModulesPath), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRetainedModules(dir); err == nil {
		t.Fatal("unsafe retained hostname was accepted")
	}
}

func TestLoadRetainedModulesRejectsSymlinkedStateFile(t *testing.T) {
	dir := t.TempDir()
	external := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(external, "retained.json"), []byte("[]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(external, "retained.json"), filepath.Join(dir, retainedModulesPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRetainedModules(dir); err == nil {
		t.Fatal("symlinked retained state file was accepted")
	}
}
