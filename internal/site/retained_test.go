package site

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestRetainedModuleStateRoundTripsWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	want := []model.RetainedModule{{Module: "monitoring", Disposition: "retained", Guests: []model.Component{{Name: "lab-monitor-01", VMID: model.MonitorVMID}}, Persistent: []model.PersistentState{{Name: "postgresql-data", Replacement: "retain-across-rootfs-replacement"}}}}
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
