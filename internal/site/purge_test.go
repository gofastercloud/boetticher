package site

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPurgeIntentRoundTripAndClear(t *testing.T) {
	dir := t.TempDir()
	intent := PurgeIntent{
		Module:        "printer",
		ModelRevision: "sha256:revision",
		CreatedAt:     "2026-08-29T00:00:00Z",
		Guests:        []PurgeGuest{{VMID: model.PrinterVMID, Name: "lab-printer-01", Kind: "lxc", Owner: "boetticher/module/printer"}},
	}
	if err := SavePurgeIntent(dir, intent); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := LoadPurgeIntent(dir)
	if err != nil || !found {
		t.Fatalf("LoadPurgeIntent() = %#v, %v, found=%t", loaded, err, found)
	}
	if loaded.Version != purgeIntentVersion || loaded.Module != intent.Module || loaded.Guests[0] != intent.Guests[0] {
		t.Fatalf("purge intent changed on round trip: %#v", loaded)
	}
	if err := ClearPurgeIntent(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, purgeIntentPath)); !os.IsNotExist(err) {
		t.Fatalf("purge intent remains after clear: %v", err)
	}
}

func TestPurgeIntentRejectsWrongOwner(t *testing.T) {
	err := SavePurgeIntent(t.TempDir(), PurgeIntent{
		Module:        "printer",
		ModelRevision: "sha256:revision",
		CreatedAt:     "2026-08-29T00:00:00Z",
		Guests:        []PurgeGuest{{VMID: model.PrinterVMID, Name: "lab-printer-01", Kind: "lxc", Owner: "user"}},
	})
	if err == nil {
		t.Fatal("purge intent accepted an unowned guest")
	}
}
