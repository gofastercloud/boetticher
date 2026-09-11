package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSnapshotRedactsDesiredConfigAndCarriesUnknownFacts(t *testing.T) {
	root := t.TempDir()
	lab := filepath.Join(root, "lab.yml")
	docs := filepath.Join(root, "docs")
	if err := os.MkdirAll(docs, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "modules.md"), []byte("# Modules\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lab, []byte(`api_version: boetticher/v3
network:
  domain: example.test
modules:
  observability:
    enabled: true
    api_key: must-not-leak
`), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 11, 1, 0, 0, 0, time.UTC)
	snapshot, err := buildSnapshot(lab, "", docs, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), "must-not-leak") {
		t.Fatal("snapshot leaked a secret-shaped value")
	}
	if snapshot.Schema != snapshotSchema || snapshot.Generation != "20260911T010000Z" || snapshot.Stale {
		t.Fatalf("snapshot metadata = %#v", snapshot)
	}
	if len(snapshot.Documents) != 1 || snapshot.Documents[0].Path != "modules.md" {
		t.Fatalf("documents = %#v", snapshot.Documents)
	}
	foundUnknown := false
	for _, item := range snapshot.Observations {
		if item.Name == "module.observability" && item.State == "unknown" {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Fatalf("observations = %#v", snapshot.Observations)
	}
}

func TestSnapshotAtomicPublishAndStaleRead(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Add(-11 * time.Minute)
	snapshot := labSnapshot{Schema: snapshotSchema, Generation: "old", GeneratedAt: now, StaleAfter: now.Add(snapshotStaleAge)}
	if err := writeSnapshotAtomic(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got, err := readSnapshot(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Stale || got.Generation != "old" {
		t.Fatalf("stale snapshot = %#v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "snapshot.json")); err != nil {
		t.Fatal(err)
	}
}
