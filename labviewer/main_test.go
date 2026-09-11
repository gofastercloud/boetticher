package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLabHandlerServesUIAndPreservesDataRoutes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snapshot.json"), []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	docs := t.TempDir()
	if err := os.WriteFile(filepath.Join(docs, "lab.md"), []byte("docs"), 0600); err != nil {
		t.Fatal(err)
	}
	h := labHandler(dir, docs)

	ui := httptest.NewRecorder()
	h.ServeHTTP(ui, httptest.NewRequest("GET", "/lab/", nil))
	if ui.Code != 200 || !strings.Contains(ui.Body.String(), "Lab Snapshot") {
		t.Fatalf("/lab/ did not serve the UI: status=%d body=%q", ui.Code, ui.Body.String())
	}

	snapshot := httptest.NewRecorder()
	h.ServeHTTP(snapshot, httptest.NewRequest("GET", "/lab/snapshot.json", nil))
	if snapshot.Code != 200 || !strings.Contains(snapshot.Body.String(), `"schema"`) {
		t.Fatalf("snapshot route changed: status=%d body=%q", snapshot.Code, snapshot.Body.String())
	}

	doc := httptest.NewRecorder()
	h.ServeHTTP(doc, httptest.NewRequest("GET", "/lab/docs/lab.md", nil))
	if doc.Code != 200 || doc.Body.String() != "docs" {
		t.Fatalf("docs route changed: status=%d body=%q", doc.Code, doc.Body.String())
	}
}

func TestRedactHidesSecretShapedFields(t *testing.T) {
	input := map[string]any{"token": "do-not-leak", "nested": map[string]any{"api_key": "also-secret", "label": "visible"}}
	output := redact(input)
	b, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "do-not-leak") || strings.Contains(string(b), "also-secret") {
		t.Fatalf("secret leaked in %s", b)
	}
	if !strings.Contains(string(b), "visible") {
		t.Fatalf("non-secret value was removed: %s", b)
	}
}
