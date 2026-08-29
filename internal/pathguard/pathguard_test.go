package pathguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateNoSymlinkComponentsRejectsParentAndFinalLinks(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "linked", "output"), filepath.Join(root, "linked")} {
		if err := ValidateNoSymlinkComponents(path); err == nil {
			t.Fatalf("symlinked path %q was accepted", path)
		} else if !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("unexpected symlink error for %q: %v", path, err)
		}
	}
}

func TestValidateNoSymlinkComponentsAllowsMissingChild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "output")
	if err := ValidateNoSymlinkComponents(path); err != nil {
		t.Fatalf("missing child was rejected: %v", err)
	}
}

func TestDescriptorOperationsRejectSymlinkSwaps(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "safe"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(filepath.Join(root, "linked", "sentinel")); err == nil {
		t.Fatal("descriptor-relative read followed a symlink")
	}
	if err := WriteFile(filepath.Join(root, "linked", "changed"), []byte("no"), 0600); err == nil {
		t.Fatal("descriptor-relative write followed a symlink")
	}
	if err := RemoveAll(filepath.Join(root, "linked")); err == nil {
		t.Fatal("descriptor-relative cleanup accepted a symlink")
	}
	if err := Rename(filepath.Join(root, "safe"), filepath.Join(root, "linked")); err == nil {
		t.Fatal("descriptor-relative rename accepted a symlink destination")
	}
	got, err := os.ReadFile(filepath.Join(external, "sentinel"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("external sentinel changed: %q, %v", got, err)
	}
}

func TestWriteFileFromStreamsAtomicallyAndEnforcesLimit(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "output")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	written, err := WriteFileFrom(target, strings.NewReader("new content"), 0600, 32)
	if err != nil || written != int64(len("new content")) {
		t.Fatalf("bounded stream write = %d, %v", written, err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "new content" {
		t.Fatalf("streamed content = %q, %v", data, err)
	}
	if _, err := WriteFileFrom(target, strings.NewReader("too large"), 0600, 4); err == nil {
		t.Fatal("oversized stream was accepted")
	}
	data, err = os.ReadFile(target)
	if err != nil || string(data) != "new content" {
		t.Fatalf("oversized stream changed destination = %q, %v", data, err)
	}
}
