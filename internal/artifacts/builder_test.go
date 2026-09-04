package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSourceArchiveReaderAcceptsProvisioningTreesAndRejectsArtifacts(t *testing.T) {
	var archive bytes.Buffer
	tarWriter := tar.NewWriter(&archive)
	for name, content := range map[string]string{
		"ansible/site.yml":                   "---\n",
		"ansible/roles/kiosk/tasks/main.yml": "---\n",
		"pi/kiosk/visualizer/index.html":     "<!doctype html>\n",
	} {
		data := []byte(content)
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := ExtractSourceArchiveReader(bytes.NewReader(archive.Bytes()), destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "ansible", "site.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "pi", "kiosk", "visualizer", "index.html")); err != nil {
		t.Fatal(err)
	}

	var invalid bytes.Buffer
	invalidWriter := tar.NewWriter(&invalid)
	if err := invalidWriter.WriteHeader(&tar.Header{Name: "generated/artifacts/unsafe", Mode: 0o600, Size: 0}); err != nil {
		t.Fatal(err)
	}
	if err := invalidWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ExtractSourceArchiveReader(bytes.NewReader(invalid.Bytes()), t.TempDir()); err == nil {
		t.Fatal("source extractor accepted a generated artifact path")
	}

	var traversal bytes.Buffer
	traversalWriter := tar.NewWriter(&traversal)
	if err := traversalWriter.WriteHeader(&tar.Header{Name: "ansible/../ansible/site.yml", Mode: 0o600, Size: 0}); err != nil {
		t.Fatal(err)
	}
	if err := traversalWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ExtractSourceArchiveReader(bytes.NewReader(traversal.Bytes()), t.TempDir()); err == nil {
		t.Fatal("source extractor accepted a non-canonical path")
	}
}

func TestExtractNativeBuilderOutputReaderRejectsUnsafeEntries(t *testing.T) {
	var archive bytes.Buffer
	tarWriter := tar.NewWriter(&archive)
	data := []byte("qualified\n")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "generated/artifacts/result/smoke.txt", Mode: 0o600, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := ExtractNativeBuilderOutputReader(bytes.NewReader(archive.Bytes()), destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "generated", "artifacts", "result", "smoke.txt")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"../outside", "generated/../outside", "generated/unsafe/../result"} {
		var invalid bytes.Buffer
		invalidWriter := tar.NewWriter(&invalid)
		if err := invalidWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 0}); err != nil {
			t.Fatal(err)
		}
		if err := invalidWriter.Close(); err != nil {
			t.Fatal(err)
		}
		if err := ExtractNativeBuilderOutputReader(bytes.NewReader(invalid.Bytes()), t.TempDir()); err == nil {
			t.Fatalf("native output extractor accepted unsafe path %q", name)
		}
	}
}

func TestBuildSourceArchiveExcludesSiteSecrets(t *testing.T) {
	root := t.TempDir()
	for _, relative := range PublicBuildInputs {
		if relative == "go.sum" {
			continue
		}
		base := filepath.Base(relative)
		if strings.Contains(base, ".") {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, relative), []byte("public build input\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Join(root, relative), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "site.yml"), []byte("fixture-secret-site-state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secrets", "runtime.sops.yaml"), []byte("fixture-secret-runtime\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive, err := BuildSourceArchive(root)
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(gzipReader)
	entries := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries++
		if header.Name == "site.yml" || strings.Contains(header.Name, "secrets") {
			t.Fatalf("build archive included site state: %s", header.Name)
		}
	}
	if entries == 0 {
		t.Fatal("public build archive was empty")
	}
}

func TestBuildNativeSourceArchiveIncludesOnlyBuilderSupport(t *testing.T) {
	root := t.TempDir()
	for _, relative := range append(append([]string(nil), PublicBuildInputs...), NativeBuilderSupportInputs...) {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(relative+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive, err := BuildNativeSourceArchive(root)
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(gzipReader)
	entries := map[string]bool{}
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = true
	}
	for _, relative := range NativeBuilderSupportInputs {
		if !entries[relative] {
			t.Fatalf("native source archive omitted builder support input %s", relative)
		}
	}
	if entries["site.yml"] || entries["secrets/runtime.sops.yaml"] {
		t.Fatal("native source archive included site state")
	}
}
