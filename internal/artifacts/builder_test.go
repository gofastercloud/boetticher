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

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestBuilderUsesPinnedQualifiedCapacityAndToolchain(t *testing.T) {
	builder := Builder()
	if builder.VMID != model.BuilderVMID || builder.Hostname != "lab-builder-01" {
		t.Fatalf("builder identity = %#v", builder)
	}
	if !builder.Temporary || builder.Network != "bootstrap-upstream-only" {
		t.Fatalf("builder isolation contract = %#v", builder)
	}
	if builder.Cores != 4 || builder.MemoryMiB != 8192 || builder.DiskGiB != 32 || builder.MinimumFreeGiB != 20 {
		t.Fatalf("builder sizing = %#v", builder)
	}
	if model.BuilderGoVersion != "1.26.5" || model.BuilderGoURL != "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz" || model.BuilderGoSHA256 != "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053" {
		t.Fatalf("builder Go toolchain is not pinned: %q %q %q", model.BuilderGoVersion, model.BuilderGoURL, model.BuilderGoSHA256)
	}
}

func TestExtractBuildArchiveReaderStreamsLargeArchive(t *testing.T) {
	reader, writer := io.Pipe()
	go func() {
		gzipWriter := gzip.NewWriter(writer)
		tarWriter := tar.NewWriter(gzipWriter)
		const size = int64(8 << 20)
		if err := tarWriter.WriteHeader(&tar.Header{Name: "generated/artifacts/large.bin", Mode: 0o600, Size: size}); err != nil {
			_ = writer.CloseWithError(err)
			return
		}
		chunk := bytes.Repeat([]byte("x"), 32<<10)
		for remaining := size; remaining > 0; {
			count := int64(len(chunk))
			if count > remaining {
				count = remaining
			}
			if _, err := tarWriter.Write(chunk[:count]); err != nil {
				_ = writer.CloseWithError(err)
				return
			}
			remaining -= count
		}
		if err := tarWriter.Close(); err != nil {
			_ = writer.CloseWithError(err)
			return
		}
		if err := gzipWriter.Close(); err != nil {
			_ = writer.CloseWithError(err)
			return
		}
		_ = writer.Close()
	}()

	tracked := &trackingReader{reader: reader}
	destination := t.TempDir()
	if err := ExtractBuildArchiveReader(tracked, destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(destination, "generated", "artifacts", "large.bin"))
	if err != nil || info.Size() != 8<<20 {
		t.Fatalf("streamed artifact = %v, size=%d", err, info.Size())
	}
	if tracked.maxRead > 1<<20 {
		t.Fatalf("archive reader requested an unbounded read buffer: %d bytes", tracked.maxRead)
	}
}

func TestExtractBuildArchiveReaderAcceptsPlainTarTransport(t *testing.T) {
	var archive bytes.Buffer
	tarWriter := tar.NewWriter(&archive)
	content := []byte("plain transport artifact")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "generated/artifacts/example/artifact", Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := ExtractBuildArchiveReader(bytes.NewReader(archive.Bytes()), destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "generated", "artifacts", "example", "artifact"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(content) {
		t.Fatalf("plain transport content = %q, want %q", data, content)
	}
}

func TestExtractBuildArchiveReaderRejectsDestinationSymlink(t *testing.T) {
	var archive bytes.Buffer
	tarWriter := tar.NewWriter(&archive)
	content := []byte("must stay out")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "generated/artifacts/redirect/payload", Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	external := t.TempDir()
	if err := os.MkdirAll(filepath.Join(destination, "generated", "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(destination, "generated", "artifacts", "redirect")); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBuildArchiveReader(bytes.NewReader(archive.Bytes()), destination); err == nil {
		t.Fatal("archive extraction followed a destination symlink")
	}
	if _, err := os.Stat(filepath.Join(external, "payload")); !os.IsNotExist(err) {
		t.Fatalf("archive wrote through destination symlink: %v", err)
	}
}

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
		if strings.Contains(header.Name, "site.yml") || strings.Contains(header.Name, "secrets") {
			t.Fatalf("build archive included site state: %s", header.Name)
		}
	}
	if entries == 0 {
		t.Fatal("public build archive was empty")
	}
}

type trackingReader struct {
	reader  io.Reader
	maxRead int
}

func (r *trackingReader) Read(data []byte) (int, error) {
	if len(data) > r.maxRead {
		r.maxRead = len(data)
	}
	return r.reader.Read(data)
}
