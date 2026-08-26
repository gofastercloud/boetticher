package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
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
