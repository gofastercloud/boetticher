package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
)

// BuilderPlan describes the ephemeral Core build environment. It receives
// public build inputs only and is never a module or a runtime secret holder.
type BuilderPlan struct {
	VMID      int
	Hostname  string
	Platform  string
	Temporary bool
	Network   string
}

func Builder() BuilderPlan {
	return BuilderPlan{VMID: model.BuilderVMID, Hostname: "lab-builder-01", Platform: "debian-13-amd64", Temporary: true, Network: "bootstrap-upstream-only"}
}

// PublicBuildInputs is the allow-list for the temporary Linux builder. The
// builder receives only reproducible build definitions and the small Go
// qualification helper; site repositories, generated state, and credentials
// are intentionally outside this set.
var PublicBuildInputs = []string{
	"go.mod",
	"go.sum",
	"cmd/qualify-artifact",
	"internal/artifacts",
	"internal/model",
	"images",
	"scripts/build-images.sh",
	"scripts/scan-images.sh",
	"scripts/smoke-appliance.sh",
	"scripts/smoke-firewall-image.sh",
}

// BuildSourceArchive returns a deterministic gzip-compressed tar stream of
// the public build inputs. It rejects symlinks so a source checkout cannot
// smuggle a site file or credential into the temporary builder through a
// path traversal or linked file.
func BuildSourceArchive(root string) ([]byte, error) {
	if root == "" {
		return nil, fmt.Errorf("build source root is required")
	}
	paths := append([]string(nil), PublicBuildInputs...)
	sort.Strings(paths)
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, relative := range paths {
		if relative == "go.sum" {
			if _, err := os.Stat(filepath.Join(root, relative)); os.IsNotExist(err) {
				continue
			}
		}
		path := filepath.Join(root, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect public build input %s: %w", relative, err)
		}
		if info.IsDir() {
			err = filepath.WalkDir(path, func(filePath string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				return addArchiveFile(root, filePath, entry, tarWriter)
			})
		} else {
			err = addArchiveFile(root, path, infoToDirEntry{info}, tarWriter)
		}
		if err != nil {
			return nil, fmt.Errorf("archive public build input %s: %w", relative, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("close build source archive: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("close build source compression: %w", err)
	}
	return archive.Bytes(), nil
}

type infoToDirEntry struct{ fs.FileInfo }

func (e infoToDirEntry) Type() fs.FileMode          { return e.Mode().Type() }
func (e infoToDirEntry) Info() (fs.FileInfo, error) { return e.FileInfo, nil }

func addArchiveFile(root, path string, entry fs.DirEntry, writer *tar.Writer) error {
	info, err := entry.Info()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink is not allowed: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("non-regular build input is not allowed: %s", path)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("build input escapes source root: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(relative)
	// Source file modification times are not desired-state inputs. A fixed
	// timestamp keeps the transferred source bundle deterministic.
	header.ModTime = time.Unix(0, 0).UTC()
	if info.Mode()&0o111 != 0 {
		header.Mode = 0o755
	} else {
		header.Mode = 0o644
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(writer, file)
	return err
}
