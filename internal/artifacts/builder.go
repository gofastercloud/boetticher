package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	buildbundle "github.com/gofastercloud/boetticher"
	"github.com/gofastercloud/boetticher/internal/model"
)

// BuilderPlan describes the ephemeral Core build environment. It receives
// public build inputs only and is never a module or a runtime secret holder.
type BuilderPlan struct {
	VMID           int
	Hostname       string
	Platform       string
	Temporary      bool
	Network        string
	Cores          int
	MemoryMiB      int
	DiskGiB        int
	MinimumFreeGiB int
}

func Builder() BuilderPlan {
	return BuilderPlan{
		VMID:           model.BuilderVMID,
		Hostname:       "lab-builder-01",
		Platform:       "debian-13-amd64",
		Temporary:      true,
		Network:        "bootstrap-upstream-only",
		Cores:          model.BuilderCores,
		MemoryMiB:      model.BuilderMemoryMiB,
		DiskGiB:        model.BuilderDiskGiB,
		MinimumFreeGiB: model.BuilderMinimumFreeGiB,
	}
}

// PublicBuildInputs is the allow-list for the temporary Linux builder. The
// builder receives only reproducible build definitions and the small Go
// qualification helper; site repositories, generated state, and credentials
// are intentionally outside this set.
var PublicBuildInputs = []string{
	"buildbundle.go",
	"go.mod",
	"go.sum",
	"cmd/artifact-identity",
	"cmd/qualify-artifact",
	"cmd/render-blocky-config",
	"internal/artifacts",
	"internal/dns",
	"internal/model",
	"internal/modules",
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

// BuildEmbeddedSourceArchive returns the same public build input archive used
// for a source checkout, backed by the files embedded in a release binary.
// This keeps bootstrap usable from an installed controller binary without
// embedding any site repository or secret material.
func BuildEmbeddedSourceArchive() ([]byte, error) {
	paths := append([]string(nil), PublicBuildInputs...)
	sort.Strings(paths)
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, relative := range paths {
		info, err := fs.Stat(buildbundle.FS, relative)
		if err != nil {
			return nil, fmt.Errorf("inspect embedded public build input %s: %w", relative, err)
		}
		if info.IsDir() {
			err = fs.WalkDir(buildbundle.FS, relative, func(filePath string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				return addEmbeddedArchiveFile(filePath, entry, tarWriter)
			})
		} else {
			err = addEmbeddedArchiveFile(relative, infoToDirEntry{info}, tarWriter)
		}
		if err != nil {
			return nil, fmt.Errorf("archive embedded public build input %s: %w", relative, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("close embedded build source archive: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("close embedded build source compression: %w", err)
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
	header.Uid, header.Gid, header.Uname, header.Gname = 0, 0, "", ""
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

func addEmbeddedArchiveFile(relative string, entry fs.DirEntry, writer *tar.Writer) error {
	info, err := entry.Info()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("non-regular embedded build input is not allowed: %s", relative)
	}
	file, err := buildbundle.FS.Open(relative)
	if err != nil {
		return err
	}
	defer file.Close()
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = path.Clean(filepath.ToSlash(relative))
	header.Uid, header.Gid, header.Uname, header.Gname = 0, 0, "", ""
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

// ExtractBuildArchive accepts only the generated artifact tree returned by a
// successful builder run. Extraction rejects links and traversal so a remote
// builder cannot write outside the controller's generated evidence directory.
func ExtractBuildArchive(data []byte, root string) error {
	if len(data) == 0 || root == "" {
		return fmt.Errorf("builder artifact archive and destination root are required")
	}
	return ExtractBuildArchiveReader(bytes.NewReader(data), root)
}

// ExtractBuildArchiveFile streams a builder archive from a controller-side
// temporary file. The complete archive is never held in memory.
func ExtractBuildArchiveFile(archivePath, root string) error {
	if archivePath == "" || root == "" {
		return fmt.Errorf("builder artifact archive and destination root are required")
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open builder artifact archive: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat builder artifact archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("builder artifact archive must be a non-empty regular file")
	}
	return ExtractBuildArchiveReader(file, root)
}

// ExtractBuildArchiveReader accepts a streamed generated artifact tree. It
// retains path, link, entry-count, and total-output protections while writing
// each regular file atomically beneath the generated artifact directory.
func ExtractBuildArchiveReader(reader io.Reader, root string) error {
	if reader == nil || root == "" {
		return fmt.Errorf("builder artifact archive and destination root are required")
	}
	const (
		maxEntries = 8192
		maxBytes   = int64(64 << 30)
	)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("open builder artifact archive: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var entries int
	var totalBytes int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read builder artifact archive: %w", err)
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("builder artifact archive contains too many entries")
		}
		if header.Size < 0 || header.Size > maxBytes-totalBytes {
			return fmt.Errorf("builder artifact archive exceeds bounded output size")
		}
		totalBytes += header.Size
		clean := path.Clean(header.Name)
		if clean != "generated/artifacts" && !strings.HasPrefix(clean, "generated/artifacts/") {
			return fmt.Errorf("builder artifact archive contains unexpected path %q", header.Name)
		}
		target := filepath.Join(root, filepath.FromSlash(clean))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			temporary, err := os.CreateTemp(filepath.Dir(target), ".builder-artifact-")
			if err != nil {
				return err
			}
			temporaryName := temporary.Name()
			if err := temporary.Chmod(0o600); err != nil {
				_ = temporary.Close()
				_ = os.Remove(temporaryName)
				return err
			}
			written, copyErr := io.Copy(temporary, tarReader)
			closeErr := temporary.Close()
			if copyErr != nil || closeErr != nil {
				_ = os.Remove(temporaryName)
				if copyErr != nil {
					return copyErr
				}
				return closeErr
			}
			if written != header.Size {
				_ = os.Remove(temporaryName)
				return fmt.Errorf("builder artifact archive entry %q ended early", header.Name)
			}
			if err := os.Rename(temporaryName, target); err != nil {
				_ = os.Remove(temporaryName)
				return err
			}
		default:
			return fmt.Errorf("builder artifact archive contains unsupported entry %q", header.Name)
		}
	}
	return nil
}
