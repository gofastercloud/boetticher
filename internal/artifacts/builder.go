package artifacts

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
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
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

// PublicBuildInputs is the allow-list for the maintainer Linux image build. The
// builder receives only reproducible build definitions and the small Go
// qualification helper; site repositories, generated state, and credentials
// are intentionally outside this set.
var PublicBuildInputs = []string{
	"buildbundle.go",
	"go.mod",
	"go.sum",
	"cmd/artifact-identity",
	"cmd/boetticher-aiops",
	"cmd/boetticher-bifrost",
	"cmd/boetticher-firewall-telemetry",
	"cmd/boetticher-log-query",
	"cmd/boetticher-network-probe",
	"cmd/boetticher-streamdeck",
	"cmd/qualify-artifact",
	"cmd/render-blocky-config",
	"internal/aiops",
	"internal/airvpn",
	"internal/artifacts",
	"internal/bifrost",
	"internal/dns",
	"internal/firewall",
	"internal/firewalltelemetry",
	"internal/gatus",
	"internal/logging",
	"internal/model",
	"internal/modules",
	"internal/network",
	"internal/networktest",
	"internal/pathguard",
	"internal/streamdeck",
	"internal/usbexport",
	"ansible/companion.yml",
	"ansible/site.yml",
	"ansible/tasks",
	"ansible/roles",
	"images",
	"pi/kiosk",
	"scripts/benchmark-artifact-compression.sh",
	"scripts/build-images.sh",
	"scripts/scan-images.sh",
	"scripts/smoke-appliance.sh",
	"scripts/smoke-firewall-image.sh",
}

// NativeBuilderSupportInputs are maintainer-only orchestration scripts. They
// are transferred to the isolated build host so it can execute the public
// build inputs, but they are not embedded in an installed operator binary.
var NativeBuilderSupportInputs = []string{
	"cmd/artifact-reuse",
	"scripts/install-debian-archive-keyring.sh",
	"scripts/local-builder-setup.sh",
	"scripts/native-builder-run.sh",
}

// CompanionSourceInputs are the public provisioning assets needed by a
// release controller to configure an external companion without a source
// checkout. They contain no site state, credentials, or private keys.
var CompanionSourceInputs = []string{
	"ansible/companion.yml",
	"ansible/roles/kiosk",
	"pi/kiosk",
}

// AnsibleSourceInputs are the deployment playbook and roles required by an
// installed release controller. They contain no site state, credentials, or
// private keys.
var AnsibleSourceInputs = []string{
	"ansible/site.yml",
	"ansible/tasks",
	"ansible/roles",
}

// BuildSourceArchive returns a deterministic gzip-compressed tar stream of
// the public build inputs. It rejects symlinks so a source checkout cannot
// smuggle a site file or credential into the maintainer image build through a
// path traversal or linked file.
func BuildSourceArchive(root string) ([]byte, error) {
	return buildSourceArchive(root, PublicBuildInputs)
}

// BuildNativeSourceArchive returns the public build inputs plus the two
// maintainer-only scripts needed to run the isolated native builder.
func BuildNativeSourceArchive(root string) ([]byte, error) {
	inputs := append(append([]string(nil), PublicBuildInputs...), NativeBuilderSupportInputs...)
	return buildSourceArchive(root, inputs)
}

func buildSourceArchive(root string, inputs []string) ([]byte, error) {
	if root == "" {
		return nil, fmt.Errorf("build source root is required")
	}
	paths := append([]string(nil), inputs...)
	sort.Strings(paths)
	return deterministicArchive(func(tarWriter *tar.Writer) error {
		for _, relative := range paths {
			if relative == "go.sum" {
				if _, err := os.Stat(filepath.Join(root, relative)); os.IsNotExist(err) {
					continue
				}
			}
			path := filepath.Join(root, relative)
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("inspect public build input %s: %w", relative, err)
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
				return fmt.Errorf("archive public build input %s: %w", relative, err)
			}
		}
		return nil
	})
}

// BuildEmbeddedSourceArchive returns the same public build input archive used
// for a source checkout, backed by the files embedded in a release binary.
// This keeps bootstrap usable from an installed controller binary without
// embedding any site repository or secret material.
func BuildEmbeddedSourceArchive() ([]byte, error) {
	return buildEmbeddedArchive(PublicBuildInputs)
}

// BuildEmbeddedCompanionSourceArchive returns a deterministic archive of the
// public companion provisioning assets embedded in a release controller.
func BuildEmbeddedCompanionSourceArchive() ([]byte, error) {
	return buildEmbeddedArchive(CompanionSourceInputs)
}

// BuildEmbeddedAnsibleSourceArchive returns the deployment playbook and
// first-party roles embedded in a release controller. Deployment still reads
// site-specific variables and secrets from the operator's private site.
func BuildEmbeddedAnsibleSourceArchive() ([]byte, error) {
	return buildEmbeddedArchive(AnsibleSourceInputs)
}

func buildEmbeddedArchive(inputs []string) ([]byte, error) {
	paths := append([]string(nil), inputs...)
	sort.Strings(paths)
	return deterministicArchive(func(tarWriter *tar.Writer) error {
		for _, relative := range paths {
			info, err := fs.Stat(buildbundle.FS, relative)
			if err != nil {
				return fmt.Errorf("inspect embedded public build input %s: %w", relative, err)
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
				return fmt.Errorf("archive embedded public build input %s: %w", relative, err)
			}
		}
		return nil
	})
}

func deterministicArchive(populate func(*tar.Writer) error) ([]byte, error) {
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := populate(tarWriter); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		return nil, err
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
	file, openedInfo, err := openEvidenceFile(path, "public build input")
	if err != nil {
		return err
	}
	defer file.Close()
	header, err := tar.FileInfoHeader(openedInfo, "")
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(relative)
	header.Uid, header.Gid, header.Uname, header.Gname = 0, 0, "", ""
	// Source file modification times are not desired-state inputs. A fixed
	// timestamp keeps the transferred source bundle deterministic.
	header.ModTime = time.Unix(0, 0).UTC()
	if openedInfo.Mode()&0o111 != 0 {
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

// ExtractSourceArchiveReader extracts only the built-in deployment and
// companion source trees. It is separate from artifact extraction so a source
// archive cannot write into generated state, and a builder artifact archive
// cannot be repurposed as a source tree.
func ExtractSourceArchiveReader(reader io.Reader, root string) error {
	return extractArchiveReader(reader, root, func(clean string) bool {
		return strings.HasPrefix(clean, "ansible/") || strings.HasPrefix(clean, "pi/kiosk/")
	}, "embedded source", 256<<20, 64<<20)
}

// ExtractNativeBuilderOutputReader imports only generated output returned by
// the isolated maintainer builder. The builder is local tooling, but its
// output still crosses a trust boundary and must not be extracted with an
// unconstrained system tar command.
func ExtractNativeBuilderOutputReader(reader io.Reader, root string) error {
	return extractArchiveReader(reader, root, func(clean string) bool {
		return clean == "generated" || strings.HasPrefix(clean, "generated/")
	}, "native builder output", 32<<30, 8<<30)
}

func extractArchiveReader(reader io.Reader, root string, allowed func(string) bool, label string, maxBytes, maxArchiveEntrySize int64) error {
	if reader == nil || root == "" {
		return fmt.Errorf("builder artifact archive and destination root are required")
	}
	if allowed == nil || label == "" || maxBytes <= 0 || maxArchiveEntrySize <= 0 {
		return fmt.Errorf("archive extraction policy is invalid")
	}
	const maxEntries = 8192
	buffered := bufio.NewReader(reader)
	var tarReader *tar.Reader
	header, err := buffered.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("inspect builder artifact archive: %w", err)
	}
	if len(header) == 2 && header[0] == 0x1f && header[1] == 0x8b {
		gzipReader, gzipErr := gzip.NewReader(buffered)
		if gzipErr != nil {
			return fmt.Errorf("open builder artifact archive: %w", gzipErr)
		}
		defer gzipReader.Close()
		tarReader = tar.NewReader(gzipReader)
	} else {
		// The controller can benchmark a plain tar return stream when the
		// already-compressed appliance payloads make gzip transport wasteful.
		// Keep the same bounded tar/path handling for either transport.
		tarReader = tar.NewReader(buffered)
	}
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
			return fmt.Errorf("%s archive contains too many entries", label)
		}
		if header.Size < 0 || header.Size > maxBytes-totalBytes || header.Size > maxArchiveEntrySize {
			return fmt.Errorf("%s archive exceeds bounded output size", label)
		}
		totalBytes += header.Size
		canonicalName := header.Name
		if header.Typeflag == tar.TypeDir {
			canonicalName = strings.TrimSuffix(canonicalName, "/")
		}
		clean := path.Clean(canonicalName)
		if header.Name == "" || clean != canonicalName || strings.HasPrefix(clean, "/") || strings.Contains(clean, "\\") || strings.ContainsRune(clean, '\x00') || !allowed(clean) {
			return fmt.Errorf("%s archive contains unexpected path %q", label, header.Name)
		}
		target := filepath.Join(root, filepath.FromSlash(clean))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := pathguard.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := pathguard.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			written, copyErr := pathguard.WriteFileFrom(target, &exactReader{reader: tarReader, remaining: header.Size}, 0o600, maxArchiveEntrySize)
			if copyErr != nil {
				return copyErr
			}
			if written != header.Size {
				return fmt.Errorf("builder artifact archive entry %q ended early", header.Name)
			}
		default:
			return fmt.Errorf("%s archive contains unsupported entry %q", label, header.Name)
		}
	}
	return nil
}

type exactReader struct {
	reader    io.Reader
	remaining int64
}

func (r *exactReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	if err == io.EOF && r.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}
