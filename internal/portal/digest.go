package portal

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

// ContentDigest returns a deterministic digest of the generated portal tree.
// It is a cache key for controller-to-guest publication only; ownership and
// file-mode enforcement remain part of the Ansible publication task.
func ContentDigest(root string) (string, error) {
	type contentFile struct {
		path     string
		relative string
	}
	files := make([]contentFile, 0)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("portal tree contains symlink %s", path)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("portal tree contains non-regular file %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relativize portal file %s: %w", path, err)
		}
		files = append(files, contentFile{path: path, relative: filepath.ToSlash(relative)})
		return nil
	}); err != nil {
		return "", fmt.Errorf("digest portal tree: %w", err)
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].relative < files[j].relative
	})
	hash := sha256.New()
	for _, fileEntry := range files {
		if _, err := fmt.Fprintf(hash, "%s\x00", fileEntry.relative); err != nil {
			return "", err
		}
		file, err := os.Open(fileEntry.path)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ContentArchive writes a deterministic, rootless tar archive of the portal
// tree. The archive is a transport optimisation only; the source tree and its
// digest remain the content authority.
func ContentArchive(root, destination string) error {
	if root == "" || destination == "" {
		return fmt.Errorf("portal archive source and destination are required")
	}
	var archive bytes.Buffer
	archiveWriter := tar.NewWriter(&archive)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			if !entry.IsDir() {
				return fmt.Errorf("portal archive source is not a directory")
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("portal tree contains symlink %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relativize portal archive path %s: %w", path, err)
		}
		header := &tar.Header{
			Name:    filepath.ToSlash(relative),
			ModTime: time.Unix(0, 0).UTC(),
			Uid:     0,
			Gid:     0,
		}
		if entry.IsDir() {
			header.Mode = 0755
			header.Typeflag = tar.TypeDir
		} else {
			if !entry.Type().IsRegular() {
				return fmt.Errorf("portal tree contains non-regular file %s", path)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			header.Mode = 0644
			header.Typeflag = tar.TypeReg
			header.Size = info.Size()
		}
		if err := archiveWriter.WriteHeader(header); err != nil {
			return err
		}
		if !entry.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(archiveWriter, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("archive portal tree: %w", err)
	}
	if err := archiveWriter.Close(); err != nil {
		return fmt.Errorf("close portal archive: %w", err)
	}
	if err := pathguard.WriteFile(destination, archive.Bytes(), 0600); err != nil {
		return fmt.Errorf("publish portal archive: %w", err)
	}
	return nil
}
