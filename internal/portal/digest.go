package portal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ContentDigest returns a deterministic digest of the generated portal tree.
// It is a cache key for controller-to-guest publication only; ownership and
// file-mode enforcement remain part of the Ansible publication task.
func ContentDigest(root string) (string, error) {
	hash := sha256.New()
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
		if _, err := fmt.Fprintf(hash, "%s\x00", filepath.ToSlash(relative)); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}); err != nil {
		return "", fmt.Errorf("digest portal tree: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
