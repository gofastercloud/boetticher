package naming

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLegacyProjectIdentifiersDoNotReappear(t *testing.T) {
	root := repositoryRoot(t)
	_, testFile, _, _ := runtime.Caller(0)
	legacy := []string{"labinabox", "lab-in-a-box", "lab in a box"}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && isIgnoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if path == testFile {
			// The detector necessarily contains the sentinel strings it rejects.
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		lower := strings.ToLower(string(data))
		for _, pattern := range legacy {
			if strings.Contains(lower, pattern) {
				t.Errorf("%s contains legacy project identifier %q", path, pattern)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate naming test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func isIgnoredDirectory(name string) bool {
	switch name {
	case ".git", ".terraform", ".cache", ".venv", ".runtime", "bin":
		return true
	default:
		return false
	}
}
