package naming

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestLegacyProjectIdentifiersDoNotReappear(t *testing.T) {
	root := repositoryRoot(t)
	_, testFile, _, _ := runtime.Caller(0)
	legacy := []string{"labinabox", "lab-in-a-box", "lab_in_a_box", "lab in a box"}
	legacyAbbreviation := regexp.MustCompile(`(?i)(^|[^a-z0-9])liab([^a-z0-9]|$)`)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == filepath.Join(root, ".git") {
			// Linked worktrees expose .git as a pointer file containing the
			// checkout path, which may retain the pre-rename directory name.
			return filepath.SkipDir
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
		if legacyAbbreviation.MatchString(string(data)) {
			t.Errorf("%s contains the legacy project abbreviation", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLegacyAbbreviationMatcherAvoidsUnrelatedWords(t *testing.T) {
	pattern := regexp.MustCompile(`(?i)(^|[^a-z0-9])liab([^a-z0-9]|$)`)
	for _, value := range []string{"LIAB", "boetticher_LIAB_marker", "(liab)"} {
		if !pattern.MatchString(value) {
			t.Errorf("legacy abbreviation %q was not detected", value)
		}
	}
	for _, value := range []string{"liability", "reliable", "library"} {
		if pattern.MatchString(value) {
			t.Errorf("unrelated word %q was detected as the legacy abbreviation", value)
		}
	}
}

func TestRemovedApplianceIdentifiersStayOutsideTheExampleGuide(t *testing.T) {
	root := repositoryRoot(t)
	_, testFile, _, _ := runtime.Caller(0)
	removed := strings.ToLower("OPN" + "sense")
	allowed := filepath.Join(root, "docs", "networking", "external-firewall.md")
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
		if path == testFile || path == allowed {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		if strings.Contains(strings.ToLower(string(data)), removed) {
			t.Errorf("%s contains removed appliance identifier", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeployIsTheOnlyPublicPlatformApplicationCommand(t *testing.T) {
	root := repositoryRoot(t)
	paths := []string{"README.md", "docs", "agents.md", "internal/cli", "schemas"}
	for _, relative := range paths {
		path := filepath.Join(root, relative)
		err := filepath.WalkDir(path, func(file string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if strings.HasSuffix(file, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "boetticher converge") {
				t.Errorf("%s exposes the removed converge command", file)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
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
	case ".git", ".cache", ".venv", ".runtime", "bin":
		return true
	default:
		return false
	}
}
