package artifacts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func EvidencePath(root, name string) string {
	return filepath.Join(root, "generated", "artifacts", strings.ToLower(name)+".json")
}

func WriteEvidence(root, name string, evidence Evidence) error {
	if root == "" || name == "" || evidence.ContentSHA256 == "" || evidence.DefinitionSHA256 == "" {
		return fmt.Errorf("artifact evidence requires root, name, definition digest, and content digest")
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(EvidencePath(root, name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".artifact-evidence-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, EvidencePath(root, name))
}
