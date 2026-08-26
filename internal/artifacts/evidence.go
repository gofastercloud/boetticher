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

// RebindEvidencePaths converts builder-local artifact paths into controller
// paths after a successful evidence archive transfer, then re-hashes each
// local artifact before writing the evidence record.
func RebindEvidencePaths(root string) error {
	if root == "" {
		return fmt.Errorf("artifact evidence root is required")
	}
	entries, err := os.ReadDir(filepath.Join(root, "generated", "artifacts"))
	if err != nil {
		return fmt.Errorf("read transferred artifact evidence: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(root, "generated", "artifacts", entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var evidence Evidence
		if err := json.Unmarshal(data, &evidence); err != nil {
			return fmt.Errorf("decode transferred evidence %s: %w", entry.Name(), err)
		}
		if evidence.Artifact.Name == "" {
			return fmt.Errorf("transferred evidence %s has no artifact identity", entry.Name())
		}
		filename := evidence.Artifact.Name + ".tar.zst"
		if evidence.Artifact.Kind == "qemu" {
			filename = fmt.Sprintf("%s-%s-%s.qcow2", evidence.Artifact.Name, evidence.Artifact.Version, evidence.Artifact.Architecture)
		}
		artifactPath := filepath.Join(root, "generated", "artifacts", evidence.Artifact.Name, filename)
		verified, err := EvidenceForFile(artifactPath, evidence.Artifact)
		if err != nil {
			return fmt.Errorf("verify transferred artifact %s: %w", evidence.Artifact.Name, err)
		}
		if verified.ContentSHA256 != evidence.ContentSHA256 {
			return fmt.Errorf("transferred artifact %s content checksum differs from evidence", evidence.Artifact.Name)
		}
		evidence.ArtifactPath = artifactPath
		if err := WriteEvidence(root, evidence.Artifact.Name, evidence); err != nil {
			return err
		}
	}
	return nil
}
