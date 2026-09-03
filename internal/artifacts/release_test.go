package artifacts

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestReleaseBundleSignsAndAtomicallyImportsQualifiedArtifacts(t *testing.T) {
	root := t.TempDir()
	artifactPath := filepath.Join(root, "boetticher-monitoring-1.0.0-amd64.tar.zst")
	artifactBytes := []byte("qualified monitoring artifact")
	if err := os.WriteFile(artifactPath, artifactBytes, 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("monitoring")
	if err != nil {
		t.Fatal(err)
	}
	artifact.ContentSHA256 = fmtSHA256(artifactBytes)
	evidencePath := filepath.Join(root, "evidence.json")
	evidence := Evidence{
		Artifact: artifact, ArtifactPath: artifactPath, ContentSHA256: artifact.ContentSHA256,
		SizeBytes: int64(len(artifactBytes)), DefinitionSHA256: artifact.DefinitionSHA256,
		QualificationPolicyVersion: QualificationPolicyVersion, QualificationEvaluator: QualificationEvaluator,
		ScanCompleted: true, Qualified: true, qualifiedByEvaluator: true,
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(root, "release.tar.gz")
	manifest, err := BuildReleaseBundle(bundlePath, "0.5.0", model.APIVersion, model.SchemaVersion, private, "release-2026", []ReleaseInput{{Artifact: artifact, ArtifactPath: artifactPath, EvidencePath: evidencePath}})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 2 || len(manifest.Artifacts) != 1 {
		t.Fatalf("unexpected release manifest: %#v", manifest)
	}
	destination := filepath.Join(root, "imported")
	imported, err := ImportReleaseBundle(bundlePath, destination, []TrustedReleaseKey{{ID: "release-2026", PublicKey: public}}, "0.5.0", model.APIVersion, model.SchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Artifacts[0].Artifact.Name != artifact.Name {
		t.Fatalf("imported wrong artifact: %#v", imported)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "artifacts", artifact.Name, filepath.Base(artifactPath))); err != nil || string(got) != string(artifactBytes) {
		t.Fatalf("imported artifact = %q, err=%v", got, err)
	}
	importedEvidence, err := os.ReadFile(filepath.Join(destination, "evidence", artifact.Name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(importedEvidence) == string(data) {
		t.Fatal("release evidence retained the workstation artifact path")
	}
	if !strings.Contains(string(importedEvidence), "artifacts/"+artifact.Name) {
		t.Fatal("release evidence was not rebound to its bundle path")
	}
}

func TestReleaseBundleRejectsUntrustedKeyBeforeCreatingDestination(t *testing.T) {
	root := t.TempDir()
	artifactPath := filepath.Join(root, "artifact")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("monitoring")
	if err != nil {
		t.Fatal(err)
	}
	artifact.ContentSHA256 = fmtSHA256([]byte("artifact"))
	evidencePath := filepath.Join(root, "evidence")
	evidence := Evidence{Artifact: artifact, ArtifactPath: artifactPath, ContentSHA256: artifact.ContentSHA256, DefinitionSHA256: artifact.DefinitionSHA256, QualificationPolicyVersion: QualificationPolicyVersion, QualificationEvaluator: QualificationEvaluator, ScanCompleted: true, Qualified: true, qualifiedByEvaluator: true}
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle.tar.gz")
	if _, err := BuildReleaseBundle(bundle, "0.5.0", model.APIVersion, model.SchemaVersion, private, "trusted", []ReleaseInput{{Artifact: artifact, ArtifactPath: artifactPath, EvidencePath: evidencePath}}); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "destination")
	if _, err := ImportReleaseBundle(bundle, destination, nil, "0.5.0", model.APIVersion, model.SchemaVersion); err == nil {
		t.Fatal("bundle with no trusted key was accepted")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed import created destination: %v", err)
	}
}

func fmtSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
