package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
	qualificationFiles := addCompleteReleaseEvidence(t, artifactPath, &evidence)
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	companionPath := filepath.Join(root, "boetticher-streamdeck-linux-arm64")
	companionBytes := []byte("release-built companion StreamDeck binary")
	if err := os.WriteFile(companionPath, companionBytes, 0700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(root, "release.tar.gz")
	manifest, err := BuildReleaseBundleWithMetadataAndCompanion(bundlePath, ReleaseBuildMetadata{
		ReleaseVersion: "0.5.0", SourceCommit: "local-build", BuildWorkflow: "local",
		ControllerMin: "0.5.0", ControllerMax: "0.5.0", QualificationPolicyVersion: QualificationPolicyVersion,
	}, model.APIVersion, model.SchemaVersion, private, "release-2026", []ReleaseInput{{Artifact: artifact, ArtifactPath: artifactPath, EvidencePath: evidencePath, QualificationFiles: qualificationFiles}}, companionPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 8 || len(manifest.Artifacts) != 1 || manifest.CompanionBinary == nil {
		t.Fatalf("unexpected release manifest: %#v", manifest)
	}
	destination := filepath.Join(root, "generated", "release")
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
	if got, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(CompanionStreamDeckPath))); err != nil || string(got) != string(companionBytes) {
		t.Fatalf("imported companion = %q, err=%v", got, err)
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
	previousKeys := EmbeddedTrustedReleaseKeys
	EmbeddedTrustedReleaseKeys = []TrustedReleaseKey{{ID: "release-2026", PublicKey: public}}
	defer func() { EmbeddedTrustedReleaseKeys = previousKeys }()
	resolvedCompanion, err := ResolveImportedCompanion(root)
	if err != nil {
		t.Fatal(err)
	}
	if resolvedCompanion != filepath.Join(root, "generated", "release", filepath.FromSlash(CompanionStreamDeckPath)) {
		t.Fatalf("resolved companion path = %q", resolvedCompanion)
	}
	if err := os.WriteFile(filepath.Join(destination, "evidence", artifact.Name, "sbom.json"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveImportedArtifact(root, artifact); err == nil || !strings.Contains(err.Error(), "signed digest verification") {
		t.Fatalf("mutated imported qualification sidecar was accepted: %v", err)
	}
	reformatted := filepath.Join(root, "reformatted.tar.gz")
	rewriteReleaseManifest(t, bundlePath, reformatted)
	if _, err := ImportReleaseBundle(reformatted, filepath.Join(root, "reformatted-import"), []TrustedReleaseKey{{ID: "release-2026", PublicKey: public}}, "0.5.0", model.APIVersion, model.SchemaVersion); err == nil {
		t.Fatal("reformatted manifest was accepted without re-signing")
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
	qualificationFiles := addCompleteReleaseEvidence(t, artifactPath, &evidence)
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
	if _, err := BuildReleaseBundle(bundle, "0.5.0", model.APIVersion, model.SchemaVersion, private, "trusted", []ReleaseInput{{Artifact: artifact, ArtifactPath: artifactPath, EvidencePath: evidencePath, QualificationFiles: qualificationFiles}}); err != nil {
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

func TestReleaseBundlePathRejectsNUL(t *testing.T) {
	if err := validateBundlePath("artifacts/example/" + string(rune(0))); err == nil {
		t.Fatal("NUL-containing release member path was accepted")
	}
}

func TestReleaseBundleRejectsIncompleteQualificationEvidence(t *testing.T) {
	root := t.TempDir()
	artifactPath := filepath.Join(root, "artifact")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("monitoring")
	if err != nil {
		t.Fatal(err)
	}
	artifact.ContentSHA256 = fmtSHA256([]byte("artifact"))
	evidence := Evidence{Artifact: artifact, ArtifactPath: artifactPath, ContentSHA256: artifact.ContentSHA256, DefinitionSHA256: artifact.DefinitionSHA256, QualificationPolicyVersion: QualificationPolicyVersion, QualificationEvaluator: QualificationEvaluator, ScanCompleted: true, Qualified: true, qualifiedByEvaluator: true}
	qualificationFiles := addCompleteReleaseEvidence(t, artifactPath, &evidence)
	delete(qualificationFiles, filepath.ToSlash(filepath.Join("evidence", artifact.Name, "smoke.txt")))
	evidencePath := filepath.Join(root, "evidence.json")
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReleaseBundle(filepath.Join(root, "bundle.tar.gz"), "0.5.0", model.APIVersion, model.SchemaVersion, private, "trusted", []ReleaseInput{{Artifact: artifact, ArtifactPath: artifactPath, EvidencePath: evidencePath, QualificationFiles: qualificationFiles}}); err == nil || !strings.Contains(err.Error(), "mandatory smoke") {
		t.Fatalf("incomplete release evidence was accepted: %v", err)
	}
}

func fmtSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func addCompleteReleaseEvidence(t *testing.T, artifactPath string, evidence *Evidence) map[string]string {
	t.Helper()
	root := filepath.Dir(artifactPath)
	files := map[string]struct {
		name   string
		assign func(string)
	}{
		"package-manifest.txt": {name: "package manifest", assign: func(digest string) { evidence.PackageManifestSHA = digest }},
		"sbom.json":            {name: "SBOM", assign: func(digest string) { evidence.SBOMSHA256 = digest }},
		"trivy.json":           {name: "Trivy report", assign: func(digest string) { evidence.TrivyReportSHA256 = digest }},
		"builder-provenance.json": {name: "builder provenance", assign: func(digest string) {
			evidence.BuilderProvenanceSHA256 = digest
		}},
		"smoke.txt": {name: "smoke report", assign: func(digest string) { evidence.SmokeReportSHA256 = digest }},
	}
	qualificationFiles := make(map[string]string, len(files))
	for filename, file := range files {
		path := filepath.Join(root, filename)
		if err := os.WriteFile(path, []byte(file.name+" evidence\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		digest, err := QualificationInputSHA256(path, file.name)
		if err != nil {
			t.Fatal(err)
		}
		file.assign(digest)
		qualificationFiles[filepath.ToSlash(filepath.Join("evidence", evidence.Artifact.Name, filename))] = path
	}
	return qualificationFiles
}

func rewriteReleaseManifest(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(reader)
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		data, readErr := io.ReadAll(tarReader)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if header.Name == ReleaseManifestName {
			var manifest ReleaseManifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			data, err = json.MarshalIndent(manifest, "", "\t")
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
		}
		copyHeader := *header
		copyHeader.Size = int64(len(data))
		if err := tarWriter.WriteHeader(&copyHeader); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
