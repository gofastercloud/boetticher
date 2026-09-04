package artifacts

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	buildbundle "github.com/gofastercloud/boetticher"
)

func TestEvidenceUsesActualArtifactBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	content := []byte("qualified appliance bytes")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	if evidence.ContentSHA256 != hex.EncodeToString(hash[:]) || evidence.ContentSHA256 == artifact.DefinitionSHA256 || evidence.Qualified {
		t.Fatalf("evidence does not bind actual bytes: %#v", evidence)
	}
}

func TestQualificationInputRejectsMissingOrEmptyEvidence(t *testing.T) {
	root := t.TempDir()
	if _, err := QualificationInputSHA256(filepath.Join(root, "missing"), "SBOM"); err == nil {
		t.Fatal("missing qualification input was accepted")
	}
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := QualificationInputSHA256(empty, "SBOM"); err == nil {
		t.Fatal("empty qualification input was accepted")
	}
}

func TestEvidenceRejectsSymlinkedArtifactAndQualificationInput(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	artifact := filepath.Join(root, "artifact")
	if err := os.WriteFile(target, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, artifact); err != nil {
		t.Fatal(err)
	}
	definition, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvidenceForFile(artifact, definition); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked artifact was accepted: %v", err)
	}
	if _, err := QualificationInputSHA256(artifact, "SBOM"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked qualification input was accepted: %v", err)
	}
}

func TestRebindEvidenceRejectsArtifactIdentityTraversal(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "generated", "artifacts")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	data := `{"artifact":{"name":"../outside","version":"1.0.0","architecture":"amd64","kind":"lxc"},"qualified":true}`
	if err := os.WriteFile(filepath.Join(directory, "transferred.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RebindEvidencePaths(root); err == nil || !strings.Contains(err.Error(), "plain identity") {
		t.Fatalf("traversing transferred artifact identity was accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "generated", "outside")); !os.IsNotExist(err) {
		t.Fatalf("path traversal created an outside evidence path: %v", err)
	}
}

func TestRebindEvidenceRejectsSymlinkedEvidenceEntry(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "generated", "artifacts")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "evidence-target.json")
	if err := os.WriteFile(target, []byte(`{"artifact":{"name":"boetticher-logging","version":"1.0.0","architecture":"amd64","kind":"lxc"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "transferred.json")); err != nil {
		t.Fatal(err)
	}
	if err := RebindEvidencePaths(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked transferred evidence was accepted: %v", err)
	}
}

func TestResolveArtifactEvidenceRejectsChangedBytes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "logging.tar.zst")
	if err := os.WriteFile(path, []byte("qualified bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	evidence = completeQualificationEvidence(t, evidence)
	evidence, err = QualifyEvidence(evidence, ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Artifact.ContentSHA256 != evidence.ContentSHA256 {
		t.Fatal("qualified evidence did not bind the content digest into its artifact identity")
	}
	if err := WriteEvidence(root, artifact.Name, evidence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err != nil {
		t.Fatalf("qualified evidence was rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("changed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil {
		t.Fatal("changed artifact bytes were accepted")
	}
}

func TestQualifiedArtifactCacheJourneys(t *testing.T) {
	root := t.TempDir()
	artifactPath := filepath.Join(root, "artifact.bin")
	if err := os.WriteFile(artifactPath, []byte("cached appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil {
		t.Fatal("missing cache evidence was accepted; a builder is required")
	}
	evidence, err := EvidenceForFile(artifactPath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = artifactPath
	evidence = completeQualificationEvidence(t, evidence)
	evidence, err = QualifyEvidence(evidence, ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(root, artifact.Name, evidence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err != nil {
		t.Fatalf("matching qualified cache was rejected: %v", err)
	}
	if err := os.Remove(artifactPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil || !strings.Contains(err.Error(), "stat artifact") {
		t.Fatalf("missing cached artifact was accepted: %v", err)
	}
	if err := os.WriteFile(artifactPath, []byte("cached appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("corrupted appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil {
		t.Fatal("corrupt cached artifact was accepted; a fresh builder is required")
	}
}

func TestResolveArtifactEvidenceRejectsAbsolutePathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(external, "artifact.bin")
	if err := os.WriteFile(artifactPath, []byte("qualified appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(artifactPath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = artifactPath
	evidence = completeQualificationEvidence(t, evidence)
	evidence, err = QualifyEvidence(evidence, ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(root, artifact.Name, evidence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil || !strings.Contains(err.Error(), "escapes evidence root") {
		t.Fatalf("absolute artifact path outside root was accepted: %v", err)
	}
}

func TestResolveArtifactEvidenceRejectsSymlinkedPathComponent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(outside, "artifact.bin")
	if err := os.WriteFile(artifactPath, []byte("qualified appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(artifactPath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = filepath.Join(link, "artifact.bin")
	evidence = completeQualificationEvidence(t, evidence)
	evidence, err = QualifyEvidence(evidence, ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(root, artifact.Name, evidence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked artifact path component was accepted: %v", err)
	}
}

func TestResolveArtifactEvidenceRejectsChangedQualificationInputs(t *testing.T) {
	root := t.TempDir()
	artifactPath := filepath.Join(root, "artifact.bin")
	if err := os.WriteFile(artifactPath, []byte("qualified bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(artifactPath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = artifactPath
	evidence = completeQualificationEvidence(t, evidence)
	evidence, err = QualifyEvidence(evidence, ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(root, artifact.Name, evidence); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sbom.json"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil {
		t.Fatal("changed SBOM was accepted as qualified evidence")
	}
}

func TestWriteEvidenceRequiresControllerVisibleArtifactBytes(t *testing.T) {
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence := completeQualificationEvidence(t, Evidence{
		Artifact:         artifact,
		ContentSHA256:    strings.Repeat("c", 64),
		DefinitionSHA256: artifact.DefinitionSHA256,
	})
	if err := WriteEvidence(t.TempDir(), artifact.Name, evidence); err == nil || !strings.Contains(err.Error(), "artifact path") {
		t.Fatalf("evidence without a verifiable artifact path was accepted: %v", err)
	}
}

func TestQualificationRejectsMissingScanAndSecurityFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("qualified bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	if _, err := QualifyEvidence(evidence, ScanSummary{}); err == nil {
		t.Fatal("missing qualification digests were accepted")
	}
	evidence = completeQualificationEvidence(t, evidence)
	if _, err := QualifyEvidence(evidence, ScanSummary{Completed: true, Secrets: 1}); err == nil {
		t.Fatal("secret finding was accepted")
	}
	if _, err := QualifyEvidence(evidence, ScanSummary{Completed: true, FixableCritical: 1}); err == nil {
		t.Fatal("fixable CRITICAL finding was accepted")
	}
	qualified, err := QualifyEvidence(evidence, ScanSummary{Completed: true, UnfixedCritical: 1, High: 2})
	if err != nil || !qualified.Qualified {
		t.Fatalf("unfixed/high findings should report but not fail qualification: %#v %v", qualified, err)
	}
}

func TestQualificationRejectsIncompleteScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("qualified bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	evidence = completeQualificationEvidence(t, evidence)
	if _, err := QualifyEvidence(evidence, ScanSummary{}); err == nil || !strings.Contains(err.Error(), "did not complete") {
		t.Fatalf("incomplete Trivy scan was accepted: %v", err)
	}
}

func TestQualificationAllowsMissingBuilderProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("qualified bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	evidence = completeQualificationEvidence(t, evidence)
	provenancePath := filepath.Join(filepath.Dir(path), "builder-provenance.json")
	if err := os.Remove(provenancePath); err != nil {
		t.Fatal(err)
	}
	evidence.BuilderProvenanceSHA256 = ""
	qualified, err := QualifyEvidence(evidence, ScanSummary{Completed: true})
	if err != nil || !qualified.Qualified {
		t.Fatalf("qualification rejected missing optional builder provenance: %#v %v", qualified, err)
	}
	root := filepath.Dir(path)
	if err := WriteEvidence(root, artifact.Name, qualified); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err != nil {
		t.Fatalf("resolution rejected qualified artifact without optional builder provenance: %v", err)
	}
}

func TestWriteEvidenceCannotForgeEvaluatorAuthorization(t *testing.T) {
	root := t.TempDir()
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "artifact.bin")
	if err := os.WriteFile(path, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	evidence = completeQualificationEvidence(t, evidence)
	evidence.QualificationEvaluator = QualificationEvaluator
	evidence.QualificationPolicyVersion = QualificationPolicyVersion
	evidence.ScanCompleted = true
	evidence.Qualified = true
	if err := WriteEvidence(root, artifact.Name, evidence); err == nil || !strings.Contains(err.Error(), "qualification evaluator") {
		t.Fatal("WriteEvidence accepted evidence that did not pass through the evaluator")
	}
}

func TestWriteEvidenceCannotAuthorizeUnqualifiedInputs(t *testing.T) {
	root := t.TempDir()
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "artifact.bin")
	if err := os.WriteFile(path, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	evidence = completeQualificationEvidence(t, evidence)
	evidence.Qualified = true
	if err := WriteEvidence(root, artifact.Name, evidence); err == nil {
		t.Fatal("WriteEvidence accepted manually authorized evidence")
	}
}

func TestQualifiedEvidenceRequiresEvaluatorAndPolicyMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("qualified bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(path, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = path
	evidence = completeQualificationEvidence(t, evidence)
	evidence.Qualified = true
	evidence.ScanCompleted = true
	for name, mutate := range map[string]func(*Evidence){
		"wrong evaluator": func(value *Evidence) {
			value.QualificationEvaluator = "untrusted-evaluator"
			value.QualificationPolicyVersion = QualificationPolicyVersion
		},
		"missing policy": func(value *Evidence) {
			value.QualificationEvaluator = QualificationEvaluator
			value.QualificationPolicyVersion = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := evidence
			mutate(&candidate)
			if err := validateQualificationDigests(candidate); err == nil {
				t.Fatal("unauthorized qualified evidence was accepted")
			}
		})
	}
}

func completeQualificationEvidence(t *testing.T, evidence Evidence) Evidence {
	t.Helper()
	if evidence.ArtifactPath == "" {
		evidence.PackageManifestSHA = strings.Repeat("a", 64)
		evidence.SBOMSHA256 = strings.Repeat("b", 64)
		evidence.TrivyReportSHA256 = strings.Repeat("c", 64)
		evidence.BuilderProvenanceSHA256 = strings.Repeat("d", 64)
		evidence.Builder = BuilderProvenance{
			Platform: "debian-13-amd64", InputImage: "debian-13-genericcloud-amd64-20260327-2429",
			Kernel: "6.1.0", Go: "go version go1.26.5 linux/amd64", Trivy: "Version: 0.69.3",
			MMDebstrap: "mmdebstrap 1.5.0", Architecture: "amd64", BoetticherVersion: "0.5.1",
		}
		return evidence
	}
	inputs := map[string]string{
		"package-manifest.txt":    "package: boetticher-test\n",
		"sbom.json":               `{"bomFormat":"CycloneDX","specVersion":"1.5"}` + "\n",
		"trivy.json":              `{"Results":[]}` + "\n",
		"builder-provenance.json": `{"platform":"debian-13-amd64","input_image":"debian-13-genericcloud-amd64-20260327-2429","kernel":"6.1.0","go":"go version go1.26.5 linux/amd64","trivy":"Version: 0.69.3","mmdebstrap":"mmdebstrap 1.5.0","architecture":"amd64","boetticher_version":"0.5.1"}` + "\n",
	}
	for filename, content := range inputs {
		if err := os.WriteFile(filepath.Join(filepath.Dir(evidence.ArtifactPath), filename), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	evidence.PackageManifestSHA, _ = QualificationInputSHA256(filepath.Join(filepath.Dir(evidence.ArtifactPath), "package-manifest.txt"), "package manifest")
	evidence.SBOMSHA256, _ = QualificationInputSHA256(filepath.Join(filepath.Dir(evidence.ArtifactPath), "sbom.json"), "SBOM")
	evidence.TrivyReportSHA256, _ = QualificationInputSHA256(filepath.Join(filepath.Dir(evidence.ArtifactPath), "trivy.json"), "Trivy report")
	evidence.BuilderProvenanceSHA256, _ = QualificationInputSHA256(filepath.Join(filepath.Dir(evidence.ArtifactPath), "builder-provenance.json"), "builder provenance")
	evidence.Builder = BuilderProvenance{
		Platform: "debian-13-amd64", InputImage: "debian-13-genericcloud-amd64-20260327-2429",
		Kernel: "6.1.0", Go: "go version go1.26.5 linux/amd64", Trivy: "Version: 0.69.3",
		MMDebstrap: "mmdebstrap 1.5.0", Architecture: "amd64", BoetticherVersion: "0.5.1",
	}
	return evidence
}

func TestBuiltInArtifactsSharePinnedBase(t *testing.T) {
	if err := ValidateDefinitions(); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"dns", "monitoring", "firewall"} {
		artifact, err := ArtifactFor(module)
		if err != nil {
			t.Fatal(err)
		}
		if artifact.ContentSHA256 != "" || artifact.DefinitionSHA256 == "" {
			t.Fatalf("artifact %s has incomplete digest metadata", module)
		}
	}
}

func TestArtifactIdentityIsDeterministic(t *testing.T) {
	first, err := ArtifactFor("dns")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ArtifactFor("dns")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("artifact identity changed: %#v != %#v", first, second)
	}
}

func TestArtifactDefinitionDigestBindsBuildInputs(t *testing.T) {
	definition, ok := func() (Definition, bool) {
		for _, candidate := range Definitions() {
			if candidate.Name == "dns" && candidate.ArtifactName == "boetticher-dns-blocky" {
				return candidate, true
			}
		}
		return Definition{}, false
	}()
	if !ok || len(definition.Inputs) == 0 {
		t.Fatalf("Blocky definition has no build inputs: %#v", definition)
	}
	original, err := definitionSHA256(definition)
	if err != nil {
		t.Fatal(err)
	}
	changed := definition
	changed.Version = "1.0.1"
	updated, err := definitionSHA256(changed)
	if err != nil {
		t.Fatal(err)
	}
	if original == updated {
		t.Fatal("artifact definition digest did not change when the recipe identity changed")
	}
	for _, input := range definition.Inputs {
		if _, err := fs.Stat(buildbundle.FS, input); err != nil {
			t.Fatalf("definition input %q is not embedded: %v", input, err)
		}
	}
}

func TestCheckedInImageDefinitionsUseThePinnedBase(t *testing.T) {
	root := filepath.Join("..", "..", "images")
	paths := []string{"base/debian.yaml", "dns/image.yaml", "dns/blocky/image.yaml", "logging/image.yaml", "monitoring/image.yaml", "firewall/image.yaml", "tailnet-router/image.yaml", "bifrost/image.yaml", "printer/image.yaml", "aiops/image.yaml"}
	for _, relative := range paths {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, "base_version: "+BaseVersion) && relative != "base/debian.yaml" {
			t.Errorf("%s does not pin base version %s", relative, BaseVersion)
		}
		if relative != "base/debian.yaml" && !strings.Contains(text, "base: "+BaseName) {
			t.Errorf("%s does not consume %s", relative, BaseName)
		}
	}
	blocky, err := os.ReadFile(filepath.Join(root, "dns", "blocky", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	blockyChecksum := "17b03f892346a160e9faf974ce68baae85fa4f2a94d7bf8ea52592a94be5eeb4"
	if !strings.Contains(string(blocky), "implementation_sha256: "+blockyChecksum) {
		t.Fatal("Blocky release checksum is not pinned")
	}
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buildScript), "download_cached \"$archive\" https://github.com/0xERR0R/blocky/releases/download/v0.34.0/blocky_v0.34.0_Linux_x86_64.tar.gz "+blockyChecksum+" sha256sum") {
		t.Fatal("Blocky build does not use the image definition checksum")
	}
	dnsCommon, err := os.ReadFile(filepath.Join(root, "dns", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"repository: trixie-auth-49",
		"package_version: 4.9.17-1pdns.trixie",
		"signing_key_sha256: efeb5b1451c76de1dac8eefaddba5af5549e8fd93484728744ea7b4923decae8",
		"signing_key_fingerprint: 9FAAA5577E8FCF62093D036C1B0C6205FD380FBB",
	} {
		if !strings.Contains(string(dnsCommon), required) {
			t.Fatalf("DNS image definition is missing PowerDNS qualification input %q", required)
		}
	}
	filteringPolicy, err := os.ReadFile(filepath.Join(root, "dns", "common", "filtering-policy.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(filteringPolicy), "# boetticher-filter-v1") {
		t.Fatal("DNS filtering policy snapshot is not revisioned")
	}
	monitoring, err := os.ReadFile(filepath.Join(root, "monitoring", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"version: 6.1.2",
		"release_url: https://github.com/rcourtman/Pulse/releases/download/v6.1.2/pulse-v6.1.2-linux-amd64.tar.gz",
		"release_sha256: 844cd054bcfce528cbcf434d782e571791cc7b02ef2fe298cf138b1cab1087ea",
		"release_url: https://github.com/rcourtman/Pulse/releases/download/v6.1.2/pulse-agent-linux-amd64",
		"release_sha256: 1f3cfda2b112e82f311f05673f750bc6e5cb05bd0f942f9b84d7612d56f1ba75",
	} {
		if !strings.Contains(string(monitoring), required) {
			t.Fatalf("monitoring image definition is missing Pulse qualification input %q", required)
		}
	}
	buildScript, err = os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pulseService, err := os.ReadFile(filepath.Join(root, "monitoring", "runtime", "pulse.service"))
	if err != nil {
		t.Fatal(err)
	}
	runPulse, err := os.ReadFile(filepath.Join(root, "monitoring", "runtime", "run-pulse.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"pulse_release_sha256", "/opt/pulse/bin/pulse", "pulse.service", "run-pulse.sh", "chmod 0755 \"$rootfs/usr/lib/boetticher\""} {
		if !strings.Contains(string(buildScript), required) {
			t.Fatalf("monitoring build is missing Pulse runtime contract %q", required)
		}
	}
	runPulseText := string(runPulse)
	if strings.Contains(runPulseText, "grep -q '[\\r\\n]'") {
		t.Fatal("Pulse credential wrapper uses a grep expression that rejects ordinary r/n characters")
	}
	for _, required := range []string{"[ \"$(wc -l < \"$credential\")\" -ne 0 ]", "grep -q \"$(printf '\\r')\" \"$credential\""} {
		if !strings.Contains(runPulseText, required) {
			t.Fatalf("Pulse credential wrapper is missing byte-safe validation %q", required)
		}
	}
	if !strings.Contains(string(pulseService), "Environment=BIND_ADDRESS=127.0.0.1") {
		t.Fatal("Pulse service is not bound to loopback behind the TLS frontend")
	}
	if strings.Contains(string(pulseService), "CAP_NET_RAW") || strings.Contains(string(pulseService), "AmbientCapabilities") || strings.Contains(string(pulseService), "CapabilityBoundingSet") {
		t.Fatal("Pulse service grants an unnecessary raw-socket capability")
	}
	if strings.Contains(string(monitoring), "latest") || strings.Contains(string(buildScript), "zabbix") || strings.Contains(string(buildScript), "postgresql") {
		t.Fatal("monitoring build retains a floating input or obsolete monitoring dependency")
	}
	firewall, err := os.ReadFile(filepath.Join(root, "firewall", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(firewall), "debian-13-genericcloud-amd64-20260327-2429.qcow2") || !strings.Contains(string(firewall), "sha512:") || strings.Contains(string(firewall), "/daily/latest/") {
		t.Fatal("firewall image does not pin its Debian 13 VM input")
	}
	tailnet, err := os.ReadFile(filepath.Join(root, "tailnet-router", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"name: boetticher-tailnet-router",
		"version: 1.0.0",
		"version: 1.76.6",
		"signing_key_sha256: 3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39",
		"advertise_routes: 10.10.0.0/16",
		"advertise_exit_node: false",
	} {
		if !strings.Contains(string(tailnet), required) {
			t.Fatalf("tailnet-router image definition is missing %q", required)
		}
	}
	if !strings.Contains(string(buildScript), `install_packages "$rootfs" dbus "tailscale=$tailscale_package_version"`) {
		t.Fatal("tailnet-router build does not install the system D-Bus required by its systemd lifecycle")
	}
	bifrost, err := os.ReadFile(filepath.Join(root, "bifrost", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"name: boetticher-bifrost",
		"version: 1.0.0",
		"router: bifrost",
		"router_contract: bifrost-openai-compatible",
		"nginx: 1.26.3-3+deb13u7",
		"backend_bind: 127.0.0.1:4000",
		"mtls_required: true",
	} {
		if !strings.Contains(string(bifrost), required) {
			t.Fatalf("Bifrost image definition is missing %q", required)
		}
	}
	smokeScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "smoke-appliance.sh"))
	if err != nil {
		t.Fatal(err)
	}
	buildText := string(buildScript)
	smokeText := string(smokeScript)
	for _, required := range []string{
		"build_tailnet_router",
		"build_bifrost",
		"CGO_ENABLED=0 go build",
		"getent passwd bifrost | grep -Eq '^bifrost:'",
		"grep -Fxq 'User=bifrost' \"$rootfs/etc/systemd/system/bifrost.service\"",
		"grep -Fxq 'CapabilityBoundingSet=' \"$rootfs/etc/systemd/system/bifrost.service\"",
		"boetticher-bifrost",
		"rm -f \"$rootfs/etc/nginx/sites-enabled/default\"",
	} {
		if !strings.Contains(buildText+smokeText, required) {
			t.Fatalf("Bifrost build hygiene is missing %q", required)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "bifrost", "runtime", "bifrost-start")); !os.IsNotExist(err) {
		t.Fatalf("Bifrost artifact retains the removed Python launcher: %v", err)
	}
}

func TestIssue22BuildAndQualificationPathsPreserveEvidenceWithBoundedWork(t *testing.T) {
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	scanScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "scan-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	buildText := string(buildScript)
	scanText := string(scanScript)
	if !strings.Contains(buildText, "BOETTICHER_BASE_ROOTFS") || !strings.Contains(buildText, "BOETTICHER_SKIP_PROVENANCE=1") || !strings.Contains(buildText, `timing_emit "artifact_build"`) || !strings.Contains(buildText, "artifact_temporary=") || !strings.Contains(buildText, "mv -f -- \"$artifact_temporary\" \"$artifact_path\"") {
		t.Fatal("bounded image workers do not isolate their base rootfs, provenance, and timing contract")
	}
	if !strings.Contains(buildText, `timing_emit "artifact_build_all"`) || !strings.Contains(buildText, "pid_a=") || !strings.Contains(buildText, "pid_b=") || !strings.Contains(buildText, "memory-heavy") {
		t.Fatal("image construction is missing explicit bounded worker scheduling")
	}
	if strings.Count(buildText, "image-tailnet-router|image-bifrost|image-aiops") != 2 {
		t.Fatal("AIOps is not accepted by both direct and selected image target validation")
	}
	benchmarkScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "benchmark-artifact-compression.sh"))
	if err != nil {
		t.Fatal(err)
	}
	benchmarkText := string(benchmarkScript)
	if !strings.Contains(buildText, "zstd_level=${BOETTICHER_ZSTD_LEVEL:-3}") || !strings.Contains(buildText, `zstd -T0 "-$2"`) || !strings.Contains(buildText, `measurement_emit "artifact_compression"`) || !strings.Contains(buildText, "artifact_inventory") {
		t.Fatal("artifact compression does not expose bounded measurement levels with the measured default")
	}
	for _, required := range []string{
		"BOETTICHER_BENCHMARK_ZSTD_LEVELS",
		"BOETTICHER_BENCHMARK_INCLUDE_PLAIN",
		"rootfs_apparent_bytes",
		"rootfs_allocated_bytes",
		"file_count",
		"cpu_user_ms",
		"compression_ratio",
	} {
		if !strings.Contains(benchmarkText, required) {
			t.Fatalf("artifact compression benchmark is missing %q", required)
		}
	}
	if strings.Count(scanText, "trivy fs --scanners vuln,secret") != 1 || !strings.Contains(scanText, "trivy fs --download-db-only") || !strings.Contains(scanText, "--skip-db-update") {
		t.Fatalf("qualification performs more than one full Trivy filesystem scan: %d", strings.Count(scanText, "trivy fs --scanners vuln,secret"))
	}
	if strings.Count(scanText, "trivy convert") != 2 || !strings.Contains(scanText, "--list-all-pkgs") {
		t.Fatal("qualification does not derive table and SBOM evidence from the canonical scan")
	}
	if !strings.Contains(scanText, `timing_emit "artifact_trivy_db_update"`) || !strings.Contains(scanText, `timing_emit "artifact_trivy_scan"`) || !strings.Contains(scanText, `timing_emit "artifact_qualification_all"`) {
		t.Fatal("qualification timing output is incomplete")
	}
	if !strings.Contains(scanText, "timing_artifact=${3:-}") || strings.Contains(scanText, "timing_emit() {\n  stage=$1\n  duration_ms=$2\n  artifact=${3:-}") {
		t.Fatal("qualification timing helper must not overwrite the artifact path")
	}
	for _, required := range []string{
		"module=${name#boetticher-}",
		"[ \"$module\" = dns-blocky ] && module=dns",
		"if ! GOCACHE=${GOCACHE:-/tmp/boetticher-gocache} go run ./cmd/qualify-artifact",
	} {
		if !strings.Contains(scanText, required) {
			t.Fatalf("qualification does not derive or fail-closed validate artifact module identity: missing %q", required)
		}
	}
	if strings.Contains(buildText, "build_dns_blocky() {\n  printf '%s\\n' 'boetticher build stage: dns blocky'\n  rootfs=$(prepare_rootfs boetticher-dns-blocky)\n  install_powerdns \"$rootfs\"\n  install_packages \"$rootfs\" chrony") {
		t.Fatal("DNS construction still performs a redundant package-index transaction")
	}
	if !strings.Contains(buildText, `install_packages "$rootfs" arping dnsutils isc-dhcp-client iperf3 netcat-openbsd nmap tcpdump`) {
		t.Fatal("network probe image does not include the DHCP client required by dynamic zones")
	}
}

func TestLoggingBuildInstallsDeclaredServices(t *testing.T) {
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	buildText := string(buildScript)
	if !strings.Contains(buildText, "build_logging()") || !strings.Contains(buildText, "install_packages \"$rootfs\" systemd-journal-remote nginx") {
		t.Fatal("logging image build does not install both declared runtime services")
	}
}

func TestBaseDefinitionPinsTheDebianSnapshotInput(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "images", "base", "debian.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"release: trixie",
		"mirror: https://snapshot.debian.org/archive/debian/20260825T000000Z/",
		"snapshot: 20260825T000000Z",
		"build:\n  packages:",
		"    - ifupdown",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("base definition is missing pinned Debian source %q", required)
		}
	}
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buildScript), "base_packages=$(awk") || !strings.Contains(string(buildScript), "--include=\"$base_packages\"") || !strings.Contains(string(buildScript), "--aptopt=Acquire::Check-Valid-Until=false") || !strings.Contains(string(buildScript), "--aptopt=Acquire::Retries=3") || !strings.Contains(string(buildScript), "debian-security-snapshot.sources") || !strings.Contains(string(buildScript), "apt-get --no-download upgrade --yes --no-install-recommends") {
		t.Fatal("base builder does not use the pinned Debian snapshot")
	}
	if !strings.Contains(string(buildScript), `dpkg-query -W -f='\${binary:Package}\\t\${Version}\\n'`) {
		t.Fatal("firewall package-manifest command does not protect dpkg-query format variables from the guest shell")
	}
	if strings.Contains(string(buildScript), "systemctl disable --now systemd-networkd-wait-online.service") {
		t.Fatal("firewall image customization tries to start or stop systemd in an offline image")
	}
	for _, required := range []string{
		"prepare_firewall_package_cache",
		"virt-cat -a \"$input\" /var/lib/dpkg/status",
		"--no-network",
		"BOETTICHER_LOCAL_FAST",
		"--tar-in \"$package_archive_tar\":/var/cache/apt/archives",
		"--tar-in \"$package_lists_tar\":/var/lib/apt/lists",
		"apt-get --no-download install",
	} {
		if !strings.Contains(string(buildScript), required) {
			t.Fatalf("firewall local package-cache build is missing %q", required)
		}
	}
	smokeFirewall, err := os.ReadFile(filepath.Join("..", "..", "scripts", "smoke-firewall-image.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(smokeFirewall), `"definition_sha256"[[:space:]]*:[[:space:]]*"[a-fA-F0-9]{64}"`) {
		t.Fatal("firewall smoke check does not accept compact JSON artifact identity")
	}
}

func TestAIOpsArtifactPinsUnmodifiedHolmesAndIsolation(t *testing.T) {
	root := filepath.Join("..", "..")
	definition, err := os.ReadFile(filepath.Join(root, "images", "aiops", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.ReadFile(filepath.Join(root, "images", "aiops", "runtime", "requirements.lock"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(root, "images", "aiops", "runtime", "holmes.service"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(root, "images", "aiops", "runtime", "holmes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	build, err := os.ReadFile(filepath.Join(root, "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		text string
		want []string
	}{
		{"definition", string(definition), []string{"holmesgpt: 0.40.0", "https://codeload.github.com/HolmesGPT/holmesgpt/tar.gz/3d201559c0f3648a6c567aece09662f4f407bcc9", "7016d3335a7f81810de35d9030a63bc38204d94991e3343d6cdbbcaf77a755be", "holmes_network: loopback-only"}},
		{"lock", string(lock), []string{"holmesgpt==0.40.0", "greenlet==3.5.5", "--hash=sha256:2eabb980975cba5b93a95f6f69287d05fc05ac955bfd6a320a7c083eeb52c0b0"}},
		{"service", string(service), []string{"/opt/holmes/bin/python -u /opt/holmes/server.py", "HOLMES_HOST=127.0.0.1", "HOLMES_CONFIGPATH_DIR=/etc/boetticher-aiops", "HOLMES_TOOL_RESULT_STORAGE_ENABLED=false", "OVERRIDE_MAX_OUTPUT_TOKEN=1200", "IPAddressDeny=any", "IPAddressAllow=localhost"}},
		{"config", string(config), []string{"max_steps: 12", "internet:\n    enabled: false", "http://127.0.0.1:8443", "/v1/evidence/query", "methods:\n            - POST"}},
		{"build", string(build), []string{"holmes_source_sha256=7016d3335a7f81810de35d9030a63bc38204d94991e3343d6cdbbcaf77a755be", "sha256sum --check --status", "holmes_source_root/server.py"}},
	}
	for _, check := range checks {
		for _, required := range check.want {
			if !strings.Contains(check.text, required) {
				t.Errorf("%s is missing %q", check.name, required)
			}
		}
	}
	if strings.Contains(string(service), "holmes serve") {
		t.Fatal("AIOps uses the nonexistent Holmes 0.40.0 wheel serve command")
	}
	smoke, err := os.ReadFile(filepath.Join(root, "scripts", "smoke-appliance.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"boetticher-aiops)", "/usr/local/libexec/boetticher-aiops", "holmes.service", "IPAddressDeny=any", "config.yaml", "test ! -e \"$rootfs/etc/boetticher-aiops/runtime.env\""} {
		if !strings.Contains(string(smoke), required) {
			t.Fatalf("AIOps smoke contract is missing %q", required)
		}
	}
}

func TestGatusArtifactSmokeContractUsesSupportedChecks(t *testing.T) {
	smoke, err := os.ReadFile(filepath.Join("..", "..", "scripts", "smoke-appliance.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(smoke)
	for _, required := range []string{
		"boetticher-gatus)",
		"test -x \"$rootfs/usr/local/bin/gatus\"",
		"test -f \"$rootfs/etc/systemd/system/gatus.service\"",
		"User=gatus",
		"Environment=GATUS_CONFIG_PATH=/etc/boetticher/gatus/config.yaml",
		"ExecStart=/usr/local/bin/gatus",
		"test ! -e \"$rootfs/etc/boetticher/gatus/config.yaml\"",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Gatus smoke contract is missing %q", required)
		}
	}
	if strings.Contains(text, "run /usr/local/bin/gatus version") {
		t.Fatal("Gatus smoke contract invokes an unsupported version subcommand")
	}
	if strings.Contains(text, "--config-path") {
		t.Fatal("Gatus smoke contract invokes an unsupported config-path argument")
	}
}

func TestApplianceBuildEmbedsDefinitionIdentityWithoutContentEvidence(t *testing.T) {
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(buildScript)
	for _, required := range []string{
		"write_artifact_identity \"$rootfs\" base",
		"write_artifact_identity \"$rootfs\" dns",
		"write_artifact_identity \"$rootfs\" logging",
		"write_artifact_identity \"$rootfs\" monitoring",
		"ConditionPathExists=/etc/blocky/config.yml",
		"-upload \"$artifact_identity:/usr/lib/boetticher/artifact.json\"",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("build path does not embed non-secret definition identity: %q", required)
		}
	}
}

func TestApplianceBuildUsesPersistentFilesystemAndPackageCaches(t *testing.T) {
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(buildScript)
	for _, required := range []string{
		"cp -a --reflink=auto",
		"pip_install \"$rootfs\"",
		"mount --bind \"$pip_cache\" \"$rootfs/root/.cache/pip\"",
		"pip_cache=\"$cache_root/pip\"",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("image build is missing persistent cache optimization %q", required)
		}
	}
	if strings.Contains(text, "--no-cache-dir") {
		t.Fatal("Python image builds explicitly disable the persistent pip cache")
	}
}

func TestCachedDownloadDoesNotClobberBuildVariables(t *testing.T) {
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(buildScript)
	start := strings.Index(text, "download_cached() {")
	if start < 0 {
		t.Fatal("cached download helper is missing")
	}
	remainder := text[start:]
	end := strings.Index(remainder, "\n}\n")
	if end < 0 {
		t.Fatal("cached download helper is not closed")
	}
	helper := remainder[:end]
	for _, required := range []string{"cache_destination=$1", "cache_url=$2", "cache_expected=$3", "cache_checker=$4", "cache_temporary="} {
		if !strings.Contains(helper, required) {
			t.Fatalf("cached download helper does not isolate %q", required)
		}
	}
	for _, forbidden := range []string{"\ndestination=", "\nurl=", "\nexpected=", "\nchecker=", "\ntemporary="} {
		if strings.Contains(helper, forbidden) {
			t.Fatalf("cached download helper assigns caller variable %q", forbidden[1:])
		}
	}
}

func TestFirewallBuildUsesIndividualVirtCustomizeDirectories(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "--mkdir /etc/boetticher,/usr/lib/boetticher") {
		t.Fatal("firewall virt-customize directory inputs must remain individual paths")
	}
	for _, directory := range []string{"--mkdir /etc/boetticher", "--mkdir /usr/lib/boetticher", "--mkdir /var/lib/boetticher/identity/ssh", "--mkdir /var/lib/boetticher/ansible"} {
		if !strings.Contains(text, directory) {
			t.Fatalf("firewall build is missing directory input %q", directory)
		}
	}
}

func TestFirewallBuildUsesCommonSSHHardeningContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "--upload images/base/runtime/sshd.conf:/etc/ssh/sshd_config.d/boetticher.conf") {
		t.Fatal("firewall build does not consume the common SSH hardening contract")
	}
	sshConfig, err := os.ReadFile(filepath.Join("..", "..", "images", "base", "runtime", "sshd.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitRootLogin prohibit-password"} {
		if !strings.Contains(string(sshConfig), required) {
			t.Fatalf("common SSH hardening is missing %q", required)
		}
	}
}

func TestApplianceBootstrapInputsContainNoOperatorKeyOrSiteState(t *testing.T) {
	root := filepath.Join("..", "..", "images")
	firstBoot, err := os.ReadFile(filepath.Join(root, "base", "first-boot", "boetticher-first-boot.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(firstBoot)
	if !strings.Contains(text, "/run/boetticher/bootstrap/operator.pub") || !strings.Contains(text, "/root/.ssh/authorized_keys") || strings.Contains(text, "ssh-ed25519 AAAA") {
		t.Fatalf("first-boot contract does not use injected-only operator access: %s", text)
	}
	if !strings.Contains(text, "systemctl disable boetticher-first-boot.service") || strings.Contains(text, "systemctl stop boetticher-first-boot.service") {
		t.Fatalf("first-boot service must disable itself and finish its oneshot without self-stopping: %s", text)
	}
	runtimeState, err := os.ReadFile(filepath.Join(root, "base", "runtime", "install-runtime-state.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runtimeState), "module-config") || !strings.Contains(string(runtimeState), "artifact-identity") || strings.Contains(string(runtimeState), "eval ") {
		t.Fatalf("runtime state helper is not bounded: %s", runtimeState)
	}
	runtimeStateText := string(runtimeState)
	for _, required := range []string{"directory_mode=0751", "directory_mode=0755", `install -d -m "$directory_mode" "$directory"`} {
		if !strings.Contains(runtimeStateText, required) {
			t.Fatalf("runtime state helper is missing directory permission contract %q", required)
		}
	}
	for _, relative := range []string{"firewall/nocloud/meta-data", "firewall/nocloud/network-config", "firewall/nocloud/user-data"} {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "ssh-ed25519 AAAA") || strings.Contains(string(data), "age1") {
			t.Fatalf("%s contains operator or site secret material", relative)
		}
	}
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	buildText := string(buildScript)
	for _, required := range []string{`chroot "$rootfs" chown root:root /etc/sudoers.d/boetticher`, `--run-command 'chown root:root /etc/sudoers.d/boetticher-firewall; chmod 0440 /etc/sudoers.d/boetticher-firewall'`} {
		if !strings.Contains(buildText, required) {
			t.Fatalf("image build does not reset sudoers ownership: missing %q", required)
		}
	}
	sudoers, err := os.ReadFile(filepath.Join(root, "base", "runtime", "boetticher.sudoers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(sudoers), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Fatalf("base appliance sudo policy retains a durable command rule: %q", line)
		}
	}
	if strings.Contains(buildText+string(sudoers), "NOPASSWD:ALL") {
		t.Fatal("appliance sudo policy grants an unrestricted root command")
	}
}

func TestDurableApplianceLabadminCannotUseRootCommandContracts(t *testing.T) {
	sudoers, err := os.ReadFile(filepath.Join("..", "..", "images", "base", "runtime", "boetticher.sudoers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(sudoers), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Fatalf("base sudoers contains an active durable privilege rule: %q", line)
		}
	}
}

func TestFirewallInspectionContractIsRootOwnedAndFailClosed(t *testing.T) {
	sudoers, err := os.ReadFile(filepath.Join("..", "..", "images", "firewall", "runtime", "boetticher.sudoers"))
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile(filepath.Join("..", "..", "images", "firewall", "runtime", "inspect-firewall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	policyText, helperText := string(sudoers), string(helper)
	for _, operation := range []string{"status", "ruleset", "table", "leases", "ddns-stats", "kernel-logs"} {
		if !strings.Contains(policyText, "inspect-firewall "+operation) || !strings.Contains(helperText, operation) {
			t.Fatalf("firewall inspection operation %q is not present in both contracts", operation)
		}
	}
	for _, required := range []string{"[ \"$#\" -eq 1 ]", "[ \"$#\" -eq 3 ]", "-le 1000", "boetticher_filter", "case \"$3\""} {
		if !strings.Contains(helperText, required) {
			t.Fatalf("firewall inspection helper is missing fail-closed guard %q", required)
		}
	}
	for _, forbidden := range []string{"sh -c", "eval ", "install ", "mkdir ", "chown ", "chmod ", "systemctl start", "systemctl stop", "sysctl -w", "pvesh", "pvesm", "sqlite3", "systemd-creds"} {
		if strings.Contains(policyText+helperText, forbidden) {
			t.Fatalf("firewall inspection contract contains forbidden operation %q", forbidden)
		}
	}
}

func TestBaseBuildRemovesBakedSSHHostKeys(t *testing.T) {
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	smokeScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "smoke-appliance.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buildScript), `rm -f "$rootfs"/etc/ssh/ssh_host_*`) || !strings.Contains(string(buildScript), `rm -f "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"`) || !strings.Contains(string(buildScript), `package_lxc()`) {
		t.Fatal("image build does not remove generated private identity material before packaging")
	}
	if strings.Contains(string(buildScript), `rm -f "$rootfs/etc/ssh/ssh_host_*"`) {
		t.Fatal("base build quotes the SSH host-key glob and leaves baked keys behind")
	}
	if !strings.Contains(string(smokeScript), "artifact contains baked SSH host identity") {
		t.Fatal("appliance smoke test does not reject baked SSH host keys")
	}
}

func TestBuildSourceArchiveIsAllowListedAndDeterministic(t *testing.T) {
	first, err := BuildSourceArchive(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSourceArchive(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("public build source archive is not deterministic")
	}
	reader, err := gzip.NewReader(strings.NewReader(string(first)))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(reader)
	entries := map[string]bool{}
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = true
	}
	for _, required := range []string{"buildbundle.go", "scripts/build-images.sh", "images/base/debian.yaml", "images/tailnet-router/image.yaml", "cmd/boetticher-bifrost/main.go", "internal/bifrost/router.go", "cmd/boetticher-streamdeck/main.go", "internal/streamdeck/pulse.go", "cmd/qualify-artifact/main.go", "cmd/boetticher-aiops/main.go", "cmd/boetticher-log-query/main.go", "internal/aiops/aiops.go", "internal/gatus/gatus.go", "internal/usbexport/plan.go"} {
		if !entries[required] {
			t.Fatalf("archive omitted public build input %s", required)
		}
	}
	for _, forbidden := range []string{"site.yml", "generated/model.json", "secrets.yaml", "identity.txt"} {
		if entries[forbidden] {
			t.Fatalf("archive included forbidden build input %s", forbidden)
		}
	}
}

func TestEmbeddedBuildSourceArchiveIsAllowListedAndDeterministic(t *testing.T) {
	first, err := BuildEmbeddedSourceArchive()
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildEmbeddedSourceArchive()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("embedded public build source archive is not deterministic")
	}
	reader, err := gzip.NewReader(strings.NewReader(string(first)))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(reader)
	entries := map[string]bool{}
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = true
	}
	for _, required := range []string{"buildbundle.go", "scripts/build-images.sh", "images/base/debian.yaml", "cmd/qualify-artifact/main.go", "internal/logging/plan.go"} {
		if !entries[required] {
			t.Fatalf("embedded archive omitted public build input %s", required)
		}
	}
	for _, forbidden := range []string{"site.yml", "generated/model.json", "secrets.yaml", "identity.txt"} {
		if entries[forbidden] {
			t.Fatalf("embedded archive included forbidden build input %s", forbidden)
		}
	}
}

func TestEmbeddedCompanionSourceArchiveContainsOnlyProvisioningAssets(t *testing.T) {
	archiveBytes, err := BuildEmbeddedCompanionSourceArchive()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(strings.NewReader(string(archiveBytes)))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(reader)
	entries := map[string]bool{}
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = true
	}
	for _, required := range []string{
		"ansible/companion.yml",
		"ansible/roles/kiosk/tasks/main.yml",
		"ansible/roles/kiosk/templates/boetticher-streamdeck.service.j2",
		"pi/kiosk/visualizer/index.html",
	} {
		if !entries[required] {
			t.Fatalf("embedded companion archive omitted %s", required)
		}
	}
	for _, forbidden := range []string{"site.yml", "generated/model.json", "secrets.yaml", "identity.txt"} {
		if entries[forbidden] {
			t.Fatalf("embedded companion archive included forbidden state %s", forbidden)
		}
	}
}

func TestEmbeddedAnsibleSourceArchiveContainsDeploymentRolesOnly(t *testing.T) {
	archiveBytes, err := BuildEmbeddedAnsibleSourceArchive()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(strings.NewReader(string(archiveBytes)))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(reader)
	entries := map[string]bool{}
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = true
	}
	for _, required := range []string{
		"ansible/site.yml",
		"ansible/roles/base/tasks/main.yml",
		"ansible/roles/monitor/templates/pulse-loopback.conf.j2",
		"ansible/roles/kiosk/templates/boetticher-streamdeck.service.j2",
	} {
		if !entries[required] {
			t.Fatalf("embedded Ansible archive omitted %s", required)
		}
	}
	for _, forbidden := range []string{"site.yml", "generated/model.json", "secrets.yaml", "identity.txt", "pi/kiosk/visualizer/index.html"} {
		if entries[forbidden] {
			t.Fatalf("embedded Ansible archive included forbidden source or state %s", forbidden)
		}
	}
}

func TestBuildSourceArchiveContainsBlockyRendererDependencies(t *testing.T) {
	archive, err := BuildSourceArchive(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(reader)
	entries := map[string]bool{}
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = true
	}
	for _, relative := range []string{"cmd/render-blocky-config/main.go", "internal/dns/recursive.go", "internal/dns/dns.go", "internal/modules/compose.go", "internal/pathguard/pathguard.go"} {
		if !entries[relative] {
			t.Fatalf("transferred builder source is missing %s", relative)
		}
	}
}

func TestTransferredEvidenceIsReboundToControllerArtifactBytes(t *testing.T) {
	root, err := os.MkdirTemp(".", ".artifact-relative-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	relativeRoot, err := filepath.Rel(".", root)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(root, "generated", "artifacts", artifact.Name, artifact.Name+"-"+artifact.Version+"-"+artifact.Architecture+".tar.zst")
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("builder bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := EvidenceForFile(artifactPath, artifact)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ArtifactPath = artifactPath
	evidence = completeQualificationEvidence(t, evidence)
	evidence.ArtifactPath = "/home/labadmin/build/generated/artifacts/boetticher-logging/boetticher-logging-1.0.0-amd64.tar.zst"
	qualified, err := QualifyEvidence(evidence, ScanSummary{Completed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(root, artifact.Name, qualified); err != nil {
		t.Fatal(err)
	}
	qualified.ArtifactPath = filepath.Join("generated", "artifacts", artifact.Name, filepath.Base(artifactPath))
	if err := WriteEvidence(root, artifact.Name, qualified); err != nil {
		t.Fatal(err)
	}
	resolved, rebound, err := ResolveArtifactEvidence(relativeRoot, artifact)
	if err != nil {
		t.Fatalf("relative cached evidence was rejected: %v", err)
	}
	if !filepath.IsAbs(rebound.ArtifactPath) {
		t.Fatalf("resolved artifact path = %q, want absolute path", rebound.ArtifactPath)
	}
	if resolved.ContentSHA256 != evidence.ContentSHA256 {
		t.Fatalf("resolved content checksum = %q, want %q", resolved.ContentSHA256, evidence.ContentSHA256)
	}
	qualified.ArtifactPath = "/home/labadmin/build/generated/artifacts/boetticher-logging/boetticher-logging-1.0.0-amd64.tar.zst"
	if err := WriteEvidence(root, artifact.Name, qualified); err != nil {
		t.Fatal(err)
	}
	if err := RebindEvidencePaths(relativeRoot); err != nil {
		t.Fatal(err)
	}
	resolved, rebound, err = ResolveArtifactEvidence(relativeRoot, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(rebound.ArtifactPath) {
		t.Fatalf("rebound artifact path = %q, want absolute path", rebound.ArtifactPath)
	}
	if resolved.ContentSHA256 != evidence.ContentSHA256 {
		t.Fatalf("rebound content checksum = %q, want %q", resolved.ContentSHA256, evidence.ContentSHA256)
	}
}

func TestPulseProxyAuthRendererUsesOnlyRuntimeCredentialMaterial(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "pulse-nginx-proxy-auth.sh.j2")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"/run/credentials/nginx.service/pulse-proxy-auth-nginx-secret",
		"/run/boetticher/pulse-proxy-auth.conf",
		"case \"$secret\" in",
		"set $boetticher_pulse_proxy_shared_secret",
		"chmod 0600",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Pulse proxy-auth renderer is missing %q", required)
		}
	}
	for _, forbidden := range []string{"pulse_proxy_auth_secret:", "PROXY_AUTH_SECRET=", "echo \"$secret\""} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Pulse proxy-auth renderer contains unsafe materialization %q", forbidden)
		}
	}
}

func TestPulseServiceDoesNotSetInvalidDisabledAgentIngestPort(t *testing.T) {
	path := filepath.Join("..", "..", "images", "monitoring", "runtime", "pulse.service")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PULSE_AGENT_INGEST_PORT=0") {
		t.Fatal("Pulse service sets an invalid disabled agent-ingest port; leave the option unset")
	}
}
