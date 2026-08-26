package artifacts

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	evidence = completeQualificationEvidence(evidence)
	evidence, err = QualifyEvidence(evidence, ScanSummary{})
	if err != nil {
		t.Fatal(err)
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
	if _, err := QualifyEvidence(evidence, ScanSummary{}); err == nil {
		t.Fatal("missing qualification digests were accepted")
	}
	evidence = completeQualificationEvidence(evidence)
	if _, err := QualifyEvidence(evidence, ScanSummary{Secrets: 1}); err == nil {
		t.Fatal("secret finding was accepted")
	}
	if _, err := QualifyEvidence(evidence, ScanSummary{FixableCritical: 1}); err == nil {
		t.Fatal("fixable CRITICAL finding was accepted")
	}
	qualified, err := QualifyEvidence(evidence, ScanSummary{UnfixedCritical: 1, High: 2})
	if err != nil || !qualified.Qualified {
		t.Fatalf("unfixed/high findings should report but not fail qualification: %#v %v", qualified, err)
	}
}

func completeQualificationEvidence(evidence Evidence) Evidence {
	evidence.PackageManifestSHA = strings.Repeat("a", 64)
	evidence.SBOMSHA256 = strings.Repeat("b", 64)
	evidence.TrivyReportSHA256 = strings.Repeat("c", 64)
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

func TestCheckedInImageDefinitionsUseThePinnedBase(t *testing.T) {
	root := filepath.Join("..", "..", "images")
	paths := []string{"base/debian.yaml", "dns/image.yaml", "dns/blocky/image.yaml", "dns/adguard/image.yaml", "logging/image.yaml", "monitoring/image.yaml", "firewall/image.yaml", "portal/image.yaml"}
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
	if !strings.Contains(string(blocky), "provider_sha256: 17b03f892346a160e9faf974ce68baae85fa4f2a94d7bf8ea52592a94be5eeb4") {
		t.Fatal("Blocky release checksum is not pinned")
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
	firewall, err := os.ReadFile(filepath.Join(root, "firewall", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(firewall), "debian-13-genericcloud-amd64-daily.qcow2") || !strings.Contains(string(firewall), "sha512:") {
		t.Fatal("firewall image does not pin its Debian 13 VM input")
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
	for _, relative := range []string{"firewall/nocloud/meta-data", "firewall/nocloud/network-config", "firewall/nocloud/user-data"} {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "ssh-ed25519 AAAA") || strings.Contains(string(data), "age1") {
			t.Fatalf("%s contains operator or site secret material", relative)
		}
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
	for _, required := range []string{"scripts/build-images.sh", "images/base/debian.yaml", "cmd/qualify-artifact/main.go"} {
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

func TestTransferredEvidenceIsReboundToControllerArtifactBytes(t *testing.T) {
	root := t.TempDir()
	artifact, err := ArtifactFor("logging")
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(root, "generated", "artifacts", artifact.Name, artifact.Name+".tar.zst")
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
	evidence.ArtifactPath = "/home/labadmin/build/generated/artifacts/boetticher-logging/boetticher-logging.tar.zst"
	evidence = completeQualificationEvidence(evidence)
	qualified, err := QualifyEvidence(evidence, ScanSummary{})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(root, artifact.Name, qualified); err != nil {
		t.Fatal(err)
	}
	if err := RebindEvidencePaths(root); err != nil {
		t.Fatal(err)
	}
	resolved, _, err := ResolveArtifactEvidence(root, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ContentSHA256 != evidence.ContentSHA256 {
		t.Fatalf("rebound content checksum = %q, want %q", resolved.ContentSHA256, evidence.ContentSHA256)
	}
}
