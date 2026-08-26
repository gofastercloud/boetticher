package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
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
	if evidence.ContentSHA256 != hex.EncodeToString(hash[:]) || evidence.ContentSHA256 == artifact.DefinitionSHA256 || !evidence.Qualified {
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
}
