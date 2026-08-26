package artifacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltInArtifactsSharePinnedBase(t *testing.T) {
	if err := ValidateDefinitions(); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"dns", "monitoring", "firewall"} {
		artifact, err := ArtifactFor(module)
		if err != nil {
			t.Fatal(err)
		}
		if artifact.SHA256 == "" || artifact.DefinitionSHA256 == "" {
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
	paths := []string{"base/debian.yaml", "dns/image.yaml", "monitoring/image.yaml", "firewall/image.yaml"}
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
}
