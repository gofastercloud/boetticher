package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
)

func TestFirstProperReleaseVersionContract(t *testing.T) {
	if model.ReleaseVersion != "0.1.0" || model.PlatformVersion != "0.1.0" {
		t.Fatalf("platform release = %s/%s, want 0.1.0", model.ReleaseVersion, model.PlatformVersion)
	}
	if artifacts.BaseVersion != "0.1.0" {
		t.Fatalf("base artifact version = %s, want 0.1.0", artifacts.BaseVersion)
	}
	if artifacts.ModuleVersion != "1.0.0" {
		t.Fatalf("module artifact version = %s, want retained 1.0.0", artifacts.ModuleVersion)
	}
	if model.APIVersion != "boetticher/v3" || model.SchemaVersion != 3 || model.ArtifactABIVersion != "boetticher/artifact/v1" || model.BundleFormatVersion != "boetticher/release-bundle/v1" {
		t.Fatalf("renumber changed an independent compatibility identity")
	}
}

func TestReleaseWorkflowHasNonPublishingManualRehearsal(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		"tags: ['v0.1.*']",
		"workflow_dispatch:",
		"default: '0.1.0'",
		"RELEASE_VERSION_INPUT: ${{ inputs.release_version || github.ref_name }}",
		`^0\.1\.[0-9]+$`,
		"manual release rehearsal must run from main",
		"name: Upload non-publishing rehearsal outputs\n        if: github.event_name == 'workflow_dispatch'",
		"name: boetticher-rehearsal-${{ github.run_id }}-${{ github.run_attempt }}",
		"retention-days: 7",
		"name: Upload validated release outputs\n        if: github.event_name == 'push' && github.ref_type == 'tag'",
		"github.event_name == 'push' && github.ref_type == 'tag'",
		"environment: release",
		"(.artifacts | length == 13)",
		"(.companion_binary != null)",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("release workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{"tags: ['v0.5.*']", `^0\.5\.[0-9]+$`} {
		if strings.Contains(text, forbidden) {
			t.Errorf("release workflow retains pre-release trigger %q", forbidden)
		}
	}
}
