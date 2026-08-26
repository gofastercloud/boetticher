package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/appliance"
	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/logging"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

func TestFreshDefaultTrialOrchestrationContract(t *testing.T) {
	base := model.NewDefaultSite("trial", "age1trial")
	if base.PhysicalNetwork.Mode != model.ModeVirtualOnly {
		t.Fatalf("default trial is not virtual-only: %q", base.PhysicalNetwork.Mode)
	}
	builder := artifacts.Builder()
	if builder.VMID != model.BuilderVMID || builder.Hostname != "lab-builder-01" || !builder.Temporary || builder.Network != "bootstrap-upstream-only" {
		t.Fatalf("default trial builder contract is incomplete: %#v", builder)
	}
	buildCloudInit := proxmox.RenderBuilderCloudInit()
	if !strings.Contains(buildCloudInit.UserData, "./scripts/build-images.sh images") || !strings.Contains(buildCloudInit.UserData, "./scripts/scan-images.sh scan-images") || strings.Contains(strings.ToLower(buildCloudInit.UserData), "age identity") {
		t.Fatal("temporary builder does not run the first-party build/qualification path with public inputs only")
	}
	site, _, err := modules.Compose(model.ConfigFromSite(base))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := proxmox.PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxmox.ResolveQualifiedArtifacts(t.TempDir(), plan, true); err == nil {
		t.Fatal("fresh trial unexpectedly accepted without builder qualification evidence")
	}

	evidenceRoot := t.TempDir()
	for index := range plan.Guests {
		guest := &plan.Guests[index]
		artifactPath := filepath.Join(evidenceRoot, guest.Artifact.Name+".artifact")
		if err := os.WriteFile(artifactPath, []byte(guest.Name+" qualified bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		evidence, err := artifacts.EvidenceForFile(artifactPath, guest.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		evidence.ArtifactPath = artifactPath
		evidence.PackageManifestSHA = strings.Repeat("a", 64)
		evidence.SBOMSHA256 = strings.Repeat("b", 64)
		evidence.TrivyReportSHA256 = strings.Repeat("c", 64)
		evidence, err = artifacts.QualifyEvidence(evidence, artifacts.ScanSummary{})
		if err != nil {
			t.Fatal(err)
		}
		if err := artifacts.WriteEvidence(evidenceRoot, guest.Artifact.Name, evidence); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := proxmox.ResolveQualifiedArtifacts(evidenceRoot, plan, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range resolved.Guests {
		if guest.Owner != "" && guest.Artifact.ContentSHA256 == "" {
			t.Fatalf("resolved module guest %s lost content evidence", guest.Name)
		}
	}
	if resolved.Guests[0].Name != "lab-fw-01" {
		t.Fatalf("trial plan did not begin with the firewall dependency: %s", resolved.Guests[0].Name)
	}
	loggingPlan, err := logging.PlanFromSite(site)
	if err != nil || loggingPlan.Collector != logging.CollectorName || !loggingPlan.MTLS {
		t.Fatalf("logging vertical slice is not present: %#v %v", loggingPlan, err)
	}
	for _, component := range site.PlatformComponents() {
		if component.Module != "" && !contains(component.Tags, "boetticher-module-"+component.Module) {
			t.Fatalf("module guest %s lacks canonical ownership tag", component.Name)
		}
	}
	var dnsGuest model.Component
	for _, component := range site.PlatformComponents() {
		if component.Name == "lab-dns-01" {
			dnsGuest = component
		}
	}
	var dnsDeclaration model.ModuleDeclaration
	for _, declaration := range site.Declarations {
		if declaration.Module == "dns" {
			dnsDeclaration = declaration
		}
	}
	runtimeConfig, err := appliance.RenderRuntimeConfig(site, dnsGuest, dnsDeclaration)
	if err != nil || !strings.Contains(string(runtimeConfig), "boetticher-dns-blocky") {
		t.Fatalf("default Blocky runtime contract missing: %v", err)
	}
	loggingConfig, err := logging.PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logging.CollectorConfiguration(loggingConfig), "SystemMaxUse=8G") || !strings.Contains(logging.CollectorServiceOverride(loggingConfig), "/var/log/journal/remote") {
		t.Fatal("logging collector does not have the executable bounded journal contract")
	}
	if _, err := proxmox.RenderFirewallCloudInitWithKey(plan.Guests[0], "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator"); err != nil {
		t.Fatalf("firewall first-boot SSH contract is not renderable: %v", err)
	}
	if dnsDeclaration.Artifact.Provider != string(model.DNSProviderBlocky) {
		t.Fatalf("default DNS provider is not Blocky: %#v", dnsDeclaration.Artifact)
	}
	externalConfig := model.ConfigFromSite(model.NewSite("trial-external", "age1trial", model.GatewayModeExternal))
	disabled := false
	externalConfig.Modules = map[string]model.ModuleConfig{"firewall": {Enabled: &disabled}}
	external, _, err := modules.Compose(externalConfig)
	if err != nil {
		t.Fatal(err)
	}
	externalPlan, err := proxmox.PlanFromSite(external)
	if err != nil {
		t.Fatal(err)
	}
	for _, guest := range externalPlan.Guests {
		if guest.VMID == model.ProxmoxVMID {
			t.Fatal("external gateway trial retained managed firewall")
		}
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
