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
	repoRoot := filepath.Join("..", "..")
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
	buildScript, err := os.ReadFile(filepath.Join(repoRoot, "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	buildText := string(buildScript)
	if strings.Contains(buildText, "BOETTICHER_IMAGE_BUILD_COMMAND") {
		t.Fatal("default trial still uses the arbitrary image-build hook")
	}
	if !strings.Contains(buildText, "export GOTOOLCHAIN=local") {
		t.Fatal("builder does not pin construction to its installed Debian Go toolchain")
	}
	if !strings.Contains(buildText, `if [ "$(id -u)" -ne 0 ]`) || !strings.Contains(buildText, "requires root in the supported Linux builder environment") {
		t.Fatal("real appliance construction does not fail closed when mount/build privileges are unavailable")
	}
	for _, required := range []string{"DefinitionSHA256", "ContentSHA256", "BuilderProvenanceSHA256", "qualification evaluator", "jq"} {
		if !strings.Contains(buildText+string(mustRead(t, filepath.Join(repoRoot, "internal", "artifacts", "catalog.go"))), required) {
			t.Fatalf("hosted qualification contract is missing %s", required)
		}
	}
	for _, artifact := range []string{"boetticher-base", "boetticher-firewall", "boetticher-dns-blocky", "boetticher-logging", "boetticher-monitoring", "boetticher-portal"} {
		if !strings.Contains(buildText, artifact) {
			t.Fatalf("default trial builder does not produce %s", artifact)
		}
	}
	bootstrapSource, err := os.ReadFile(filepath.Join(repoRoot, "internal", "cli", "bootstrap.go"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapText := string(bootstrapSource)
	for _, required := range []string{"EnsureBuilderVM", "RebindEvidencePaths", "DestroyBuilderVM", "createBuilderKnownHosts", "CheckBuilderCapacity", "RunStream", "ExtractBuildArchiveFile"} {
		if !strings.Contains(bootstrapText, required) {
			t.Fatalf("bootstrap does not complete the builder qualification lifecycle: %s", required)
		}
	}
	builderSource, err := os.ReadFile(filepath.Join(repoRoot, "internal", "proxmox", "plan.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"BuilderVMID", "DestroyBuilderVM", "WaitForGuestAbsent", "cleanupBuilderSnippets", "ResizeQEMUDisk"} {
		if !strings.Contains(string(builderSource), required) {
			t.Fatalf("temporary builder lifecycle is missing %s", required)
		}
	}
	deploySource, err := os.ReadFile(filepath.Join(repoRoot, "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	deployText := string(deploySource)
	firewallReady := strings.Index(deployText, "HOLD: managed gateway is not reachable before dependent appliances")
	dependentCreation := strings.Index(deployText, "deploy %s appliances")
	if firewallReady < 0 || dependentCreation < 0 || firewallReady > dependentCreation {
		t.Fatal("deploy does not gate dependent appliances on firewall SSH readiness")
	}
	dnsTasks, err := os.ReadFile(filepath.Join(repoRoot, "ansible", "roles", "dns", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dnsTasks), "blocky validate --config /etc/blocky/config.yml") || !strings.Contains(string(dnsTasks), "dns_plan.recursive_provider == 'blocky'") {
		t.Fatal("default DNS path does not validate and configure the qualified Blocky appliance")
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
		for filename, content := range map[string]string{"package-manifest.txt": "package: trial\n", "sbom.json": "{}\n", "trivy.json": "{\"Results\":[]}\n", "builder-provenance.json": "{\"platform\":\"debian-13-amd64\",\"input_image\":\"debian-13-genericcloud-amd64-20260327-2429\",\"kernel\":\"6.1.0\",\"go\":\"go version go1.26.5 linux/amd64\",\"trivy\":\"Version: 0.69.3\",\"mmdebstrap\":\"mmdebstrap 1.5.0\",\"architecture\":\"amd64\",\"boetticher_version\":\"0.3.2\"}\n"} {
			if err := os.WriteFile(filepath.Join(filepath.Dir(artifactPath), filename), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		evidence.PackageManifestSHA, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactPath), "package-manifest.txt"), "package manifest")
		evidence.SBOMSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactPath), "sbom.json"), "SBOM")
		evidence.TrivyReportSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactPath), "trivy.json"), "Trivy report")
		evidence.BuilderProvenanceSHA256, _ = artifacts.QualificationInputSHA256(filepath.Join(filepath.Dir(artifactPath), "builder-provenance.json"), "builder provenance")
		evidence.Builder = artifacts.BuilderProvenance{Platform: "debian-13-amd64", InputImage: "debian-13-genericcloud-amd64-20260327-2429", Kernel: "6.1.0", Go: "go version go1.26.5 linux/amd64", Trivy: "Version: 0.69.3", MMDebstrap: "mmdebstrap 1.5.0", Architecture: "amd64", BoetticherVersion: "0.3.2"}
		evidence, err = artifacts.QualifyEvidence(evidence, artifacts.ScanSummary{Completed: true})
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
		if component.Module != "" && !contains(component.Tags, model.ModuleOwnershipTag(component.Module)) {
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
	if !strings.Contains(logging.CollectorConfiguration(loggingConfig), "MaxUse=8G") || !strings.Contains(logging.CollectorServiceOverride(loggingConfig), "/var/log/journal/remote") {
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
	externalConfig.Modules.Firewall = &model.ToggleModuleConfig{Enabled: &disabled}
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

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
