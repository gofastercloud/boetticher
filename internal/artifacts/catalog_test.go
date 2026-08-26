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
	if err := os.WriteFile(artifactPath, []byte("corrupted appliance"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveArtifactEvidence(root, artifact); err == nil {
		t.Fatal("corrupt cached artifact was accepted; a fresh builder is required")
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

func TestQualificationRequiresBuilderProvenance(t *testing.T) {
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
	evidence.BuilderProvenanceSHA256 = ""
	if _, err := QualifyEvidence(evidence, ScanSummary{Completed: true}); err == nil || !strings.Contains(err.Error(), "builder provenance") {
		t.Fatalf("qualification accepted missing builder provenance: %v", err)
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
			MMDebstrap: "mmdebstrap 1.5.0", Architecture: "amd64", BoetticherVersion: "0.3.1",
		}
		return evidence
	}
	inputs := map[string]string{
		"package-manifest.txt":    "package: boetticher-test\n",
		"sbom.json":               `{"bomFormat":"CycloneDX","specVersion":"1.5"}` + "\n",
		"trivy.json":              `{"Results":[]}` + "\n",
		"builder-provenance.json": `{"platform":"debian-13-amd64","input_image":"debian-13-genericcloud-amd64-20260327-2429","kernel":"6.1.0","go":"go version go1.26.5 linux/amd64","trivy":"Version: 0.69.3","mmdebstrap":"mmdebstrap 1.5.0","architecture":"amd64","boetticher_version":"0.3.1"}` + "\n",
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
		MMDebstrap: "mmdebstrap 1.5.0", Architecture: "amd64", BoetticherVersion: "0.3.1",
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
			if candidate.Name == "dns" && candidate.Provider == "blocky" {
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
		"package_version: 1:7.0.30-1+debian13",
		"release_package_sha256: 4a926b8815cdefddc31558fe622676730a3987610f75d5af0d4024809d21dd43",
	} {
		if !strings.Contains(string(monitoring), required) {
			t.Fatalf("monitoring image definition is missing Zabbix qualification input %q", required)
		}
	}
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"zabbix-sql-scripts=$zabbix_package_version", "php-pgsql"} {
		if !strings.Contains(string(buildScript), required) {
			t.Fatalf("monitoring build is missing runtime package %q", required)
		}
	}
	firewall, err := os.ReadFile(filepath.Join(root, "firewall", "image.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(firewall), "debian-13-genericcloud-amd64-20260327-2429.qcow2") || !strings.Contains(string(firewall), "sha512:") || strings.Contains(string(firewall), "/daily/latest/") {
		t.Fatal("firewall image does not pin its Debian 13 VM input")
	}
}

func TestBaseDefinitionPinsTheDebianSnapshotInput(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "images", "base", "debian.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"mirror: https://snapshot.debian.org/archive/debian/20260327T000000Z/",
		"snapshot: 20260327T000000Z",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("base definition is missing pinned Debian source %q", required)
		}
	}
	buildScript, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buildScript), "mirror=https://snapshot.debian.org/archive/debian/20260327T000000Z/") || !strings.Contains(string(buildScript), "--aptopt=Acquire::Check-Valid-Until=false") {
		t.Fatal("base builder does not use the pinned Debian snapshot")
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
	for _, directory := range []string{"--mkdir /etc/boetticher", "--mkdir /usr/lib/boetticher", "--mkdir /var/lib/boetticher/identity/ssh", "--mkdir /tmp/boetticher-ansible"} {
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
	sudoers, err := os.ReadFile(filepath.Join(root, "base", "runtime", "boetticher.sudoers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"/tmp/boetticher-ansible", "/usr/bin/python3 /tmp/boetticher-ansible/ansible-tmp-*/*", "/usr/bin/systemd-creds *", "/usr/bin/sqlite3 *", "/usr/bin/psql *"} {
		if !strings.Contains(string(sudoers), required) {
			t.Fatalf("appliance sudo policy does not constrain runtime command %q", required)
		}
	}
	if strings.Contains(buildText+string(sudoers), "NOPASSWD:ALL") {
		t.Fatal("appliance sudo policy grants an unrestricted root command")
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
	if !strings.Contains(string(buildScript), `rm -f "$rootfs"/etc/ssh/ssh_host_*`) {
		t.Fatal("base build does not remove generated SSH host keys before packaging")
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
	for _, required := range []string{"buildbundle.go", "scripts/build-images.sh", "images/base/debian.yaml", "cmd/qualify-artifact/main.go"} {
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
	for _, required := range []string{"buildbundle.go", "scripts/build-images.sh", "images/base/debian.yaml", "cmd/qualify-artifact/main.go"} {
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
	for _, relative := range []string{"cmd/render-blocky-config/main.go", "internal/dns/recursive.go", "internal/dns/dns.go", "internal/modules/compose.go"} {
		if !entries[relative] {
			t.Fatalf("transferred builder source is missing %s", relative)
		}
	}
}

func TestTransferredEvidenceIsReboundToControllerArtifactBytes(t *testing.T) {
	root := t.TempDir()
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
