package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	buildbundle "github.com/gofastercloud/boetticher"
	"github.com/gofastercloud/boetticher/internal/model"
)

// Definition describes the checked-in build contract for an official
// appliance. The resulting artifact is still built and qualified outside the
// ordinary offline test path; the digest is deterministic until that artifact
// is published.
type Definition struct {
	Name         string
	Provider     string
	Version      string
	Kind         string
	Architecture string
	Base         string
	BaseVersion  string
	Inputs       []string
}

// Evidence binds concrete bytes and qualification outputs to a deterministic
// artifact definition. Build timestamps and tool versions are evidence only;
// they never become desired-state inputs.
type Evidence struct {
	Artifact                   model.Artifact    `json:"artifact"`
	ArtifactPath               string            `json:"artifact_path,omitempty"`
	ContentSHA256              string            `json:"content_sha256"`
	SizeBytes                  int64             `json:"size_bytes"`
	PackageManifestSHA         string            `json:"package_manifest_sha256,omitempty"`
	SBOMSHA256                 string            `json:"sbom_sha256,omitempty"`
	TrivyReportSHA256          string            `json:"trivy_report_sha256,omitempty"`
	BuilderProvenanceSHA256    string            `json:"builder_provenance_sha256,omitempty"`
	QualificationPolicyVersion string            `json:"qualification_policy_version,omitempty"`
	QualificationEvaluator     string            `json:"qualification_evaluator,omitempty"`
	ScanCompleted              bool              `json:"scan_completed"`
	DefinitionSHA256           string            `json:"definition_sha256"`
	Qualified                  bool              `json:"qualified"`
	Builder                    BuilderProvenance `json:"builder,omitempty"`
	qualifiedByEvaluator       bool
}

// BuilderProvenance records the non-deterministic environment that produced
// qualification evidence. It is evidence only and never enters the
// deterministic Site revision.
type BuilderProvenance struct {
	Platform          string `json:"platform"`
	InputImage        string `json:"input_image"`
	Kernel            string `json:"kernel"`
	Go                string `json:"go"`
	Trivy             string `json:"trivy"`
	MMDebstrap        string `json:"mmdebstrap"`
	Libguestfs        string `json:"libguestfs,omitempty"`
	QEMUImg           string `json:"qemu_img,omitempty"`
	Architecture      string `json:"architecture"`
	BoetticherVersion string `json:"boetticher_version"`
}

type ScanSummary struct {
	Completed       bool
	Secrets         int
	FixableCritical int
	UnfixedCritical int
	High            int
}

const QualificationPolicyVersion = "boetticher-trivy-v1"

const QualificationEvaluator = "boetticher-qualify-artifact"

// QualifyEvidence is the only operation allowed to mark artifact evidence
// qualified. The evaluator records the completed smoke/Trivy gate; optional
// manifests, SBOMs, and builder provenance remain useful release outputs.
func QualifyEvidence(evidence Evidence, scan ScanSummary) (Evidence, error) {
	if err := validateQualificationDigests(evidence); err != nil {
		return Evidence{}, fmt.Errorf("qualification evidence is incomplete: %w", err)
	}
	if !scan.Completed {
		return Evidence{}, fmt.Errorf("qualification failed: Trivy scan did not complete")
	}
	if scan.Secrets > 0 {
		return Evidence{}, fmt.Errorf("qualification failed: Trivy found %d secret finding(s)", scan.Secrets)
	}
	if scan.FixableCritical > 0 {
		return Evidence{}, fmt.Errorf("qualification failed: Trivy found %d fixable CRITICAL finding(s)", scan.FixableCritical)
	}
	evidence.QualificationPolicyVersion = QualificationPolicyVersion
	evidence.QualificationEvaluator = QualificationEvaluator
	evidence.ScanCompleted = true
	evidence.Qualified = true
	evidence.qualifiedByEvaluator = true
	return evidence, nil
}

// LoadEvidence reads the controller-side qualification record for one exact
// artifact. Evidence is generated state and is never part of the canonical
// desired model.
func LoadEvidence(root, name string) (Evidence, error) {
	if root == "" || name == "" {
		return Evidence{}, fmt.Errorf("artifact evidence requires root and name")
	}
	if err := validateEvidenceName(name); err != nil {
		return Evidence{}, err
	}
	path := EvidencePath(root, name)
	if err := validateEvidenceEntry(path); err != nil {
		return Evidence{}, fmt.Errorf("inspect artifact evidence %s: %w", name, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Evidence{}, fmt.Errorf("read artifact evidence %s: %w", name, err)
	}
	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return Evidence{}, fmt.Errorf("decode artifact evidence %s: %w", name, err)
	}
	return evidence, nil
}

// ResolveArtifactEvidence proves that a qualification record describes the
// requested definition and, when a local artifact path is recorded, that the
// path still contains the qualified bytes.
func ResolveArtifactEvidence(root string, requested model.Artifact) (model.Artifact, Evidence, error) {
	evidence, err := LoadEvidence(root, requested.Name)
	if err != nil {
		return model.Artifact{}, Evidence{}, err
	}
	if !evidence.Qualified {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s is not qualified", requested.Name)
	}
	if evidence.QualificationEvaluator != QualificationEvaluator {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s qualification evaluator is not authorized", requested.Name)
	}
	if evidence.DefinitionSHA256 != requested.DefinitionSHA256 || evidence.Artifact != requested {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact evidence does not match requested definition for %s", requested.Name)
	}
	if evidence.ContentSHA256 == "" {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s has no content checksum", requested.Name)
	}
	if evidence.ArtifactPath == "" {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s qualification evidence has no artifact path", requested.Name)
	}
	if err := validateQualificationDigests(evidence); err != nil {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s qualification evidence is incomplete: %w", requested.Name, err)
	}
	if err := verifyQualificationInputs(evidence); err != nil {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s qualification inputs are not bound to the recorded digests: %w", requested.Name, err)
	}
	verified, err := EvidenceForFile(evidence.ArtifactPath, requested)
	if err != nil {
		return model.Artifact{}, Evidence{}, err
	}
	if verified.ContentSHA256 != evidence.ContentSHA256 {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s content checksum does not match qualification evidence", requested.Name)
	}
	resolved := requested
	resolved.ContentSHA256 = evidence.ContentSHA256
	return resolved, evidence, nil
}

// verifyQualificationInputs checks any qualification outputs that were
// recorded beside the artifact. The content digest and completed Trivy gate
// are authoritative; manifests, SBOMs, and provenance are optional outputs.
func verifyQualificationInputs(evidence Evidence) error {
	if evidence.ArtifactPath == "" {
		return fmt.Errorf("artifact path is required")
	}
	directory := filepath.Dir(evidence.ArtifactPath)
	inputs := []struct {
		name     string
		filename string
		expected string
	}{
		{name: "package manifest", filename: "package-manifest.txt", expected: evidence.PackageManifestSHA},
		{name: "SBOM", filename: "sbom.json", expected: evidence.SBOMSHA256},
		{name: "Trivy report", filename: "trivy.json", expected: evidence.TrivyReportSHA256},
	}
	for _, input := range inputs {
		if input.expected == "" {
			continue
		}
		actual, err := QualificationInputSHA256(filepath.Join(directory, input.filename), input.name)
		if err != nil {
			return err
		}
		if actual != input.expected {
			return fmt.Errorf("%s checksum differs from qualification evidence", input.name)
		}
	}
	return nil
}

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func validateQualificationDigests(evidence Evidence) error {
	if !sha256Pattern.MatchString(evidence.ContentSHA256) {
		return fmt.Errorf("content_sha256 must be a SHA-256 digest")
	}
	for name, value := range map[string]string{
		"package_manifest_sha256": evidence.PackageManifestSHA,
		"sbom_sha256":             evidence.SBOMSHA256,
		"trivy_report_sha256":     evidence.TrivyReportSHA256,
	} {
		if value == "" {
			continue
		}
		if !sha256Pattern.MatchString(value) {
			return fmt.Errorf("%s must be a SHA-256 digest", name)
		}
	}
	if evidence.QualificationPolicyVersion != "" && evidence.QualificationPolicyVersion != QualificationPolicyVersion {
		return fmt.Errorf("unsupported qualification policy %q", evidence.QualificationPolicyVersion)
	}
	if evidence.Qualified && evidence.QualificationEvaluator != QualificationEvaluator {
		return fmt.Errorf("qualified evidence must be produced by %s", QualificationEvaluator)
	}
	if evidence.Qualified && evidence.QualificationPolicyVersion != QualificationPolicyVersion {
		return fmt.Errorf("qualified evidence must declare policy %s", QualificationPolicyVersion)
	}
	if evidence.Qualified && !evidence.ScanCompleted {
		return fmt.Errorf("qualified evidence must include a completed Trivy scan")
	}
	if evidence.Qualified && !sha256Pattern.MatchString(evidence.TrivyReportSHA256) {
		return fmt.Errorf("qualified evidence must include a Trivy report digest")
	}
	return nil
}

const (
	BaseName      = "boetticher-base"
	BaseVersion   = "0.3.22"
	Architecture  = "amd64"
	DebianRelease = "13"
	ModuleVersion = "1.0.0"
)

var commonDefinitionInputs = []string{
	"images/base",
	"cmd/artifact-identity",
	"scripts/build-images.sh",
	"scripts/smoke-appliance.sh",
}

func Definitions() []Definition {
	return []Definition{
		{Name: "base", Version: BaseVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion, Inputs: append([]string(nil), commonDefinitionInputs...)},
		{Name: "dns", Provider: "blocky", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion, Inputs: append(append([]string(nil), commonDefinitionInputs...), "images/dns", "internal/dns", "internal/model", "internal/modules", "cmd/render-blocky-config")},
		{Name: "dns", Provider: "adguard", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion, Inputs: append(append([]string(nil), commonDefinitionInputs...), "images/dns")},
		{Name: "logging", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion, Inputs: append(append([]string(nil), commonDefinitionInputs...), "images/logging")},
		{Name: "monitoring", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion, Inputs: append(append([]string(nil), commonDefinitionInputs...), "images/monitoring")},
		{Name: "firewall", Version: ModuleVersion, Kind: "qemu", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion, Inputs: append(append([]string(nil), commonDefinitionInputs...), "images/firewall", "scripts/smoke-firewall-image.sh")},
		{Name: "portal", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion, Inputs: append(append([]string(nil), commonDefinitionInputs...), "images/portal")},
	}
}

func Lookup(module string) (Definition, bool) {
	for _, definition := range Definitions() {
		if definition.Name == module {
			return definition, true
		}
	}
	return Definition{}, false
}

func ArtifactFor(module string, provider ...string) (model.Artifact, error) {
	selectedProvider := ""
	if len(provider) > 0 {
		selectedProvider = provider[0]
	}
	var definition Definition
	var ok bool
	for _, candidate := range Definitions() {
		if candidate.Name == module && candidate.Provider == selectedProvider {
			definition, ok = candidate, true
			break
		}
	}
	if !ok && selectedProvider == "" {
		definition, ok = Lookup(module)
	}
	if !ok {
		return model.Artifact{}, fmt.Errorf("no built-in artifact definition for module %q provider %q", module, selectedProvider)
	}
	definitionDigest, err := definitionSHA256(definition)
	if err != nil {
		return model.Artifact{}, fmt.Errorf("hash artifact definition %s: %w", definition.Name, err)
	}
	return model.Artifact{
		Name: "boetticher-" + module + func() string {
			if definition.Provider != "" {
				return "-" + definition.Provider
			}
			return ""
		}(),
		Version:          definition.Version,
		Provider:         definition.Provider,
		Architecture:     definition.Architecture,
		Kind:             definition.Kind,
		DefinitionSHA256: definitionDigest,
	}, nil
}

func ValidateDefinitions() error {
	for _, definition := range Definitions() {
		if definition.Base != BaseName || definition.BaseVersion != BaseVersion {
			return fmt.Errorf("artifact %s does not consume the pinned %s base", definition.Name, BaseName)
		}
		if definition.Architecture != Architecture || definition.Version == "" || definition.Kind == "" || len(definition.Inputs) == 0 {
			return fmt.Errorf("artifact %s has incomplete identity", definition.Name)
		}
		if _, err := definitionSHA256(definition); err != nil {
			return fmt.Errorf("artifact %s has unavailable build inputs: %w", definition.Name, err)
		}
	}
	return nil
}

// definitionSHA256 binds the desired artifact identity to the checked-in
// build definitions and pinned public inputs that produce it. It is a recipe
// identity, not a claim about the bytes emitted by a particular build.
func definitionSHA256(definition Definition) (string, error) {
	identity := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", definition.Base, definition.BaseVersion, definition.Name, definition.Provider, definition.Version, definition.Architecture, definition.Kind)
	hash := sha256.New()
	if _, err := io.WriteString(hash, identity+"\x00"); err != nil {
		return "", err
	}
	paths, err := definitionFiles(definition.Inputs)
	if err != nil {
		return "", err
	}
	for _, name := range paths {
		data, err := fs.ReadFile(buildbundle.FS, name)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		if _, err := io.WriteString(hash, name+"\x00"); err != nil {
			return "", err
		}
		if _, err := hash.Write(data); err != nil {
			return "", err
		}
		if _, err := hash.Write([]byte{0}); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func definitionFiles(inputs []string) ([]string, error) {
	files := make(map[string]struct{})
	for _, input := range inputs {
		info, err := fs.Stat(buildbundle.FS, input)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files[input] = struct{}{}
			continue
		}
		if err := fs.WalkDir(buildbundle.FS, input, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			files[name] = struct{}{}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	result := make([]string, 0, len(files))
	for name := range files {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func EvidenceForFile(path string, artifact model.Artifact) (Evidence, error) {
	file, info, err := openEvidenceFile(path, "artifact")
	if err != nil {
		return Evidence{}, fmt.Errorf("open artifact %s: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return Evidence{}, fmt.Errorf("hash artifact %s: %w", path, err)
	}
	content := hex.EncodeToString(hash.Sum(nil))
	return Evidence{Artifact: artifact, ContentSHA256: content, SizeBytes: info.Size(), DefinitionSHA256: artifact.DefinitionSHA256}, nil
}

// QualificationInputSHA256 hashes a generated qualification input only when it
// is a non-empty regular file. Empty or special files cannot provide evidence
// for a package manifest, SBOM, or scanner report.
func QualificationInputSHA256(path, name string) (string, error) {
	file, info, err := openEvidenceFile(path, name+" qualification input")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if info.Size() == 0 {
		return "", fmt.Errorf("%s qualification input must be a non-empty regular file", name)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s qualification input: %w", name, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func openEvidenceFile(path, description string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat %s: %w", description, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s must not be a symlink", description)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s must be a regular file", description)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", description, err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat opened %s: %w", description, err)
	}
	if !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s changed while opening", description)
	}
	return file, opened, nil
}

// ContentSHA256ForFile recalculates the checksum immediately before an
// artifact is handed to an infrastructure provider.
func ContentSHA256ForFile(path string) (string, error) {
	evidence, err := EvidenceForFile(path, model.Artifact{})
	if err != nil {
		return "", err
	}
	return evidence.ContentSHA256, nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
