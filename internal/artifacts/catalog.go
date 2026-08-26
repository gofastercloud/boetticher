package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

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
}

// Evidence binds concrete bytes and qualification outputs to a deterministic
// artifact definition. Build timestamps and tool versions are evidence only;
// they never become desired-state inputs.
type Evidence struct {
	Artifact           model.Artifact `json:"artifact"`
	ArtifactPath       string         `json:"artifact_path,omitempty"`
	ContentSHA256      string         `json:"content_sha256"`
	SizeBytes          int64          `json:"size_bytes"`
	PackageManifestSHA string         `json:"package_manifest_sha256,omitempty"`
	SBOMSHA256         string         `json:"sbom_sha256,omitempty"`
	TrivyReportSHA256  string         `json:"trivy_report_sha256,omitempty"`
	DefinitionSHA256   string         `json:"definition_sha256"`
	Qualified          bool           `json:"qualified"`
}

// LoadEvidence reads the controller-side qualification record for one exact
// artifact. Evidence is generated state and is never part of the canonical
// desired model.
func LoadEvidence(root, name string) (Evidence, error) {
	if root == "" || name == "" {
		return Evidence{}, fmt.Errorf("artifact evidence requires root and name")
	}
	data, err := os.ReadFile(EvidencePath(root, name))
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
	if evidence.DefinitionSHA256 != requested.DefinitionSHA256 || evidence.Artifact != requested {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact evidence does not match requested definition for %s", requested.Name)
	}
	if evidence.ContentSHA256 == "" {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s has no content checksum", requested.Name)
	}
	if err := validateQualificationDigests(evidence); err != nil {
		return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s qualification evidence is incomplete: %w", requested.Name, err)
	}
	if evidence.ArtifactPath != "" {
		verified, err := EvidenceForFile(evidence.ArtifactPath, requested)
		if err != nil {
			return model.Artifact{}, Evidence{}, err
		}
		if verified.ContentSHA256 != evidence.ContentSHA256 {
			return model.Artifact{}, Evidence{}, fmt.Errorf("artifact %s content checksum does not match qualification evidence", requested.Name)
		}
	}
	resolved := requested
	resolved.ContentSHA256 = evidence.ContentSHA256
	return resolved, evidence, nil
}

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func validateQualificationDigests(evidence Evidence) error {
	for name, value := range map[string]string{
		"content_sha256":          evidence.ContentSHA256,
		"package_manifest_sha256": evidence.PackageManifestSHA,
		"sbom_sha256":             evidence.SBOMSHA256,
		"trivy_report_sha256":     evidence.TrivyReportSHA256,
	} {
		if !sha256Pattern.MatchString(value) {
			return fmt.Errorf("%s must be a SHA-256 digest", name)
		}
	}
	return nil
}

const (
	BaseName      = "boetticher-base"
	BaseVersion   = "0.3.1"
	Architecture  = "amd64"
	DebianRelease = "13"
	ModuleVersion = "1.0.0"
)

func Definitions() []Definition {
	return []Definition{
		{Name: "dns", Provider: "blocky", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
		{Name: "dns", Provider: "adguard", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
		{Name: "logging", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
		{Name: "monitoring", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
		{Name: "firewall", Version: ModuleVersion, Kind: "qemu", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
		{Name: "portal", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
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
	identity := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", definition.Base, definition.BaseVersion, definition.Name, definition.Provider, definition.Version, definition.Architecture, definition.Kind)
	definitionDigest := digest(identity)
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
		if definition.Architecture != Architecture || definition.Version == "" || definition.Kind == "" {
			return fmt.Errorf("artifact %s has incomplete identity", definition.Name)
		}
	}
	return nil
}

func EvidenceForFile(path string, artifact model.Artifact) (Evidence, error) {
	file, err := os.Open(path)
	if err != nil {
		return Evidence{}, fmt.Errorf("open artifact %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Evidence{}, fmt.Errorf("stat artifact %s: %w", path, err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return Evidence{}, fmt.Errorf("hash artifact %s: %w", path, err)
	}
	content := hex.EncodeToString(hash.Sum(nil))
	return Evidence{Artifact: artifact, ContentSHA256: content, SizeBytes: info.Size(), DefinitionSHA256: artifact.DefinitionSHA256, Qualified: true}, nil
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
