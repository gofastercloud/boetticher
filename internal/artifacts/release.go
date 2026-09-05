package artifacts

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	ReleaseBundleFormatVersion = "boetticher/release-bundle/v1"
	ArtifactABIVersion         = "boetticher/artifact/v1"
	ReleaseManifestName        = "manifest.json"
	ReleaseSignatureName       = "manifest.sig"
	MaxReleaseManifestBytes    = 1 << 20
	MaxReleaseFileBytes        = int64(8 << 30)
	MaxReleaseBundleBytes      = int64(32 << 30)
)

// ReleaseManifest is the compatibility and integrity contract for a
// prepared release. It contains no workstation paths, timestamps, or secret
// values; the signature covers the exact manifest.json bytes.
type ReleaseManifest struct {
	FormatVersion              string            `json:"format_version"`
	ReleaseVersion             string            `json:"release_version"`
	SourceCommit               string            `json:"source_commit"`
	BuildWorkflow              string            `json:"build_workflow"`
	SiteAPIVersion             string            `json:"site_api_version"`
	SchemaVersion              int               `json:"schema_version"`
	ArtifactABIVersion         string            `json:"artifact_abi_version"`
	Architecture               string            `json:"architecture"`
	ControllerMin              string            `json:"controller_min_version"`
	ControllerMax              string            `json:"controller_max_version"`
	ControllerSHA256           string            `json:"controller_sha256,omitempty"`
	ControllerSizeBytes        int64             `json:"controller_size_bytes,omitempty"`
	QualificationPolicyVersion string            `json:"qualification_policy_version,omitempty"`
	Artifacts                  []ReleaseArtifact `json:"artifacts"`
	Files                      []ReleaseFile     `json:"files"`
	CompanionBinary            *ReleaseFile      `json:"companion_binary,omitempty"`
	CompanionStatusBinary      *ReleaseFile      `json:"companion_status_binary,omitempty"`
}

// ReleaseBuildMetadata is supplied by the Linux release workflow. It keeps
// release provenance and controller compatibility explicit instead of
// overloading the site platform-version field.
type ReleaseBuildMetadata struct {
	ReleaseVersion             string
	SourceCommit               string
	BuildWorkflow              string
	ControllerMin              string
	ControllerMax              string
	ControllerSHA256           string
	ControllerSizeBytes        int64
	QualificationPolicyVersion string
}

type ReleaseArtifact struct {
	Artifact     model.Artifact `json:"artifact"`
	ArtifactPath string         `json:"artifact_path"`
	EvidencePath string         `json:"evidence_path,omitempty"`
}

type ReleaseFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Kind      string `json:"kind"`
	Artifact  string `json:"artifact"`
}

// ReleaseInput is the source-side material assembled by the maintainer build.
// Qualification evidence is optional release transparency; artifact bytes and
// their signed manifest identity are the operator trust boundary.
type ReleaseInput struct {
	Artifact           model.Artifact
	ArtifactPath       string
	EvidencePath       string
	QualificationFiles map[string]string
}

const (
	CompanionStreamDeckPath = "companion/streamdeck/boetticher-streamdeck-linux-arm64"
	CompanionStreamDeckKind = "companion"
	CompanionStatusPath     = "companion/status/boetticher-companion-linux-arm64"
	CompanionStatusKind     = "companion-status"
)

type ManifestSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type TrustedReleaseKey struct {
	ID        string
	PublicKey ed25519.PublicKey
}

// EmbeddedTrustedReleaseKeys is the small compiled trust set used by a
// release binary. Release builds replace the placeholder with the approved
// public keys; multiple entries permit overlap during key rotation.
var EmbeddedTrustedReleaseKeys = []TrustedReleaseKey{}

// EmbeddedTrustedReleaseKeyData is populated by the release build with a
// comma-separated set of id=base64-public-key entries. Keeping the value
// injectable permits key overlap during rotation without making the trust
// root a private or single-use runtime secret.
var EmbeddedTrustedReleaseKeyData string

func TrustedReleaseKeys() ([]TrustedReleaseKey, error) {
	keys := append([]TrustedReleaseKey(nil), EmbeddedTrustedReleaseKeys...)
	if strings.TrimSpace(EmbeddedTrustedReleaseKeyData) == "" {
		return keys, nil
	}
	for _, encoded := range strings.Split(EmbeddedTrustedReleaseKeyData, ",") {
		parts := strings.SplitN(encoded, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New("embedded release key entry must be id=base64-public-key")
		}
		if err := validateKeyID(parts[0]); err != nil {
			return nil, err
		}
		data, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || len(data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("embedded release key %s is invalid", parts[0])
		}
		keys = append(keys, TrustedReleaseKey{ID: parts[0], PublicKey: ed25519.PublicKey(data)})
	}
	return keys, nil
}

// BuildReleaseBundle assembles and signs a release bundle from already
// qualified artifacts. It does not build software, contact a host, or accept
// a site directory. The output is gzip-compressed tar for broad offline
// portability; every member is listed and hashed in the signed manifest.
func BuildReleaseBundle(output string, platformVersion, siteAPIVersion string, schemaVersion int, privateKey ed25519.PrivateKey, keyID string, inputs []ReleaseInput) (ReleaseManifest, error) {
	return BuildReleaseBundleWithMetadata(output, ReleaseBuildMetadata{
		ReleaseVersion: platformVersion, SourceCommit: "local-build", BuildWorkflow: "local",
		ControllerMin: platformVersion, ControllerMax: platformVersion,
	}, siteAPIVersion, schemaVersion, privateKey, keyID, inputs)
}

func BuildReleaseBundleWithMetadata(output string, metadata ReleaseBuildMetadata, siteAPIVersion string, schemaVersion int, privateKey ed25519.PrivateKey, keyID string, inputs []ReleaseInput) (ReleaseManifest, error) {
	return BuildReleaseBundleWithMetadataAndCompanion(output, metadata, siteAPIVersion, schemaVersion, privateKey, keyID, inputs, "")
}

// BuildReleaseBundleWithMetadataAndCompanion adds the release-built external
// companion binary to the signed bundle. The companion is deliberately not an
// appliance artifact: it is a capability installed on a physical Pi.
func BuildReleaseBundleWithMetadataAndCompanion(output string, metadata ReleaseBuildMetadata, siteAPIVersion string, schemaVersion int, privateKey ed25519.PrivateKey, keyID string, inputs []ReleaseInput, companionBinaryPath string, statusBinaryPaths ...string) (ReleaseManifest, error) {
	if len(statusBinaryPaths) > 1 {
		return ReleaseManifest{}, errors.New("only one Companion status binary is supported")
	}
	if output == "" || metadata.ReleaseVersion == "" || metadata.SourceCommit == "" || metadata.BuildWorkflow == "" || metadata.ControllerMin == "" || metadata.ControllerMax == "" || siteAPIVersion == "" || schemaVersion <= 0 {
		return ReleaseManifest{}, errors.New("release bundle output and compatibility versions are required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return ReleaseManifest{}, errors.New("release bundle signing key is invalid")
	}
	if err := validateKeyID(keyID); err != nil {
		return ReleaseManifest{}, err
	}
	if len(inputs) == 0 {
		return ReleaseManifest{}, errors.New("release bundle requires at least one qualified artifact")
	}
	if err := validateOutputPath(output); err != nil {
		return ReleaseManifest{}, err
	}
	if metadata.BuildWorkflow != "local" && (metadata.ControllerSHA256 == "" || metadata.ControllerSizeBytes <= 0) {
		return ReleaseManifest{}, errors.New("non-local release bundle requires a controller digest and size binding")
	}

	manifest := ReleaseManifest{
		FormatVersion: ReleaseBundleFormatVersion, ReleaseVersion: metadata.ReleaseVersion,
		SourceCommit: metadata.SourceCommit, BuildWorkflow: metadata.BuildWorkflow,
		SiteAPIVersion: siteAPIVersion, SchemaVersion: schemaVersion,
		ArtifactABIVersion: ArtifactABIVersion, Architecture: Architecture,
		ControllerMin: metadata.ControllerMin, ControllerMax: metadata.ControllerMax,
		ControllerSHA256: metadata.ControllerSHA256, ControllerSizeBytes: metadata.ControllerSizeBytes,
		QualificationPolicyVersion: metadata.QualificationPolicyVersion,
	}
	members := make([]releaseMember, 0, len(inputs)*2)
	var totalMemberBytes int64
	seenArtifacts := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if err := validateReleaseInput(input); err != nil {
			return ReleaseManifest{}, err
		}
		if _, exists := seenArtifacts[input.Artifact.Name]; exists {
			return ReleaseManifest{}, fmt.Errorf("release bundle repeats artifact %q", input.Artifact.Name)
		}
		seenArtifacts[input.Artifact.Name] = struct{}{}
		artifactPath := filepath.ToSlash(filepath.Join("artifacts", input.Artifact.Name, filepath.Base(input.ArtifactPath)))
		artifactMember, err := newReleaseMember(artifactPath, input.ArtifactPath, "artifact", input.Artifact.Name)
		if err != nil {
			return ReleaseManifest{}, fmt.Errorf("read artifact %s: %w", input.Artifact.Name, err)
		}
		if input.Artifact.ContentSHA256 != artifactMember.SHA256 {
			return ReleaseManifest{}, fmt.Errorf("artifact %s content checksum does not match its qualified identity", input.Artifact.Name)
		}
		totalMemberBytes += artifactMember.Size
		if totalMemberBytes > MaxReleaseBundleBytes {
			return ReleaseManifest{}, errors.New("release bundle exceeds the permitted uncompressed size")
		}
		members = append(members, artifactMember)
		artifactPath = artifactMember.Path
		releaseArtifact := ReleaseArtifact{Artifact: input.Artifact, ArtifactPath: artifactPath}
		if input.EvidencePath != "" {
			evidenceBytes, err := pathguard.ReadFileLimited(input.EvidencePath, maxEvidenceJSONBytes)
			if err != nil {
				return ReleaseManifest{}, fmt.Errorf("read qualification evidence %s: %w", input.Artifact.Name, err)
			}
			var evidence Evidence
			if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
				return ReleaseManifest{}, fmt.Errorf("decode qualification evidence %s: %w", input.Artifact.Name, err)
			}
			if !evidence.Qualified || !artifactIdentityMatches(evidence.Artifact, input.Artifact) || evidence.ContentSHA256 != input.Artifact.ContentSHA256 {
				return ReleaseManifest{}, fmt.Errorf("qualification evidence for %s is not bound to the requested artifact", input.Artifact.Name)
			}
			evidence.ArtifactPath = artifactPath
			rewrittenEvidence, err := json.MarshalIndent(evidence, "", "  ")
			if err != nil {
				return ReleaseManifest{}, fmt.Errorf("encode qualification evidence %s: %w", input.Artifact.Name, err)
			}
			evidencePath := filepath.ToSlash(filepath.Join("evidence", input.Artifact.Name+".json"))
			evidenceMember, err := newInlineReleaseMember(evidencePath, append(rewrittenEvidence, '\n'), "evidence", input.Artifact.Name)
			if err != nil {
				return ReleaseManifest{}, fmt.Errorf("prepare qualification evidence %s: %w", input.Artifact.Name, err)
			}
			totalMemberBytes += evidenceMember.Size
			if totalMemberBytes > MaxReleaseBundleBytes {
				return ReleaseManifest{}, errors.New("release bundle exceeds the permitted uncompressed size")
			}
			members = append(members, evidenceMember)
			releaseArtifact.EvidencePath = evidencePath
		}
		manifest.Artifacts = append(manifest.Artifacts, releaseArtifact)
		for name, source := range input.QualificationFiles {
			if err := validateBundlePath(name); err != nil {
				return ReleaseManifest{}, err
			}
			name = filepath.ToSlash(name)
			if name != filepath.ToSlash(filepath.Join("evidence", input.Artifact.Name, filepath.Base(name))) {
				return ReleaseManifest{}, fmt.Errorf("qualification file %q must be beneath evidence/%s/", name, input.Artifact.Name)
			}
			if releaseMemberExists(members, name) {
				continue
			}
			member, memberErr := newReleaseMember(name, source, "evidence", input.Artifact.Name)
			if memberErr != nil {
				return ReleaseManifest{}, fmt.Errorf("read qualification file %s: %w", name, memberErr)
			}
			if releaseMemberExists(members, name) {
				return ReleaseManifest{}, fmt.Errorf("release bundle repeats file %q", name)
			}
			totalMemberBytes += member.Size
			if totalMemberBytes > MaxReleaseBundleBytes {
				return ReleaseManifest{}, errors.New("release bundle exceeds the permitted uncompressed size")
			}
			members = append(members, member)
		}
	}
	if strings.TrimSpace(companionBinaryPath) != "" {
		companionMember, err := newReleaseMember(CompanionStreamDeckPath, companionBinaryPath, CompanionStreamDeckKind, "")
		if err != nil {
			return ReleaseManifest{}, fmt.Errorf("read companion StreamDeck binary: %w", err)
		}
		if releaseMemberExists(members, companionMember.Path) {
			return ReleaseManifest{}, fmt.Errorf("release bundle repeats file %q", companionMember.Path)
		}
		if totalMemberBytes > MaxReleaseBundleBytes-companionMember.Size {
			return ReleaseManifest{}, errors.New("release bundle exceeds the permitted uncompressed size")
		}
		totalMemberBytes += companionMember.Size
		members = append(members, companionMember)
		manifest.CompanionBinary = &ReleaseFile{
			Path: companionMember.Path, SHA256: companionMember.SHA256, SizeBytes: companionMember.Size,
			Kind: companionMember.Kind,
		}
	}
	if len(statusBinaryPaths) == 1 && statusBinaryPaths[0] != "" {
		member, err := newReleaseMember(CompanionStatusPath, statusBinaryPaths[0], CompanionStatusKind, "")
		if err != nil {
			return ReleaseManifest{}, err
		}
		if totalMemberBytes > MaxReleaseBundleBytes-member.Size {
			return ReleaseManifest{}, errors.New("release bundle exceeds the permitted uncompressed size")
		}
		totalMemberBytes += member.Size
		members = append(members, member)
		manifest.CompanionStatusBinary = &ReleaseFile{Path: member.Path, SHA256: member.SHA256, SizeBytes: member.Size, Kind: member.Kind}
	}
	for _, member := range members {
		manifest.Files = append(manifest.Files, ReleaseFile{Path: member.Path, SHA256: member.SHA256, SizeBytes: member.Size, Kind: member.Kind, Artifact: member.Artifact})
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].Artifact.Name < manifest.Artifacts[j].Artifact.Name })
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	if err := validateReleaseManifest(manifest); err != nil {
		return ReleaseManifest{}, err
	}
	manifestBytes, err := canonicalManifest(manifest)
	if err != nil {
		return ReleaseManifest{}, err
	}
	signature := ManifestSignature{Algorithm: "ed25519", KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestBytes))}
	signatureBytes, err := json.MarshalIndent(signature, "", "  ")
	if err != nil {
		return ReleaseManifest{}, err
	}
	if err := writeReleaseArchive(output, manifestBytes, append(signatureBytes, '\n'), members); err != nil {
		return ReleaseManifest{}, err
	}
	return manifest, nil
}

// ImportReleaseBundle verifies the signed compatibility contract before
// extracting any artifact member. It stages all files in a fresh directory,
// checks every declared size and digest, and atomically installs the complete
// tree only after verification succeeds.
func ImportReleaseBundle(bundlePath, destination string, trusted []TrustedReleaseKey, platformVersion, siteAPIVersion string, schemaVersion int) (ReleaseManifest, error) {
	if bundlePath == "" || destination == "" {
		return ReleaseManifest{}, errors.New("release bundle and destination are required")
	}
	if len(trusted) == 0 {
		return ReleaseManifest{}, errors.New("no trusted release signing keys are configured")
	}
	if err := validateSourcePath(bundlePath); err != nil {
		return ReleaseManifest{}, err
	}
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return ReleaseManifest{}, errors.New("release bundle destination must not be a symlink")
		}
		return ReleaseManifest{}, fmt.Errorf("release bundle destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ReleaseManifest{}, err
	}

	file, err := os.Open(bundlePath)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("open release bundle: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return ReleaseManifest{}, errors.New("release bundle must be a non-empty regular file")
	}
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("open release bundle compression: %w", err)
	}
	gzipClosed := false
	defer func() {
		if !gzipClosed {
			_ = gzipReader.Close()
		}
	}()
	tarReader := tar.NewReader(gzipReader)
	manifestHeader, err := tarReader.Next()
	if err != nil || manifestHeader.Name != ReleaseManifestName || manifestHeader.Typeflag != tar.TypeReg {
		return ReleaseManifest{}, errors.New("release bundle must begin with manifest.json")
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(tarReader, MaxReleaseManifestBytes+1))
	if err != nil || int64(len(manifestBytes)) > MaxReleaseManifestBytes {
		return ReleaseManifest{}, errors.New("release manifest is invalid or too large")
	}
	signatureHeader, err := tarReader.Next()
	if err != nil || signatureHeader.Name != ReleaseSignatureName || signatureHeader.Typeflag != tar.TypeReg {
		return ReleaseManifest{}, errors.New("release bundle must contain manifest.sig after manifest.json")
	}
	signatureBytes, err := io.ReadAll(io.LimitReader(tarReader, MaxReleaseManifestBytes+1))
	if err != nil || int64(len(signatureBytes)) > MaxReleaseManifestBytes {
		return ReleaseManifest{}, errors.New("release signature is invalid or too large")
	}
	var signature ManifestSignature
	if err := json.Unmarshal(signatureBytes, &signature); err != nil {
		return ReleaseManifest{}, fmt.Errorf("decode release signature: %w", err)
	}
	if err := verifyManifest(manifestBytes, signature, trusted); err != nil {
		return ReleaseManifest{}, err
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ReleaseManifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := validateReleaseManifest(manifest); err != nil {
		return ReleaseManifest{}, err
	}
	if manifest.ReleaseVersion == "" || manifest.ReleaseVersion != platformVersion || manifest.SiteAPIVersion != siteAPIVersion || manifest.SchemaVersion != schemaVersion || manifest.Architecture != Architecture {
		return ReleaseManifest{}, errors.New("release bundle compatibility does not match this controller")
	}
	if err := validateExecutingControllerBinding(manifest); err != nil {
		return ReleaseManifest{}, err
	}

	parent := filepath.Dir(destination)
	if err := pathguard.MkdirAll(parent, 0700); err != nil {
		return ReleaseManifest{}, fmt.Errorf("prepare release destination: %w", err)
	}
	stage, err := pathguard.MkdirTemp(parent, ".release-import-", 0700)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("create release staging directory: %w", err)
	}
	defer pathguard.RemoveAll(stage)
	if err := pathguard.WriteFile(filepath.Join(stage, ReleaseManifestName), manifestBytes, 0600); err != nil {
		return ReleaseManifest{}, fmt.Errorf("stage release manifest: %w", err)
	}
	if err := pathguard.WriteFile(filepath.Join(stage, ReleaseSignatureName), signatureBytes, 0600); err != nil {
		return ReleaseManifest{}, fmt.Errorf("stage release signature: %w", err)
	}
	expected := make(map[string]ReleaseFile, len(manifest.Files))
	for _, member := range manifest.Files {
		expected[member.Path] = member
	}
	seen := make(map[string]struct{}, len(expected))
	var totalMemberBytes int64
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return ReleaseManifest{}, fmt.Errorf("read release member: %w", nextErr)
		}
		if header.Typeflag != tar.TypeReg {
			return ReleaseManifest{}, fmt.Errorf("release member %q is not a regular file", header.Name)
		}
		member, ok := expected[header.Name]
		if !ok {
			return ReleaseManifest{}, fmt.Errorf("release contains undeclared member %q", header.Name)
		}
		if _, exists := seen[header.Name]; exists {
			return ReleaseManifest{}, fmt.Errorf("release repeats member %q", header.Name)
		}
		if header.Size != member.SizeBytes || header.Size < 0 || header.Size > MaxReleaseFileBytes {
			return ReleaseManifest{}, fmt.Errorf("release member %q has unexpected size", header.Name)
		}
		if totalMemberBytes > MaxReleaseBundleBytes-header.Size {
			return ReleaseManifest{}, errors.New("release exceeds the permitted uncompressed size")
		}
		totalMemberBytes += header.Size
		if err := validateBundlePath(header.Name); err != nil {
			return ReleaseManifest{}, err
		}
		target := filepath.Join(stage, filepath.FromSlash(header.Name))
		if err := pathguard.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return ReleaseManifest{}, err
		}
		if _, err := pathguard.WriteFileFrom(target, &exactReleaseReader{reader: tarReader, remaining: header.Size}, 0600, MaxReleaseFileBytes); err != nil {
			return ReleaseManifest{}, fmt.Errorf("stage release member %q: %w", header.Name, err)
		}
		seen[header.Name] = struct{}{}
	}
	if len(seen) != len(expected) {
		return ReleaseManifest{}, errors.New("release is missing one or more declared files")
	}
	for path, member := range expected {
		data, err := pathguard.ReadFile(filepath.Join(stage, filepath.FromSlash(path)))
		if err != nil {
			return ReleaseManifest{}, fmt.Errorf("read staged release member %q: %w", path, err)
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != member.SizeBytes || hex.EncodeToString(sum[:]) != member.SHA256 {
			return ReleaseManifest{}, fmt.Errorf("release member %q failed digest verification", path)
		}
	}
	if err := gzipReader.Close(); err != nil {
		return ReleaseManifest{}, fmt.Errorf("verify release compression: %w", err)
	}
	gzipClosed = true
	if err := pathguard.Rename(stage, destination); err != nil {
		return ReleaseManifest{}, fmt.Errorf("install release bundle: %w", err)
	}
	return manifest, nil
}

// InspectReleaseBundle reads and validates only the unsigned manifest. It is
// intentionally suitable for diagnostics; installation still requires
// ImportReleaseBundle, which verifies the signature before extraction.
func InspectReleaseBundle(bundlePath string) (ReleaseManifest, error) {
	if err := validateSourcePath(bundlePath); err != nil {
		return ReleaseManifest{}, err
	}
	file, err := os.Open(bundlePath)
	if err != nil {
		return ReleaseManifest{}, err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return ReleaseManifest{}, err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	header, err := tarReader.Next()
	if err != nil || header.Name != ReleaseManifestName || header.Typeflag != tar.TypeReg {
		return ReleaseManifest{}, errors.New("release bundle must begin with manifest.json")
	}
	data, err := io.ReadAll(io.LimitReader(tarReader, MaxReleaseManifestBytes+1))
	if err != nil || int64(len(data)) > MaxReleaseManifestBytes {
		return ReleaseManifest{}, errors.New("release manifest is invalid or too large")
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ReleaseManifest{}, err
	}
	if err := validateReleaseManifest(manifest); err != nil {
		return ReleaseManifest{}, err
	}
	return manifest, nil
}

func canonicalManifest(manifest ReleaseManifest) ([]byte, error) {
	return json.Marshal(manifest)
}

func verifyManifest(manifestBytes []byte, signature ManifestSignature, trusted []TrustedReleaseKey) error {
	if signature.Algorithm != "ed25519" || signature.KeyID == "" {
		return errors.New("release signature algorithm or key id is invalid")
	}
	raw, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("release signature encoding is invalid")
	}
	for _, key := range trusted {
		if key.ID == signature.KeyID && len(key.PublicKey) == ed25519.PublicKeySize && ed25519.Verify(key.PublicKey, manifestBytes, raw) {
			return nil
		}
	}
	return fmt.Errorf("release signature was not produced by a trusted key")
}

func validateReleaseManifest(manifest ReleaseManifest) error {
	if manifest.FormatVersion != ReleaseBundleFormatVersion || manifest.ReleaseVersion == "" || manifest.SourceCommit == "" || manifest.BuildWorkflow == "" || manifest.SiteAPIVersion == "" || manifest.SchemaVersion <= 0 || manifest.ArtifactABIVersion != ArtifactABIVersion || manifest.Architecture != Architecture || manifest.ControllerMin == "" || manifest.ControllerMax == "" {
		return errors.New("release manifest has incomplete or unsupported compatibility fields")
	}
	if (manifest.ControllerSHA256 == "") != (manifest.ControllerSizeBytes == 0) || (manifest.ControllerSHA256 != "" && (!isSHA256(manifest.ControllerSHA256) || manifest.ControllerSizeBytes < 0 || manifest.ControllerSizeBytes > MaxReleaseFileBytes)) {
		return errors.New("release controller binding is incomplete or invalid")
	}
	if manifest.BuildWorkflow != "local" && (manifest.ControllerSHA256 == "" || manifest.ControllerSizeBytes <= 0) {
		return errors.New("non-local release manifest is missing its controller binding")
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Files) == 0 {
		return errors.New("release manifest has no artifacts or files")
	}
	files := make(map[string]ReleaseFile, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := validateBundlePath(file.Path); err != nil {
			return err
		}
		if file.SHA256 == "" || !isSHA256(file.SHA256) || file.SizeBytes < 0 || file.SizeBytes > MaxReleaseFileBytes || (file.Kind != "artifact" && file.Kind != "evidence" && file.Kind != CompanionStreamDeckKind && file.Kind != CompanionStatusKind) {
			return fmt.Errorf("release member %q has invalid metadata", file.Path)
		}
		if _, exists := files[file.Path]; exists {
			return fmt.Errorf("release manifest repeats file %q", file.Path)
		}
		if file.Kind == CompanionStreamDeckKind {
			if manifest.CompanionBinary == nil || *manifest.CompanionBinary != file || file.Path != CompanionStreamDeckPath || file.Artifact != "" {
				return fmt.Errorf("release companion member %q is not bound to the declared companion binary", file.Path)
			}
		} else if file.Kind == CompanionStatusKind {
			if manifest.CompanionStatusBinary == nil || *manifest.CompanionStatusBinary != file || file.Path != CompanionStatusPath || file.Artifact != "" {
				return fmt.Errorf("release Companion status member %q has invalid binding", file.Path)
			}
		} else {
			artifact, err := releaseFileArtifact(file.Path, file.Kind)
			if err != nil {
				return err
			}
			if file.Artifact != artifact {
				return fmt.Errorf("release member %q is not bound to artifact %q", file.Path, file.Artifact)
			}
		}
		files[file.Path] = file
	}
	if manifest.CompanionBinary != nil {
		companion := *manifest.CompanionBinary
		if companion.Kind != CompanionStreamDeckKind || companion.Path != CompanionStreamDeckPath || companion.Artifact != "" || companion.SHA256 == "" || !isSHA256(companion.SHA256) || companion.SizeBytes < 0 || companion.SizeBytes > MaxReleaseFileBytes {
			return errors.New("release companion binary metadata is invalid")
		}
		if declared, ok := files[companion.Path]; !ok || declared != companion {
			return errors.New("release companion binary is missing its declared member")
		}
	}
	if manifest.CompanionStatusBinary != nil {
		file := *manifest.CompanionStatusBinary
		if file.Path != CompanionStatusPath || file.Kind != CompanionStatusKind || file.Artifact != "" || files[file.Path] != file {
			return errors.New("release Companion status binary is missing its declared member")
		}
	}
	seenArtifacts := map[string]struct{}{}
	for _, artifact := range manifest.Artifacts {
		if artifact.Artifact.Name == "" || artifact.Artifact.ContentSHA256 == "" || !isSHA256(artifact.Artifact.ContentSHA256) || artifact.ArtifactPath == "" {
			return errors.New("release artifact identity is incomplete")
		}
		if err := validateBundlePath(artifact.ArtifactPath); err != nil {
			return err
		}
		if artifact.EvidencePath != "" {
			if err := validateBundlePath(artifact.EvidencePath); err != nil {
				return err
			}
		}
		if got, err := releaseFileArtifact(artifact.ArtifactPath, "artifact"); err != nil || got != artifact.Artifact.Name {
			if err != nil {
				return err
			}
			return fmt.Errorf("release artifact %s has an invalid content path", artifact.Artifact.Name)
		}
		if files[artifact.ArtifactPath].Kind != "artifact" {
			return fmt.Errorf("release artifact %s is missing its artifact member", artifact.Artifact.Name)
		}
		if files[artifact.ArtifactPath].SHA256 != artifact.Artifact.ContentSHA256 || files[artifact.ArtifactPath].Artifact != artifact.Artifact.Name {
			return fmt.Errorf("release artifact %s content member is not bound to its identity", artifact.Artifact.Name)
		}
		if artifact.EvidencePath != "" {
			if artifact.EvidencePath != filepath.ToSlash(filepath.Join("evidence", artifact.Artifact.Name+".json")) {
				return fmt.Errorf("release artifact %s has an invalid evidence path", artifact.Artifact.Name)
			}
			if files[artifact.EvidencePath].Kind != "evidence" || files[artifact.EvidencePath].Artifact != artifact.Artifact.Name {
				return fmt.Errorf("release artifact %s is missing its evidence member", artifact.Artifact.Name)
			}
		}
		if _, exists := seenArtifacts[artifact.Artifact.Name]; exists {
			return fmt.Errorf("release manifest repeats artifact %q", artifact.Artifact.Name)
		}
		seenArtifacts[artifact.Artifact.Name] = struct{}{}
	}
	for path, file := range files {
		if file.Kind == CompanionStreamDeckKind || file.Kind == CompanionStatusKind {
			continue
		}
		if _, ok := seenArtifacts[file.Artifact]; !ok {
			return fmt.Errorf("release member %q references an unknown artifact", path)
		}
	}
	return nil
}

func validateExecutingControllerBinding(manifest ReleaseManifest) error {
	if manifest.ControllerSHA256 == "" {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executing controller for release binding: %w", err)
	}
	info, err := os.Stat(executable)
	if err != nil {
		return fmt.Errorf("inspect executing controller for release binding: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("executing controller is not a regular file")
	}
	actual, err := ContentSHA256ForFile(executable)
	if err != nil {
		return fmt.Errorf("hash executing controller for release binding: %w", err)
	}
	if !strings.EqualFold(actual, manifest.ControllerSHA256) || info.Size() != manifest.ControllerSizeBytes {
		return fmt.Errorf("release controller binding does not match the executing controller")
	}
	return nil
}

func releaseFileArtifact(path, kind string) (string, error) {
	parts := strings.Split(path, "/")
	switch kind {
	case "artifact":
		if len(parts) != 3 || parts[0] != "artifacts" || parts[1] == "" || parts[2] == "" {
			return "", fmt.Errorf("artifact member path %q is incomplete", path)
		}
		return parts[1], nil
	case "evidence":
		if len(parts) == 2 && strings.HasSuffix(parts[1], ".json") {
			artifact := strings.TrimSuffix(parts[1], ".json")
			if artifact == "" {
				return "", fmt.Errorf("evidence member path %q is incomplete", path)
			}
			return artifact, nil
		}
		if len(parts) >= 3 && parts[0] == "evidence" && parts[1] != "" && parts[2] != "" {
			return parts[1], nil
		}
		return "", fmt.Errorf("evidence member path %q is incomplete", path)
	default:
		return "", fmt.Errorf("release member path %q has unknown kind %q", path, kind)
	}
}

// ImportedReleaseManifest reads the manifest from a release tree that has
// already passed ImportReleaseBundle. The returned digest is the identity
// bound into deployment plans; callers never infer release identity from a
// filename or directory timestamp.
func ImportedReleaseManifest(root string) (ReleaseManifest, string, error) {
	path := filepath.Join(root, "generated", "release", ReleaseManifestName)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return ReleaseManifest{}, "", err
	}
	data, err := pathguard.ReadFileLimited(path, MaxReleaseManifestBytes)
	if err != nil {
		return ReleaseManifest{}, "", err
	}
	signaturePath := filepath.Join(root, "generated", "release", ReleaseSignatureName)
	signatureData, err := pathguard.ReadFileLimited(signaturePath, MaxReleaseManifestBytes)
	if err != nil {
		return ReleaseManifest{}, "", fmt.Errorf("read imported release signature: %w", err)
	}
	var signature ManifestSignature
	if err := json.Unmarshal(signatureData, &signature); err != nil {
		return ReleaseManifest{}, "", fmt.Errorf("decode imported release signature: %w", err)
	}
	trusted, err := TrustedReleaseKeys()
	if err != nil {
		return ReleaseManifest{}, "", err
	}
	if err := verifyManifest(data, signature, trusted); err != nil {
		return ReleaseManifest{}, "", fmt.Errorf("verify imported release signature: %w", err)
	}
	var manifest ReleaseManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ReleaseManifest{}, "", fmt.Errorf("decode imported release manifest: %w", err)
	}
	if err := validateReleaseManifest(manifest); err != nil {
		return ReleaseManifest{}, "", err
	}
	if err := validateExecutingControllerBinding(manifest); err != nil {
		return ReleaseManifest{}, "", err
	}
	sum := sha256.Sum256(data)
	return manifest, hex.EncodeToString(sum[:]), nil
}

// ResolveImportedArtifact binds an artifact to the paths inside the
// authenticated release tree. It deliberately does not inspect legacy
// generated/artifacts output, so a copied or stale local file cannot replace
// the signed release selected by the operator.
func ResolveImportedArtifact(root string, requested model.Artifact) (model.Artifact, Evidence, error) {
	manifest, _, err := ImportedReleaseManifest(root)
	if err != nil {
		return model.Artifact{}, Evidence{}, fmt.Errorf("load imported release: %w", err)
	}
	var selected *ReleaseArtifact
	for index := range manifest.Artifacts {
		candidate := &manifest.Artifacts[index]
		if candidate.Artifact.Name == requested.Name {
			selected = candidate
			break
		}
	}
	if selected == nil {
		return model.Artifact{}, Evidence{}, fmt.Errorf("release does not contain artifact %s", requested.Name)
	}
	if !artifactIdentityMatches(selected.Artifact, requested) {
		return model.Artifact{}, Evidence{}, fmt.Errorf("imported artifact %s does not match requested definition", requested.Name)
	}
	releaseRoot := filepath.Join(root, "generated", "release")
	artifactPath := filepath.Join(releaseRoot, filepath.FromSlash(selected.ArtifactPath))
	manifestFiles := make(map[string]ReleaseFile, len(manifest.Files))
	for _, file := range manifest.Files {
		manifestFiles[file.Path] = file
	}
	artifactData, err := readImportedReleaseMember(artifactPath, manifestFiles, selected.ArtifactPath)
	if err != nil {
		return model.Artifact{}, Evidence{}, fmt.Errorf("read imported artifact %s: %w", requested.Name, err)
	}
	artifactSum := sha256.Sum256(artifactData)
	if hex.EncodeToString(artifactSum[:]) != selected.Artifact.ContentSHA256 {
		return model.Artifact{}, Evidence{}, fmt.Errorf("imported artifact %s content digest differs from manifest", requested.Name)
	}
	evidence := Evidence{ArtifactPath: artifactPath}
	if selected.EvidencePath != "" {
		evidencePath := filepath.Join(releaseRoot, filepath.FromSlash(selected.EvidencePath))
		evidenceData, err := readImportedReleaseMember(evidencePath, manifestFiles, selected.EvidencePath)
		if err != nil {
			return model.Artifact{}, Evidence{}, fmt.Errorf("read imported evidence %s: %w", requested.Name, err)
		}
		if err := json.Unmarshal(evidenceData, &evidence); err != nil {
			return model.Artifact{}, Evidence{}, err
		}
		if !evidence.Qualified || !artifactIdentityMatches(evidence.Artifact, requested) || evidence.ContentSHA256 != selected.Artifact.ContentSHA256 || (evidence.Artifact.ContentSHA256 != "" && evidence.Artifact.ContentSHA256 != selected.Artifact.ContentSHA256) {
			return model.Artifact{}, Evidence{}, fmt.Errorf("imported evidence for %s is not bound to the manifest", requested.Name)
		}
	}
	evidence.ArtifactPath = artifactPath
	return selected.Artifact, evidence, nil
}

func readImportedReleaseMember(path string, manifestFiles map[string]ReleaseFile, manifestPath string) ([]byte, error) {
	declared, ok := manifestFiles[manifestPath]
	if !ok {
		return nil, fmt.Errorf("release member %q is not declared", manifestPath)
	}
	data, err := pathguard.ReadFileLimited(path, MaxReleaseFileBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != declared.SizeBytes || hex.EncodeToString(sum[:]) != declared.SHA256 {
		return nil, fmt.Errorf("release member %q failed signed digest verification", manifestPath)
	}
	return data, nil
}

// ResolveImportedCompanion binds the StreamDeck runtime to the authenticated
// release tree. It never falls back to a workstation build or an arbitrary
// path supplied through the environment.
func ResolveImportedCompanion(root string) (string, error) {
	manifest, _, err := ImportedReleaseManifest(root)
	if err != nil {
		return "", fmt.Errorf("load imported release: %w", err)
	}
	if manifest.CompanionBinary == nil {
		return "", errors.New("authenticated release does not contain the companion StreamDeck binary")
	}
	companion := *manifest.CompanionBinary
	if companion.Kind != CompanionStreamDeckKind || companion.Path != CompanionStreamDeckPath || companion.Artifact != "" {
		return "", errors.New("authenticated release contains an invalid companion StreamDeck binding")
	}
	path := filepath.Join(root, "generated", "release", filepath.FromSlash(companion.Path))
	data, err := readReleaseFile(path)
	if err != nil {
		return "", fmt.Errorf("read imported companion StreamDeck binary: %w", err)
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != companion.SizeBytes || hex.EncodeToString(sum[:]) != companion.SHA256 {
		return "", errors.New("imported companion StreamDeck binary failed digest verification")
	}
	return path, nil
}

func ResolveImportedCompanionStatus(root string) (string, error) {
	manifest, _, err := ImportedReleaseManifest(root)
	if err != nil {
		return "", err
	}
	if manifest.CompanionStatusBinary == nil {
		return "", errors.New("import a release containing the Companion status binary before setup")
	}
	file := *manifest.CompanionStatusBinary
	if file.Path != CompanionStatusPath || file.Kind != CompanionStatusKind || file.Artifact != "" {
		return "", errors.New("invalid Companion status binary binding")
	}
	path := filepath.Join(root, "generated", "release", filepath.FromSlash(file.Path))
	data, err := readReleaseFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != file.SizeBytes || hex.EncodeToString(sum[:]) != file.SHA256 {
		return "", errors.New("Companion status binary failed digest verification")
	}
	return path, nil
}

// ActivateImportedRelease replaces the active release tree only after a
// complete staged import has succeeded. The old tree is restored if the
// second rename fails.
func ActivateImportedRelease(staged, active string) error {
	if err := validateSourcePath(filepath.Join(staged, ReleaseManifestName)); err != nil {
		return err
	}
	if err := pathguard.ValidateNoSymlinkComponents(active); err != nil {
		return err
	}
	if _, err := os.Stat(active); errors.Is(err, os.ErrNotExist) {
		return pathguard.Rename(staged, active)
	} else if err != nil {
		return err
	}
	backup := active + ".previous"
	if err := pathguard.RemoveAll(backup); err != nil {
		return err
	}
	if err := pathguard.Rename(active, backup); err != nil {
		return err
	}
	if err := pathguard.Rename(staged, active); err != nil {
		_ = pathguard.Rename(backup, active)
		return err
	}
	return pathguard.RemoveAll(backup)
}

func validateReleaseInput(input ReleaseInput) error {
	if input.Artifact.Name == "" || input.Artifact.ContentSHA256 == "" || !isSHA256(input.Artifact.ContentSHA256) || input.ArtifactPath == "" {
		return errors.New("release input has incomplete artifact identity")
	}
	if strings.ContainsAny(input.Artifact.Name, "/\\\x00") || input.Artifact.Name == "." || input.Artifact.Name == ".." {
		return fmt.Errorf("release artifact name %q is unsafe", input.Artifact.Name)
	}
	if err := validateSourcePath(input.ArtifactPath); err != nil {
		return err
	}
	if input.EvidencePath != "" {
		if err := validateSourcePath(input.EvidencePath); err != nil {
			return err
		}
	}
	return nil
}

type releaseMember struct {
	Path     string
	Source   string
	Data     []byte
	Inline   bool
	SHA256   string
	Size     int64
	Kind     string
	Artifact string
}

func newReleaseMember(path, source, kind, artifact string) (releaseMember, error) {
	if err := validateBundlePath(path); err != nil {
		return releaseMember{}, err
	}
	if err := validateSourcePath(source); err != nil {
		return releaseMember{}, err
	}
	sum, size, err := hashReleaseFile(source)
	if err != nil {
		return releaseMember{}, err
	}
	return releaseMember{Path: filepath.ToSlash(path), Source: source, SHA256: sum, Size: size, Kind: kind, Artifact: artifact}, nil
}

func newInlineReleaseMember(path string, data []byte, kind, artifact string) (releaseMember, error) {
	if err := validateBundlePath(path); err != nil {
		return releaseMember{}, err
	}
	if int64(len(data)) > MaxReleaseFileBytes {
		return releaseMember{}, errors.New("release member exceeds the permitted size")
	}
	sum := sha256.Sum256(data)
	return releaseMember{Path: filepath.ToSlash(path), Data: data, Inline: true, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), Kind: kind, Artifact: artifact}, nil
}

func hashReleaseFile(source string) (string, int64, error) {
	file, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaxReleaseFileBytes {
		return "", 0, errors.New("release source has an invalid size or type")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, MaxReleaseFileBytes+1))
	if err != nil {
		return "", 0, err
	}
	if info.Size() > MaxReleaseFileBytes || written != info.Size() {
		return "", 0, errors.New("release source exceeds the permitted size")
	}
	return hex.EncodeToString(hash.Sum(nil)), info.Size(), nil
}

func releaseMemberExists(members []releaseMember, path string) bool {
	for _, member := range members {
		if member.Path == path {
			return true
		}
	}
	return false
}

func readReleaseFile(path string) ([]byte, error) {
	if err := validateSourcePath(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("release source must be a regular non-symlink file")
	}
	if info.Size() < 0 || info.Size() > MaxReleaseFileBytes {
		return nil, errors.New("release source exceeds the permitted size")
	}
	return pathguard.ReadFile(path)
}

func writeReleaseArchive(output string, manifest, signature []byte, members []releaseMember) error {
	// Artifact bytes stay on disk until they are streamed into the archive.
	// Only the small manifest, signature, and rewritten evidence are retained
	// in memory, so a release-sized image cannot double controller memory use.
	file, err := os.CreateTemp(filepath.Dir(output), ".release-bundle-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	writeMember := func(member releaseMember) error {
		header := &tar.Header{Name: member.Path, Mode: 0600, Size: member.Size, ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if member.Inline {
			_, err := tarWriter.Write(member.Data)
			return err
		}
		file, err := os.Open(member.Source)
		if err != nil {
			return err
		}
		defer file.Close()
		hash := sha256.New()
		written, err := io.CopyN(io.MultiWriter(tarWriter, hash), file, member.Size)
		if err != nil {
			return err
		}
		if written != member.Size {
			return io.ErrUnexpectedEOF
		}
		if hex.EncodeToString(hash.Sum(nil)) != member.SHA256 {
			return fmt.Errorf("release source %q changed while the archive was assembled", member.Source)
		}
		return nil
	}
	if err := writeMember(releaseMember{Path: ReleaseManifestName, Data: manifest, Inline: true, Size: int64(len(manifest))}); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		_ = file.Close()
		return err
	}
	if err := writeMember(releaseMember{Path: ReleaseSignatureName, Data: signature, Inline: true, Size: int64(len(signature))}); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		_ = file.Close()
		return err
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Path < members[j].Path })
	for _, member := range members {
		if err := writeMember(member); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			_ = file.Close()
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		_ = file.Close()
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return pathguard.Rename(temporary, output)
}

type exactReleaseReader struct {
	reader    io.Reader
	remaining int64
}

func (reader *exactReleaseReader) Read(p []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > reader.remaining {
		p = p[:reader.remaining]
	}
	n, err := reader.reader.Read(p)
	reader.remaining -= int64(n)
	if err == io.EOF && reader.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func validateSourcePath(path string) error {
	if path == "" || strings.ContainsRune(path, 0) {
		return errors.New("release path is required")
	}
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("release path must be a regular non-symlink file")
	}
	return nil
}

func validateOutputPath(path string) error {
	if path == "" || strings.ContainsRune(path, 0) {
		return errors.New("release output path is required")
	}
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return fmt.Errorf("validate release output path: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("release output must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateBundlePath(name string) error {
	clean := filepath.ToSlash(filepath.Clean(name))
	if name == "" || strings.ContainsRune(name, 0) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(name) || strings.Contains(clean, "\\") || clean != name {
		return fmt.Errorf("release member path %q is unsafe", name)
	}
	if !strings.HasPrefix(clean, "artifacts/") && !strings.HasPrefix(clean, "evidence/") && !strings.HasPrefix(clean, "companion/") {
		return fmt.Errorf("release member path %q is outside the release content trees", name)
	}
	return nil
}

func validateKeyID(keyID string) error {
	if keyID == "" || len(keyID) > 64 || strings.TrimSpace(keyID) != keyID || strings.ContainsAny(keyID, "/\\\x00") {
		return errors.New("release signing key id is invalid")
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
