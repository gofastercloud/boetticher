package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
)

// release-bundle deliberately has no build or network behavior. The release
// workflow invokes the image builder and qualification evaluator first, then
// hands this command the resulting site-local evidence tree.
func main() {
	siteDir := flag.String("site", ".", "site directory containing generated/artifacts")
	artifactRoot := flag.String("artifact-root", "", "qualified artifact directory; defaults to <site>/generated/artifacts")
	output := flag.String("output", "", "signed release bundle output path")
	releaseVersion := flag.String("release", model.ReleaseVersion, "release version")
	sourceCommit := flag.String("source-commit", "", "source commit included in provenance")
	workflow := flag.String("workflow", "", "release workflow identity included in provenance")
	controllerMin := flag.String("controller-min", model.ReleaseVersion, "minimum compatible controller release")
	controllerMax := flag.String("controller-max", model.ReleaseVersion, "maximum compatible controller release")
	keyID := flag.String("key-id", "", "release signing key id")
	privateKeyPath := flag.String("private-key", "", "0600 file containing base64 or raw Ed25519 private key")
	flag.Parse()
	if *output == "" || *sourceCommit == "" || *workflow == "" || *keyID == "" || *privateKeyPath == "" || flag.NArg() != 0 {
		fatal("usage: release-bundle -output PATH -source-commit COMMIT -workflow NAME -key-id ID -private-key PATH [-site DIR]")
	}
	if *artifactRoot == "" {
		*artifactRoot = filepath.Join(*siteDir, "generated", "artifacts")
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		fatal("read signing key: %v", err)
	}
	inputs := make([]artifacts.ReleaseInput, 0, len(artifacts.Definitions()))
	for _, definition := range artifacts.Definitions() {
		artifact, err := artifacts.ArtifactFor(definition.Name)
		if err != nil {
			fatal("resolve %s artifact: %v", definition.Name, err)
		}
		artifactPath := filepath.Join(*artifactRoot, artifact.Name, artifactFilename(artifact))
		evidence, err := artifacts.LoadEvidence(*siteDir, artifact.Name)
		if err != nil {
			fatal("load %s qualification evidence: %v", artifact.Name, err)
		}
		if !evidence.Qualified {
			fatal("artifact %s is not qualified", artifact.Name)
		}
		qualificationFiles := map[string]string{}
		for _, required := range []struct {
			name   string
			digest string
		}{
			{name: "package-manifest.txt", digest: evidence.PackageManifestSHA},
			{name: "sbom.json", digest: evidence.SBOMSHA256},
			{name: "trivy.json", digest: evidence.TrivyReportSHA256},
			{name: "builder-provenance.json", digest: evidence.BuilderProvenanceSHA256},
			{name: "smoke.txt", digest: evidence.SmokeReportSHA256},
		} {
			if err := addQualificationFile(qualificationFiles, artifact.Name, required.name, required.digest, *artifactRoot); err != nil {
				fatal("artifact %s: %v", artifact.Name, err)
			}
		}
		inputs = append(inputs, artifacts.ReleaseInput{
			Artifact: artifact, ArtifactPath: artifactPath,
			EvidencePath: artifacts.EvidencePath(*siteDir, artifact.Name), QualificationFiles: qualificationFiles,
		})
	}
	manifest, err := artifacts.BuildReleaseBundleWithMetadata(*output, artifacts.ReleaseBuildMetadata{
		ReleaseVersion: *releaseVersion, SourceCommit: *sourceCommit, BuildWorkflow: *workflow,
		ControllerMin: *controllerMin, ControllerMax: *controllerMax,
		QualificationPolicyVersion: artifacts.QualificationPolicyVersion,
	}, model.APIVersion, model.ConfigSchemaVersion, privateKey, *keyID, inputs)
	if err != nil {
		fatal("build release bundle: %v", err)
	}
	fmt.Printf("signed release bundle: %s release=%s artifacts=%d\n", *output, manifest.ReleaseVersion, len(manifest.Artifacts))
}

func artifactFilename(artifact model.Artifact) string {
	if artifact.Kind == "qemu" {
		return fmt.Sprintf("%s-%s-%s.qcow2", artifact.Name, artifact.Version, artifact.Architecture)
	}
	return fmt.Sprintf("%s-%s-%s.tar.zst", artifact.Name, artifact.Version, artifact.Architecture)
}

func addQualificationFile(files map[string]string, artifact, name, digest, root string) error {
	if digest == "" {
		return fmt.Errorf("mandatory qualification evidence %s is missing", name)
	}
	files[filepath.ToSlash(filepath.Join("evidence", artifact, name))] = filepath.Join(root, artifact, name)
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("signing key must be a private regular file with mode 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if decoded, decodeErr := base64.StdEncoding.DecodeString(trimmed); decodeErr == nil && len(decoded) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(decoded), nil
	}
	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(data), nil
	}
	return nil, errors.New("signing key must contain a raw or base64 Ed25519 private key")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
