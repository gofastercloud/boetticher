// Command artifact-reuse is maintainer-only validation for reusing a
// previously built and qualified appliance artifact. It is not part of the
// installed Boetticher operator CLI.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/artifacts"
)

func main() {
	root := flag.String("root", "", "artifact evidence root containing generated/artifacts")
	module := flag.String("module", "", "built-in artifact module name")
	flag.Parse()
	if *root == "" || *module == "" || flag.NArg() != 0 {
		fatal("usage: artifact-reuse -root EVIDENCE_ROOT -module NAME")
	}
	artifact, err := artifacts.ArtifactFor(*module)
	if err != nil {
		fatal("resolve artifact definition: %v", err)
	}
	artifactPath, err := artifacts.ArtifactCachePath(*root, artifact)
	if err != nil {
		fatal("resolve artifact cache path: %v", err)
	}
	evidence, err := artifacts.LoadEvidence(*root, artifact.Name)
	if err != nil {
		if artifactBlobPresent(artifactPath) {
			fmt.Printf("qualification-needed %s\n", artifact.Name)
			return
		}
		fatal("load artifact qualification evidence: %v", err)
	}
	// Build-input identity is a maintainer cache key, not an operator trust
	// decision. Keep it here so a relevant image-input change rebuilds the
	// artifact, while runtime/release resolution can reuse unchanged bytes
	// across source-only revisions.
	if evidence.DefinitionSHA256 != artifact.DefinitionSHA256 {
		if artifactBlobPresent(artifactPath) {
			fmt.Printf("rebuild-needed %s\n", artifact.Name)
			return
		}
		fatal("artifact build inputs changed for %s", artifact.Name)
	}
	if evidence.Artifact.Name != artifact.Name || evidence.Artifact.Version != artifact.Version || evidence.Artifact.Architecture != artifact.Architecture || evidence.Artifact.Kind != artifact.Kind {
		fatal("artifact coordinates changed for %s", artifact.Name)
	}
	if evidence.ContentSHA256 != "" && artifactBlobPresent(artifactPath) {
		actual, hashErr := artifacts.ContentSHA256ForFile(artifactPath)
		if hashErr != nil {
			fatal("read artifact bytes for %s: %v", artifact.Name, hashErr)
		}
		if actual != evidence.ContentSHA256 {
			fmt.Printf("rebuild-needed %s\n", artifact.Name)
			return
		}
	}
	if _, _, err := artifacts.ResolveArtifactEvidence(*root, artifact); err != nil {
		if artifactBlobPresent(artifactPath) {
			fmt.Printf("qualification-needed %s\n", artifact.Name)
			return
		}
		fatal("artifact is not reusable: %v", err)
	}
	fmt.Printf("reusable %s\n", artifact.Name)
}

func artifactBlobPresent(path string) bool {
	info, err := os.Stat(filepath.Clean(path))
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
