package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/artifacts"
)

type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			Severity     string `json:"Severity"`
			FixedVersion string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
		Secrets []struct{} `json:"Secrets"`
	} `json:"Results"`
}

func main() {
	artifactPath := flag.String("artifact", "", "qualified artifact bytes")
	reportPath := flag.String("report", "", "Trivy JSON report")
	manifestPath := flag.String("manifest", "", "package manifest")
	sbomPath := flag.String("sbom", "", "SBOM")
	evidenceRoot := flag.String("evidence-root", "generated/artifacts", "evidence output directory")
	module := flag.String("module", "", "built-in module name")
	provider := flag.String("provider", "", "built-in provider")
	flag.Parse()
	for name, value := range map[string]string{"artifact": *artifactPath, "report": *reportPath, "manifest": *manifestPath, "sbom": *sbomPath, "module": *module} {
		if value == "" {
			fatalf("-%s is required", name)
		}
	}
	data, err := os.ReadFile(*reportPath)
	if err != nil {
		fatalf("read Trivy report: %v", err)
	}
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		fatalf("decode Trivy report: %v", err)
	}
	summary := artifacts.ScanSummary{}
	for _, result := range report.Results {
		summary.Secrets += len(result.Secrets)
		for _, vulnerability := range result.Vulnerabilities {
			switch vulnerability.Severity {
			case "CRITICAL":
				if vulnerability.FixedVersion == "" {
					summary.UnfixedCritical++
				} else {
					summary.FixableCritical++
				}
			case "HIGH":
				summary.High++
			}
		}
	}
	artifact, err := artifacts.ArtifactFor(*module, *provider)
	if err != nil {
		fatalf("resolve artifact definition: %v", err)
	}
	evidence, err := artifacts.EvidenceForFile(*artifactPath, artifact)
	if err != nil {
		fatalf("hash artifact: %v", err)
	}
	evidence.ArtifactPath = *artifactPath
	evidence.PackageManifestSHA = hashFile(*manifestPath, "package manifest")
	evidence.SBOMSHA256 = hashFile(*sbomPath, "SBOM")
	evidence.TrivyReportSHA256 = hashBytes(data)
	evidence, err = artifacts.QualifyEvidence(evidence, summary)
	if err != nil {
		fatalf("qualify artifact: %v", err)
	}
	if err := artifacts.WriteEvidence(*evidenceRoot, artifact.Name, evidence); err != nil {
		fatalf("write qualification evidence: %v", err)
	}
	fmt.Printf("qualified %s content=%s policy=%s\n", artifact.Name, evidence.ContentSHA256, evidence.QualificationPolicyVersion)
}

func hashFile(path, name string) string {
	digest, err := artifacts.QualificationInputSHA256(path, name)
	if err != nil {
		fatalf("hash qualification input %s: %v", name, err)
	}
	return digest
}

func hashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
