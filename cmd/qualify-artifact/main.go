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
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			Severity         string `json:"Severity"`
			FixedVersion     string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
		} `json:"Secrets"`
	} `json:"Results"`
}

func main() {
	artifactPath := flag.String("artifact", "", "qualified artifact bytes")
	reportPath := flag.String("report", "", "Trivy JSON report")
	manifestPath := flag.String("manifest", "", "package manifest")
	sbomPath := flag.String("sbom", "", "SBOM")
	provenancePath := flag.String("provenance", "", "builder provenance evidence")
	evidenceRoot := flag.String("evidence-root", "generated/artifacts", "evidence output directory")
	module := flag.String("module", "", "built-in module name")
	flag.Parse()
	for name, value := range map[string]string{"artifact": *artifactPath, "report": *reportPath, "module": *module} {
		if value == "" {
			fatalf("-%s is required", name)
		}
	}
	data, err := artifacts.ReadQualificationInput(*reportPath, "Trivy report")
	if err != nil {
		fatalf("read Trivy report: %v", err)
	}
	summary, fixableFindings, secretFindings, err := analyzeTrivyReport(data)
	if err != nil {
		fatalf("decode Trivy report: %v", err)
	}
	artifact, err := artifacts.ArtifactFor(*module)
	if err != nil {
		fatalf("resolve artifact definition: %v", err)
	}
	evidence, err := artifacts.EvidenceForFile(*artifactPath, artifact)
	if err != nil {
		fatalf("hash artifact: %v", err)
	}
	evidence.ArtifactPath = *artifactPath
	if *manifestPath != "" {
		evidence.PackageManifestSHA = hashFile(*manifestPath, "package manifest")
	}
	if *sbomPath != "" {
		evidence.SBOMSHA256 = hashFile(*sbomPath, "SBOM")
	}
	evidence.TrivyReportSHA256 = hashBytes(data)
	if *provenancePath != "" {
		provenanceData, readErr := artifacts.ReadQualificationInput(*provenancePath, "builder provenance")
		if readErr != nil {
			fatalf("read builder provenance: %v", readErr)
		}
		var provenance artifacts.BuilderProvenance
		if err := json.Unmarshal(provenanceData, &provenance); err != nil {
			fatalf("decode builder provenance: %v", err)
		}
		evidence.Builder = provenance
		evidence.BuilderProvenanceSHA256 = hashBytes(provenanceData)
	}
	evidence, err = artifacts.QualifyEvidence(evidence, summary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "qualify artifact: %v\n", err)
		for _, finding := range fixableFindings {
			fmt.Fprintf(os.Stderr, "Trivy fixable CRITICAL: %s package=%s installed=%s fixed=%s\n", finding.id, finding.packageName, finding.installed, finding.fixed)
		}
		for _, finding := range secretFindings {
			fmt.Fprintf(os.Stderr, "Trivy secret: target=%s rule=%s category=%s title=%s lines=%d-%d\n", finding.target, finding.ruleID, finding.category, finding.title, finding.startLine, finding.endLine)
		}
		os.Exit(1)
	}
	if err := artifacts.WriteEvidence(*evidenceRoot, artifact.Name, evidence); err != nil {
		fatalf("write qualification evidence: %v", err)
	}
	fmt.Printf("qualified %s content=%s policy=%s\n", artifact.Name, evidence.ContentSHA256, evidence.QualificationPolicyVersion)
}

type fixableCriticalFinding struct {
	id, packageName, installed, fixed string
}

type secretFinding struct {
	target, ruleID, category, title string
	startLine, endLine              int
}

func analyzeTrivyReport(data []byte) (artifacts.ScanSummary, []fixableCriticalFinding, []secretFinding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return artifacts.ScanSummary{}, nil, nil, err
	}
	if report.Results == nil {
		return artifacts.ScanSummary{}, nil, nil, fmt.Errorf("Results is missing")
	}
	summary := artifacts.ScanSummary{Completed: true}
	fixable := make([]fixableCriticalFinding, 0)
	secrets := make([]secretFinding, 0)
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			switch vulnerability.Severity {
			case "CRITICAL":
				if vulnerability.FixedVersion == "" {
					summary.UnfixedCritical++
				} else {
					summary.FixableCritical++
					fixable = append(fixable, fixableCriticalFinding{
						id: vulnerability.VulnerabilityID, packageName: vulnerability.PkgName,
						installed: vulnerability.InstalledVersion, fixed: vulnerability.FixedVersion,
					})
				}
			case "HIGH":
				summary.High++
			}
		}
		summary.Secrets += len(result.Secrets)
		for _, secret := range result.Secrets {
			secrets = append(secrets, secretFinding{
				target: result.Target, ruleID: secret.RuleID, category: secret.Category,
				title: secret.Title, startLine: secret.StartLine, endLine: secret.EndLine,
			})
		}
	}
	return summary, fixable, secrets, nil
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
