package main

import "testing"

func TestSummarizeTrivyReportRequiresResults(t *testing.T) {
	if _, err := summarizeTrivyReport([]byte(`{}`)); err == nil {
		t.Fatal("empty Trivy report was accepted")
	}
}

func TestSummarizeTrivyReportMarksCompletedScanAndFindings(t *testing.T) {
	summary, err := summarizeTrivyReport([]byte(`{
  "Results": [{
    "Vulnerabilities": [
      {"Severity": "CRITICAL", "FixedVersion": "1.2.3"},
      {"Severity": "CRITICAL", "FixedVersion": ""},
      {"Severity": "HIGH", "FixedVersion": ""}
    ],
    "Secrets": [{}]
  }]
}`))
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Completed || summary.Secrets != 1 || summary.FixableCritical != 1 || summary.UnfixedCritical != 1 || summary.High != 1 {
		t.Fatalf("unexpected Trivy summary: %#v", summary)
	}
}

func TestFixableCriticalFindingsExposePackageAndVersionDetails(t *testing.T) {
	findings := fixableCriticalFindings([]byte(`{
  "Results": [{"Vulnerabilities": [{
    "VulnerabilityID": "CVE-2026-1234",
    "PkgName": "openssl",
    "InstalledVersion": "3.0.1",
    "Severity": "CRITICAL",
    "FixedVersion": "3.0.2"
  }]}]
}`))
	if len(findings) != 1 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	if findings[0].id != "CVE-2026-1234" || findings[0].packageName != "openssl" || findings[0].installed != "3.0.1" || findings[0].fixed != "3.0.2" {
		t.Fatalf("unexpected finding details: %#v", findings[0])
	}
}

func TestSecretFindingsExposeLocationWithoutSecretValue(t *testing.T) {
	findings := secretFindings([]byte(`{
  "Results": [{"Target": "/etc/example.conf", "Secrets": [{
    "RuleID": "generic-api-key",
    "Category": "generic",
    "Title": "Generic API Key",
    "StartLine": 7,
    "EndLine": 7,
    "Match": "must-not-be-printed"
  }]}]
}`))
	if len(findings) != 1 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	if findings[0].target != "/etc/example.conf" || findings[0].ruleID != "generic-api-key" || findings[0].startLine != 7 || findings[0].endLine != 7 {
		t.Fatalf("unexpected finding details: %#v", findings[0])
	}
}
