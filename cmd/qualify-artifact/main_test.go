package main

import "testing"

func TestAnalyzeTrivyReportRequiresResults(t *testing.T) {
	if _, _, _, err := analyzeTrivyReport([]byte(`{}`)); err == nil {
		t.Fatal("empty Trivy report was accepted")
	}
}

func TestAnalyzeTrivyReportBuildsSummaryAndDiagnosticsInOnePass(t *testing.T) {
	data := []byte(`{"Results":[{"Target":"image.tar","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"pkg-a","InstalledVersion":"1.0","Severity":"CRITICAL","FixedVersion":"1.1"},{"VulnerabilityID":"CVE-2","PkgName":"pkg-b","InstalledVersion":"2.0","Severity":"CRITICAL"},{"VulnerabilityID":"CVE-3","PkgName":"pkg-c","InstalledVersion":"3.0","Severity":"HIGH"}],"Secrets":[{"RuleID":"secret-1","Category":"credential","Title":"test finding","StartLine":4,"EndLine":4}]}]}`)
	summary, fixable, secrets, err := analyzeTrivyReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Completed || summary.Secrets != 1 || summary.FixableCritical != 1 || summary.UnfixedCritical != 1 || summary.High != 1 {
		t.Fatalf("unexpected Trivy summary: %#v", summary)
	}
	if len(fixable) != 1 || fixable[0].id != "CVE-1" {
		t.Fatalf("unexpected fixable findings: %#v", fixable)
	}
	if len(secrets) != 1 || secrets[0].ruleID != "secret-1" {
		t.Fatalf("unexpected secret findings: %#v", secrets)
	}
}

func TestAnalyzeTrivyReportExposesPackageAndVersionDetails(t *testing.T) {
	_, findings, _, err := analyzeTrivyReport([]byte(`{
  "Results": [{"Vulnerabilities": [{
    "VulnerabilityID": "CVE-2026-1234",
    "PkgName": "openssl",
    "InstalledVersion": "3.0.1",
    "Severity": "CRITICAL",
    "FixedVersion": "3.0.2"
  }]}]
}`))
	if err != nil || len(findings) != 1 {
		t.Fatalf("unexpected findings: %#v, %v", findings, err)
	}
	if findings[0].id != "CVE-2026-1234" || findings[0].packageName != "openssl" || findings[0].installed != "3.0.1" || findings[0].fixed != "3.0.2" {
		t.Fatalf("unexpected finding details: %#v", findings[0])
	}
}

func TestAnalyzeTrivyReportExposesSecretLocationWithoutSecretValue(t *testing.T) {
	_, _, findings, err := analyzeTrivyReport([]byte(`{
  "Results": [{"Target": "/etc/example.conf", "Secrets": [{
    "RuleID": "generic-api-key",
    "Category": "generic",
    "Title": "Generic API Key",
    "StartLine": 7,
    "EndLine": 7,
    "Match": "must-not-be-printed"
  }]}]
}`))
	if err != nil || len(findings) != 1 {
		t.Fatalf("unexpected findings: %#v, %v", findings, err)
	}
	if findings[0].target != "/etc/example.conf" || findings[0].ruleID != "generic-api-key" || findings[0].startLine != 7 || findings[0].endLine != 7 {
		t.Fatalf("unexpected finding details: %#v", findings[0])
	}
}
