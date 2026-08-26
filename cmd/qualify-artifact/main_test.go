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
