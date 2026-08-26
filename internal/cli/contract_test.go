package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestQuickstartCommandsMatchPublicCLI(t *testing.T) {
	root := repositoryRoot(t)
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	quickstart := sectionCodeBlock(string(readme), "## Quickstart")
	if quickstart == "" {
		t.Fatal("README quickstart code block is missing")
	}

	for _, line := range strings.Split(quickstart, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "boetticher ") {
			t.Errorf("quickstart line is not a boetticher command: %q", line)
			continue
		}
		validateCommandForm(t, strings.Fields(line))
	}
}

func TestUsageIsGeneratedFromCommandMetadata(t *testing.T) {
	var output bytes.Buffer
	if err := Run([]string{"--help"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	for _, spec := range commandSpecs {
		if !strings.Contains(output.String(), spec.Usage) {
			t.Errorf("usage output is missing command form %q", spec.Usage)
		}
	}
}

func TestCommandReferenceContainsCLIUsage(t *testing.T) {
	root := repositoryRoot(t)
	document, err := os.ReadFile(filepath.Join(root, "docs", "commands.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range commandSpecs {
		if !strings.Contains(string(document), spec.Usage) {
			t.Errorf("docs/commands.md is missing command form %q", spec.Usage)
		}
	}
}

func validateCommandForm(t *testing.T, fields []string) {
	t.Helper()
	if len(fields) < 2 || fields[0] != "boetticher" {
		t.Fatalf("invalid command form: %q", fields)
	}
	known := map[string]map[string]bool{
		"init":               {"--site-dir": true, "--age-identity": true, "--external-firewall": true},
		"bootstrap-endpoint": {"--site": true},
		"preflight":          {"--site": true, "--live": true, "--bootstrap-address": true, "--trunk-interface": true},
		"bootstrap":          {"--site": true, "--recovery-confirmed": true, "--trunk-interface": true, "--dry-run": true},
		"provision":          {"--site": true, "--debian-template": true, "--dry-run": true},
		"converge":           {"--site": true, "--zabbix-url": true, "--dry-run": true},
		"ssh-config":         {"--site": true, "--output": true, "--force": true, "--check": true, "--install-include": true},
		"verify":             {"--site": true},
		"doctor":             {"--site": true},
		"upgrade":            {"--site": true},
		"access":             {"--site": true},
		"portal":             {"--site": true, "--output": true, "--docs": true},
		"network":            {"--site": true},
		"pki":                {"--site": true},
		"firewall":           {"--site": true, "--live": true, "--json": true},
		"dhcp":               {"--site": true, "--live": true, "--json": true},
		"storage":            {"--site": true, "--live": true, "--confirmed": true},
	}
	command := fields[1]
	if _, ok := known[command]; !ok {
		t.Fatalf("quickstart uses unknown command %q", command)
	}
	for _, field := range fields[2:] {
		if !strings.HasPrefix(field, "--") {
			continue
		}
		name := strings.SplitN(field, "=", 2)[0]
		if !known[command][name] {
			t.Errorf("quickstart uses undocumented or unsupported flag %q for %s", name, command)
		}
	}
}

func sectionCodeBlock(document, heading string) string {
	start := strings.Index(document, heading)
	if start < 0 {
		return ""
	}
	remainder := document[start+len(heading):]
	end := strings.Index(remainder, "\n## ")
	if end >= 0 {
		remainder = remainder[:end]
	}
	open := strings.Index(remainder, "```")
	if open < 0 {
		return ""
	}
	content := remainder[open+3:]
	if newline := strings.IndexByte(content, '\n'); newline >= 0 {
		content = content[newline+1:]
	}
	if close := strings.Index(content, "```"); close >= 0 {
		return content[:close]
	}
	return ""
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
