package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/site"
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

func TestQuickstartOfflineCommandsExecute(t *testing.T) {
	// Commands that require a Proxmox host or mutate infrastructure remain
	// outside local CI; init and its secret path use the bundled implementation.
	siteDir := filepath.Join(t.TempDir(), "my-boetticher")
	identity := filepath.Join(t.TempDir(), "age-identity.txt")
	rootIdentity := filepath.Join(t.TempDir(), "root-age-identity.txt")
	run := func(args ...string) string {
		t.Helper()
		var output bytes.Buffer
		if err := Run(args, &output, &output); err != nil {
			t.Fatalf("%v failed: %v\n%s", args, err, output.String())
		}
		return output.String()
	}

	run("init", "--site-dir", siteDir, "--age-identity", identity, "--root-age-identity", rootIdentity)
	initialized, err := site.Load(siteDir)
	if err != nil {
		t.Fatal(err)
	}
	presence, err := site.PlatformSecretPresence(siteDir, initialized, identity, []string{"pulse_proxy_auth_secret"})
	if err != nil {
		t.Fatal(err)
	}
	if !presence["pulse_proxy_auth_secret"] {
		t.Fatal("init did not create the Core-owned Pulse proxy credential")
	}
	run("config", "validate", "--site", siteDir)
	run("module", "list", "--site", siteDir)
	var deployOutput bytes.Buffer
	if err := Run([]string{"deploy", "--site", siteDir, "--dry-run"}, &deployOutput, &deployOutput); err == nil {
		t.Fatal("deploy dry-run unexpectedly passed without qualified artifact evidence")
	}
	if !strings.Contains(deployOutput.String(), "Deployment: FAIL") || !strings.Contains(deployOutput.String(), "Infrastructure changed: NO") {
		t.Fatalf("deploy dry-run did not render its binary failure summary: %s", deployOutput.String())
	}

	var statusOutput bytes.Buffer
	if err := Run([]string{"status", "--site", siteDir}, &statusOutput, &statusOutput); err == nil {
		t.Fatal("status unexpectedly passed before live deployment evidence")
	}
	if !strings.Contains(statusOutput.String(), "Platform FAILED") {
		t.Fatalf("status did not report the failed local health checks: %s", statusOutput.String())
	}
	if strings.Contains(statusOutput.String(), "NOT TESTED") || strings.Contains(statusOutput.String(), "ACTION REQUIRED") {
		t.Fatalf("status reported an unknowable check: %s", statusOutput.String())
	}
}

func TestInitConfiguresDedicatedDataDiskWithoutManualSiteEdits(t *testing.T) {
	siteDir := filepath.Join(t.TempDir(), "my-boetticher")
	identity := filepath.Join(t.TempDir(), "age-identity.txt")
	rootIdentity := filepath.Join(t.TempDir(), "root-age-identity.txt")
	var output bytes.Buffer
	if err := Run([]string{"init", "--site-dir", siteDir, "--age-identity", identity, "--root-age-identity", rootIdentity, "--storage-profile", "dedicated-data-disk", "--storage-device", "/dev/disk/by-id/ata-example-data"}, &output, &output); err != nil {
		t.Fatalf("init dedicated storage: %v\n%s", err, output.String())
	}
	configured, err := site.Load(siteDir)
	if err != nil {
		t.Fatal(err)
	}
	if configured.StorageProfile != "dedicated-data-disk" || configured.StorageDevice != "/dev/disk/by-id/ata-example-data" {
		t.Fatalf("dedicated storage was not saved: %#v", configured)
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

func TestRootShortHelpListsCurrentCommands(t *testing.T) {
	var output bytes.Buffer
	if err := Run([]string{"-h"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, command := range []string{"boetticher init", "boetticher enroll", "boetticher plan", "boetticher deploy", "boetticher status", "boetticher module", "boetticher network", "boetticher update", "boetticher help --advanced"} {
		if !strings.Contains(text, command) {
			t.Errorf("root short help omitted %s: %s", command, text)
		}
	}
	for _, hidden := range []string{"boetticher preflight", "boetticher modules"} {
		if strings.Contains(text, hidden) {
			t.Errorf("root short help exposed advanced command %s: %s", hidden, text)
		}
	}
}

func TestPublicHelpPathsDoNotFail(t *testing.T) {
	for _, args := range [][]string{
		{"init", "--help"}, {"enroll", "--help"}, {"bundle", "--help"}, {"deploy", "--help"}, {"status", "--help"}, {"update", "--help"},
		{"network", "--help"}, {"firewall", "--help"}, {"dhcp", "--help"}, {"dns", "--help"}, {"pki", "--help"}, {"access", "--help"}, {"network", "test", "--help"},
		{"module", "--help"}, {"module", "secrets", "--help"}, {"config", "--help"}, {"logs", "--help"}, {"aiops", "--help"},
	} {
		var output bytes.Buffer
		if err := Run(args, &output, &output); err != nil {
			t.Errorf("%v: %v", args, err)
		}
		if output.Len() == 0 {
			t.Errorf("%v produced no help output", args)
		}
	}
}

func TestNestedHelpPathsArePathAwareAndSubstantive(t *testing.T) {
	paths := []string{
		"firewall diff", "dhcp leases", "network trunk status", "pki trust export",
		"companion add", "companion setup", "companion status",
		"module disable", "module configure printer",
		"config schema",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			var output bytes.Buffer
			args := append(strings.Fields(path), "--help")
			if err := Run(args, &output, &output); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			for _, section := range []string{"What it does:", "Usage:", "Arguments:", "Options:", "Worth knowing:", "Try it:", "Related commands:"} {
				if !strings.Contains(text, section) {
					t.Errorf("nested help %q is missing %s: %s", path, section, text)
				}
			}
			if strings.Contains(text, "Run boetticher "+strings.Fields(path)[0]+" with --help") {
				t.Errorf("nested help %q contains recursive hint: %s", path, text)
			}
			if path == "module configure printer" && !strings.Contains(text, "The interactive workflow asks only for fields the module needs.") {
				t.Errorf("module-specific help %q fell back to generic module help: %s", path, text)
			}
		})
	}
}

func TestCommandMetadataHasSubstantiveHelpForEveryPath(t *testing.T) {
	for path, spec := range helpSpecs {
		t.Run(path, func(t *testing.T) {
			for name, value := range map[string]string{
				"Purpose": spec.Purpose, "Usage": spec.Usage, "Arguments": spec.Arguments,
				"Options": spec.Options, "Safety": spec.Safety, "Examples": spec.Examples,
				"Related": spec.Related,
			} {
				if strings.TrimSpace(value) == "" {
					t.Errorf("help metadata has empty %s field", name)
				}
			}
		})
	}
	for path, spec := range nestedHelpSpecs {
		t.Run("nested/"+path, func(t *testing.T) {
			if spec.Usage == "" || spec.Purpose == "" || spec.Safety == "" {
				t.Fatalf("nested help metadata is incomplete: %#v", spec)
			}
		})
	}
}

func TestConvergeIsNotAnActiveCommand(t *testing.T) {
	var output bytes.Buffer
	if err := Run([]string{"converge"}, &output, &output); err == nil {
		t.Fatal("removed converge command was accepted")
	}
	if strings.Contains(output.String(), "boetticher converge") {
		t.Fatal("removed converge command appeared in normal CLI output")
	}
}

func TestCommandReferenceContainsCLIUsage(t *testing.T) {
	root := repositoryRoot(t)
	document, err := os.ReadFile(filepath.Join(root, "docs", "commands.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range advancedCommandSpecs {
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
		"init":       {"--site-dir": true, "--age-identity": true, "--root-age-identity": true, "--external-firewall": true, "--storage-profile": true, "--storage-device": true},
		"bundle":     {"--site": true, "--json": true},
		"enroll":     {"--site": true, "--bootstrap-address": true, "--operator-key": true, "--age-identity": true, "--recovery-confirmed": true, "--storage-confirmed": true, "--proxmox-ca": true},
		"plan":       {"--site": true, "--live": true, "--json": true},
		"deploy":     {"--plan": true, "--site": true, "--dry-run": true, "--confirm": true, "--replace-firewall": true, "--recreate-legacy-lxcs": true},
		"status":     {"--site": true, "--live": true, "--details": true, "--json": true},
		"update":     {"--site": true, "--dry-run": true, "--confirm": true},
		"logs":       {"--site": true, "--unit": true, "--since": true, "--priority": true, "--limit": true},
		"ssh-config": {"--site": true, "--output": true, "--force": true, "--check": true, "--install-include": true},
		"access":     {"--site": true},
		"network":    {"--site": true},
		"pki":        {"--site": true},
		"firewall":   {"--site": true, "--live": true, "--json": true},
		"dhcp":       {"--site": true, "--live": true, "--json": true},
		"storage":    {"--site": true, "--live": true, "--storage-confirmed": true, "--reinitialize": true, "--reboot": true, "--allow-shared-usb-bridge-quirk": true},
		"module":     {"--site": true, "--dry-run": true, "--confirm": true, "--purge": true, "--age-identity": true, "--proxmox-ca": true, "--insecure": true},
		"config":     {"--site": true},
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
