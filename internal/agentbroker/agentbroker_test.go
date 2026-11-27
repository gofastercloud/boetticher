package agentbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func allowAnyOwner(os.FileInfo) error { return nil }

func allTier2Policy() Policy {
	return Policy{
		Tier2: Tier2Policy{
			SystemPower:      true,
			FirewallTest:     true,
			DNSRecords:       true,
			DHCPReservations: true,
			ModuleApply:      []string{"firewall", "dns", "dhcp", "observability", "vpn", "tailnet", "media"},
		},
	}
}

func TestParseCommandRejectsInvalidInputs(t *testing.T) {
	oversized := "boetticher host status " + strings.Repeat("a", MaxCommandBytes)
	tooManyArgs := "boetticher" + strings.Repeat(" a", MaxArgs+1)

	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"spaces only", "    "},
		{"nul byte", "boetticher host status\x00"},
		{"newline", "boetticher host status\nwhoami"},
		{"carriage return", "boetticher host status\rwhoami"},
		{"tab", "boetticher\thost\tstatus"},
		{"escape char", "boetticher host status\x1b[31m"},
		{"semicolon", "boetticher host status; id"},
		{"pipe", "boetticher host status | cat"},
		{"ampersand", "boetticher host status && id"},
		{"dollar", "boetticher host system-status $(id)"},
		{"backtick", "boetticher host system-status `id`"},
		{"parens", "boetticher (host status)"},
		{"redirect out", "boetticher host status > /tmp/out"},
		{"redirect in", "boetticher host status < /etc/passwd"},
		{"backslash", `boetticher host status \`},
		{"single quote", "boetticher host system-status 'foo'"},
		{"double quote", `boetticher host system-status "foo"`},
		{"glob star", "boetticher host system-status *"},
		{"oversized", oversized},
		{"too many args", tooManyArgs},
		{"non-boetticher binary", "sh -c id"},
		{"absolute path prefix", "/usr/local/bin/boetticher host status"},
		{"relative path prefix", "./boetticher host status"},
		{"install script", "install.sh"},
		{"path traversal", "boetticher host system-status ../etc/passwd"},
		{"non-ascii", "boetticher host system-status café"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if argv, err := ParseCommand(tc.raw); err == nil {
				t.Fatalf("ParseCommand(%q) succeeded with %v, want error", tc.raw, argv)
			}
		})
	}
}

func TestParseCommandAcceptsValidInput(t *testing.T) {
	argv, err := ParseCommand("  boetticher   host   status  --details  ")
	if err != nil {
		t.Fatalf("ParseCommand returned unexpected error: %v", err)
	}
	want := []string{"boetticher", "host", "status", "--details"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("ParseCommand = %v, want %v", argv, want)
	}
}

func TestEvaluateTier1Allowed(t *testing.T) {
	commands := []string{
		"boetticher controller status",
		"boetticher controller status --operator pi",
		"boetticher host status",
		"boetticher host status --details",
		"boetticher host plan-storage",
		"boetticher host list-systems",
		"boetticher host system-status octoprint",
		"boetticher host upgrade --plan",
		"boetticher host reboot --plan",
		"boetticher host reboot --with-guests --plan",
		"boetticher host reboot --plan --with-guests",
		"boetticher module firewall status",
		"boetticher module firewall plan",
		"boetticher module dns status",
		"boetticher module dns plan",
		"boetticher module dns list-records",
		"boetticher module dhcp status",
		"boetticher module dhcp plan",
		"boetticher module dhcp list-reservations",
		"boetticher module dhcp list-leases",
		"boetticher module dhcp list-leases --details",
		"boetticher module observability status",
		"boetticher module observability plan",
		"boetticher module logging status",
		"boetticher module logging query",
		"boetticher module logging query --host lab-dns-01 --unit blocky.service --level warning --since 2h --limit 20",
		"boetticher module logging query --host=lab-dns-01 --limit=500 --since=168h",
		"boetticher module monitoring status",
		"boetticher module monitoring incidents list",
		"boetticher module monitoring incidents list --json",
		"boetticher module monitoring incidents --json list",
		"boetticher module monitoring incidents show 42",
		"boetticher module monitoring incidents show 42 --json",
		"boetticher module statuspage status",
		"boetticher module vpn status",
		"boetticher module vpn status --details",
		"boetticher module vpn plan",
		"boetticher module tailnet status",
		"boetticher module tailnet plan",
		"boetticher module media status",
		"boetticher module media plan",
	}

	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			argv, err := ParseCommand(cmd)
			if err != nil {
				t.Fatalf("ParseCommand(%q) error: %v", cmd, err)
			}
			dec := Evaluate(argv, Policy{})
			if !dec.Allowed || dec.Tier != "tier1" {
				t.Fatalf("Evaluate(%q) = %+v, want Allowed=true Tier=tier1", cmd, dec)
			}
		})
	}
}

func TestEvaluateTier2OptInAndDefaultDeny(t *testing.T) {
	cases := []struct {
		name   string
		cmd    string
		policy Policy
	}{
		{
			name:   "system_power start plan",
			cmd:    "boetticher host start-system octoprint --plan",
			policy: Policy{Tier2: Tier2Policy{SystemPower: true}},
		},
		{
			name:   "system_power start yes",
			cmd:    "boetticher host start-system octoprint --yes",
			policy: Policy{Tier2: Tier2Policy{SystemPower: true}},
		},
		{
			name:   "system_power stop yes",
			cmd:    "boetticher host stop-system octoprint --yes",
			policy: Policy{Tier2: Tier2Policy{SystemPower: true}},
		},
		{
			name:   "firewall_test plan",
			cmd:    "boetticher module firewall test --plan",
			policy: Policy{Tier2: Tier2Policy{FirewallTest: true}},
		},
		{
			name:   "firewall_test yes",
			cmd:    "boetticher module firewall test --yes",
			policy: Policy{Tier2: Tier2Policy{FirewallTest: true}},
		},
		{
			name:   "dns_records add",
			cmd:    "boetticher module dns add-record app --type A --value 10.10.20.61 --yes",
			policy: Policy{Tier2: Tier2Policy{DNSRecords: true}},
		},
		{
			name:   "dns_records add cname",
			cmd:    "boetticher module dns add-record web --type=CNAME --value=app.lab.home.arpa",
			policy: Policy{Tier2: Tier2Policy{DNSRecords: true}},
		},
		{
			name:   "dns_records remove",
			cmd:    "boetticher module dns remove-record app --yes",
			policy: Policy{Tier2: Tier2Policy{DNSRecords: true}},
		},
		{
			name:   "dhcp_reservations add",
			cmd:    "boetticher module dhcp add-reservation app --zone TRUSTED --mac 02:00:00:00:30:01 --address 10.10.30.61 --yes",
			policy: Policy{Tier2: Tier2Policy{DHCPReservations: true}},
		},
		{
			name:   "dhcp_reservations remove",
			cmd:    "boetticher module dhcp remove-reservation app --yes",
			policy: Policy{Tier2: Tier2Policy{DHCPReservations: true}},
		},
		{
			name:   "module_apply allowlisted dns",
			cmd:    "boetticher module dns apply --yes",
			policy: Policy{Tier2: Tier2Policy{ModuleApply: []string{"dns"}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv, err := ParseCommand(tc.cmd)
			if err != nil {
				t.Fatalf("ParseCommand(%q) error: %v", tc.cmd, err)
			}
			// Denied with default (empty) policy.
			if dec := Evaluate(argv, Policy{}); dec.Allowed {
				t.Fatalf("Evaluate(%q) with default policy allowed (%+v), want deny", tc.cmd, dec)
			}
			// Allowed when opted in.
			dec := Evaluate(argv, tc.policy)
			if !dec.Allowed || dec.Tier != "tier2" {
				t.Fatalf("Evaluate(%q) with opt-in policy = %+v, want Allowed=true Tier=tier2", tc.cmd, dec)
			}
		})
	}

	// Non-allowlisted module_apply must still be denied.
	argv, err := ParseCommand("boetticher module firewall apply --yes")
	if err != nil {
		t.Fatalf("ParseCommand error: %v", err)
	}
	if dec := Evaluate(argv, Policy{Tier2: Tier2Policy{ModuleApply: []string{"dns"}}}); dec.Allowed {
		t.Fatalf("non-allowlisted module_apply was allowed: %+v", dec)
	}
}

func TestEvaluateHardDeniesAndBypasses(t *testing.T) {
	permissive := allTier2Policy()

	denied := []struct {
		name string
		cmd  string
	}{
		{"host teardown", "boetticher host teardown --plan"},
		{"module teardown", "boetticher module firewall teardown --yes"},
		{"data-disk flag", "boetticher host apply --data-disk /dev/disk/by-id/disk1 --yes"},
		{"data-disk equals", "boetticher module dns apply --data-disk=/dev/sda --yes"},
		{"host reboot yes", "boetticher host reboot --yes"},
		{"host reboot plan then yes", "boetticher host reboot --plan --yes"},
		{"host reboot yes then plan", "boetticher host reboot --yes --plan"},
		{"host reboot with-guests yes", "boetticher host reboot --with-guests --yes"},
		{"host upgrade yes", "boetticher host upgrade --yes"},
		{"host upgrade plan and yes", "boetticher host upgrade --plan --yes"},
		{"controller reboot", "boetticher controller reboot --yes"},
		{"controller bootstrap", "boetticher controller bootstrap --operator pi --confirm-key-login"},
		{"controller agent-access status", "boetticher controller agent-access status"},
		{"controller agent-access disable", "boetticher controller agent-access disable --yes"},
		{"observability secrets list", "boetticher module observability secrets list"},
		{"observability secrets rotate", "boetticher module observability secrets rotate --yes"},
		{"install.sh arg", "boetticher install.sh"},
		{"unknown subcommand", "boetticher host enroll root@10.10.99.5"},
		{"unknown controller action", "boetticher controller unknown"},
		{"unknown module capability", "boetticher module bogus status"},
		{"unknown flag on host status", "boetticher host status --bogus"},
		{"unknown flag on module apply", "boetticher module dns apply --yes --bogus"},
		{"vpn api-key-stdin", "boetticher module vpn apply --api-key-stdin --yes"},
		{"tailnet auth-key-file", "boetticher module tailnet apply --auth-key-file /tmp/key --yes"},
		{"media cloudflare-token-file", "boetticher module media apply --cloudflare-token-file /tmp/tok --yes"},
		{"monitoring ask", "boetticher module monitoring ask why-is-dns-slow"},
		{"monitoring incidents investigate", "boetticher module monitoring incidents investigate 42"},
		{"logging query positional arg", "boetticher module logging query extra"},
		{"logging query unknown flag", "boetticher module logging query --follow"},
		{"logging query since too large", "boetticher module logging query --since 200h"},
		{"logging query limit too large", "boetticher module logging query --limit 501"},
		{"logging query limit zero", "boetticher module logging query --limit 0"},
		{"logging query invalid level", "boetticher module logging query --level bogus"},
		{"start-system both flags", "boetticher host start-system octoprint --plan --yes"},
		{"start-system no flags", "boetticher host start-system octoprint"},
		{"firewall test both flags", "boetticher module firewall test --plan --yes"},
		{"firewall test cleanup-only", "boetticher module firewall test --cleanup-only --yes"},
		{"dns add-record invalid type", "boetticher module dns add-record app --type TXT --value hello --yes"},
		{"dns add-record missing value", "boetticher module dns add-record app --type A --yes"},
		{"dhcp add-reservation missing mac", "boetticher module dhcp add-reservation app --zone TRUSTED --address 10.10.30.61 --yes"},
		{"statuspage plan unsupported", "boetticher module statuspage plan"},
		{"bare boetticher", "boetticher"},
	}

	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			argv, err := ParseCommand(tc.cmd)
			if err != nil {
				// Parse-level rejection also satisfies deny.
				return
			}
			if dec := Evaluate(argv, permissive); dec.Allowed {
				t.Fatalf("Evaluate(%q) allowed (%+v) under permissive policy, want deny", tc.cmd, dec)
			}
		})
	}
}

func TestLoadPolicyValidation(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file returns empty default policy", func(t *testing.T) {
		p, err := LoadPolicy(filepath.Join(dir, "missing.yml"), allowAnyOwner)
		if err != nil {
			t.Fatalf("LoadPolicy missing file error: %v", err)
		}
		if p.Tier2.SystemPower || p.Tier2.FirewallTest || p.Tier2.DNSRecords || p.Tier2.DHCPReservations || len(p.Tier2.ModuleApply) != 0 {
			t.Fatalf("expected empty default policy, got %+v", p)
		}
	})

	t.Run("valid policy", func(t *testing.T) {
		path := filepath.Join(dir, "valid.yml")
		content := "tier2:\n  system_power: true\n  firewall_test: true\n  module_apply:\n    - dns\n    - dhcp\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := LoadPolicy(path, allowAnyOwner)
		if err != nil {
			t.Fatalf("LoadPolicy valid error: %v", err)
		}
		if !p.Tier2.SystemPower || !p.Tier2.FirewallTest || !reflect.DeepEqual(p.Tier2.ModuleApply, []string{"dns", "dhcp"}) {
			t.Fatalf("unexpected policy: %+v", p)
		}
	})

	t.Run("unknown YAML field rejected", func(t *testing.T) {
		path := filepath.Join(dir, "unknown.yml")
		if err := os.WriteFile(path, []byte("tier2:\n  unknown_flag: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path, allowAnyOwner); err == nil {
			t.Fatal("expected error for unknown YAML field")
		}
	})

	t.Run("unknown module_apply capability rejected", func(t *testing.T) {
		path := filepath.Join(dir, "bad-cap.yml")
		if err := os.WriteFile(path, []byte("tier2:\n  module_apply:\n    - bogus\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path, allowAnyOwner); err == nil {
			t.Fatal("expected error for unknown module_apply capability")
		}
	})

	t.Run("symlinked policy file rejected", func(t *testing.T) {
		target := filepath.Join(dir, "real.yml")
		if err := os.WriteFile(target, []byte("tier2:\n  system_power: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.yml")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(link, allowAnyOwner); err == nil {
			t.Fatal("expected error for symlinked policy file")
		}
	})

	t.Run("directory rejected", func(t *testing.T) {
		subdir := filepath.Join(dir, "policydir")
		if err := os.Mkdir(subdir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(subdir, allowAnyOwner); err == nil {
			t.Fatal("expected error for directory policy path")
		}
	})

	t.Run("non-root owner check rejected", func(t *testing.T) {
		path := filepath.Join(dir, "nonroot.yml")
		if err := os.WriteFile(path, []byte("tier2:\n  system_power: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		failOwner := func(os.FileInfo) error { return errors.New("must be root-owned") }
		if _, err := LoadPolicy(path, failOwner); err == nil {
			t.Fatal("expected error when owner check fails")
		}
		if os.Geteuid() != 0 {
			if _, err := LoadPolicy(path, DefaultOwnerCheck); err == nil {
				t.Fatal("expected DefaultOwnerCheck to reject non-root file")
			}
		}
	})
}

func TestBrokerRunAndAuditLog(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "agent-policy.yml")
	if err := os.WriteFile(policyPath, []byte("tier2:\n  system_power: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var gotBinary string
	var gotArgs []string
	var stdout, stderr, audit bytes.Buffer

	b := &Broker{
		Binary:     DefaultBoetticherBinary,
		PolicyPath: policyPath,
		OwnerCheck: allowAnyOwner,
		Exec: func(_ context.Context, binary string, args []string, _ io.Reader, out, _ io.Writer) (int, error) {
			gotBinary = binary
			gotArgs = append([]string(nil), args...)
			_, _ = io.WriteString(out, "ok\n")
			return 0, nil
		},
		Stdin:    strings.NewReader(""),
		Stdout:   &stdout,
		Stderr:   &stderr,
		AuditOut: &audit,
		Now:      func() time.Time { return time.Date(2026, 11, 27, 5, 0, 0, 0, time.UTC) },
	}

	code := b.Run(context.Background(), "boetticher host start-system octoprint --plan", "boetticher-agent", "claude-mac")
	if code != 0 {
		t.Fatalf("Run exit code = %d, want 0 (stderr=%s)", code, stderr.String())
	}
	if gotBinary != DefaultBoetticherBinary {
		t.Fatalf("executed binary = %q, want %q", gotBinary, DefaultBoetticherBinary)
	}
	wantArgs := []string{"host", "start-system", "octoprint", "--plan"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("executed args = %v, want %v", gotArgs, wantArgs)
	}

	var rec AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &rec); err != nil {
		t.Fatalf("invalid JSON audit record: %v (raw=%q)", err, audit.String())
	}
	if rec.Decision != "allow" || rec.Tier != "tier2" || rec.User != "boetticher-agent" || rec.KeyComment != "claude-mac" || rec.ExitCode != 0 {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
	if !reflect.DeepEqual(rec.Argv, []string{"boetticher", "host", "start-system", "octoprint", "--plan"}) {
		t.Fatalf("audit argv = %v", rec.Argv)
	}
}

func TestBrokerDeniesAndNeverExecutesOnSymlinkPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yml")
	if err := os.WriteFile(target, []byte("tier2:\n  system_power: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	executed := false
	var stderr, audit bytes.Buffer
	b := &Broker{
		PolicyPath: link,
		OwnerCheck: allowAnyOwner,
		Exec: func(_ context.Context, _ string, _ []string, _ io.Reader, _, _ io.Writer) (int, error) {
			executed = true
			return 0, nil
		},
		Stderr:   &stderr,
		AuditOut: &audit,
	}

	code := b.Run(context.Background(), "boetticher host status", "boetticher-agent", "")
	if code == 0 {
		t.Fatalf("expected non-zero exit code for symlinked policy")
	}
	if executed {
		t.Fatalf("executor must not run when policy file is a symlink")
	}
	var rec AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &rec); err != nil {
		t.Fatalf("invalid JSON audit record: %v", err)
	}
	if rec.Decision != "deny" || rec.ExitCode == 0 {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
}

func TestExecDirect(t *testing.T) {
	echoBin, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("echo not found in PATH")
	}
	falseBin, err := exec.LookPath("false")
	if err != nil {
		t.Skip("false not found in PATH")
	}

	var out, errOut bytes.Buffer
	code, err := ExecDirect(context.Background(), echoBin, []string{"hello", "world"}, strings.NewReader(""), &out, &errOut)
	if err != nil {
		t.Fatalf("ExecDirect error: %v", err)
	}
	if code != 0 || strings.TrimSpace(out.String()) != "hello world" {
		t.Fatalf("ExecDirect code=%d out=%q", code, out.String())
	}

	code, err = ExecDirect(context.Background(), falseBin, nil, strings.NewReader(""), &out, &errOut)
	if err == nil || code == 0 {
		t.Fatalf("expected non-zero exit for false, got code=%d err=%v", code, err)
	}
}
