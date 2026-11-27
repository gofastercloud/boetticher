package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/agentbroker"
	"golang.org/x/crypto/ssh"
)

func generateTestEd25519PubKey(t *testing.T, comment string) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return line, ssh.FingerprintSHA256(sshPub)
}

func generateTestECDSAPubKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " ecdsa-agent"
}

func generateTestRSAPubKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " rsa-agent"
}

func TestValidateAgentSSHPublicKey(t *testing.T) {
	edKey, edFP := generateTestEd25519PubKey(t, "agent@macbook")
	ecdsaKey := generateTestECDSAPubKey(t)
	rsaKey := generateTestRSAPubKey(t)

	got, err := ValidateAgentSSHPublicKey(edKey)
	if err != nil {
		t.Fatalf("expected valid ed25519 key, got error: %v", err)
	}
	if got.Type != ssh.KeyAlgoED25519 || got.Fingerprint != edFP || got.Comment != "agent@macbook" {
		t.Fatalf("unexpected validated key: %+v", got)
	}

	if _, err := ValidateAgentSSHPublicKey(ecdsaKey); err != nil {
		t.Fatalf("expected valid ecdsa key, got error: %v", err)
	}
	if _, err := ValidateAgentSSHPublicKey(rsaKey); err != nil {
		t.Fatalf("expected valid rsa key, got error: %v", err)
	}

	invalidCases := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "whitespace only", raw: "   "},
		{name: "embedded options", raw: `command="/bin/sh" ` + edKey},
		{name: "restrict option embedded", raw: `restrict ` + edKey},
		{name: "newline injection", raw: edKey + "\n" + edKey},
		{name: "trailing newline", raw: edKey + "\n"},
		{name: "carriage return", raw: edKey + "\r"},
		{name: "control character in comment", raw: edKey + "\x07"},
		{name: "tab control char", raw: strings.Replace(edKey, " ", "\t", 1)},
		{name: "garbage key", raw: "ssh-ed25519 not-valid-base64!!!"},
		{name: "unsupported key type", raw: "ssh-dss AAAAB3NzaC1kc3MAAACBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAAAAFQCXYFCPFSMLzLKSuYKi64QL8Fgc9QAAAIEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoAAACBAKKW2Y2L6fY5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5Y5cW7G7H0B8cT6kL5"},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateAgentSSHPublicKey(tc.raw); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestAgentAccessPlanIsReadOnly(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "boetticher-agent")
	brokerPath := filepath.Join(tmp, "libexec", "boetticher-agent-broker")
	sudoersPath := filepath.Join(tmp, "sudoers.d", "boetticher-agent-broker")
	policyPath := filepath.Join(tmp, "etc", "agent-policy.yml")
	edKey, _ := generateTestEd25519PubKey(t, "agent@test")

	commandCalled := false
	opts := AgentAccessOptions{
		BrokerPath:       brokerPath,
		SudoersPath:      sudoersPath,
		PolicyPath:       policyPath,
		PolicyOwnerCheck: func(os.FileInfo) error { return nil },
		IsRoot:           func() bool { return false },
		LookupUser: func(string) (AgentUserInfo, bool, error) {
			return AgentUserInfo{}, false, nil
		},
		Command: func(context.Context, string, ...string) ([]byte, error) {
			commandCalled = true
			return nil, nil
		},
	}

	plan, err := PlanEnableAgentAccess(edKey, opts)
	if err != nil {
		t.Fatalf("PlanEnableAgentAccess failed: %v", err)
	}
	if !plan.HasChanges() {
		t.Fatalf("expected planned changes, got %+v", plan.Changes)
	}
	if commandCalled {
		t.Fatal("PlanEnableAgentAccess invoked an OS command")
	}
	for _, p := range []string{homeDir, sudoersPath, policyPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("PlanEnableAgentAccess mutated %s", p)
		}
	}

	disablePlan, err := PlanDisableAgentAccess(true, opts)
	if err != nil {
		t.Fatalf("PlanDisableAgentAccess failed: %v", err)
	}
	if disablePlan.HasChanges() {
		t.Fatalf("expected no disable changes when absent, got %+v", disablePlan.Changes)
	}
	if commandCalled {
		t.Fatal("PlanDisableAgentAccess invoked an OS command")
	}
}

func TestAgentAccessEnableStatusDisableLifecycle(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "boetticher-agent")
	brokerPath := filepath.Join(tmp, "libexec", "boetticher-agent-broker")
	sudoersPath := filepath.Join(tmp, "sudoers.d", "boetticher-agent-broker")
	policyPath := filepath.Join(tmp, "etc", "agent-policy.yml")

	if err := os.MkdirAll(filepath.Dir(brokerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(brokerPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	userCreated := false
	var recordedCmds [][]string
	edKey, edFP := generateTestEd25519PubKey(t, "agent@mac")

	opts := AgentAccessOptions{
		BrokerPath:       brokerPath,
		SudoersPath:      sudoersPath,
		PolicyPath:       policyPath,
		PolicyOwnerCheck: func(os.FileInfo) error { return nil },
		IsRoot:           func() bool { return true },
		Chown:            func(string, int, int) error { return nil },
		LookPath: func(name string) (string, error) {
			if name == "visudo" {
				return "/usr/sbin/visudo", nil
			}
			return "", exec.ErrNotFound
		},
		LookupUser: func(name string) (AgentUserInfo, bool, error) {
			if !userCreated {
				return AgentUserInfo{}, false, nil
			}
			return AgentUserInfo{Username: name, UID: 999, GID: 999, HomeDir: homeDir}, true, nil
		},
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			recordedCmds = append(recordedCmds, append([]string{name}, args...))
			if name == "useradd" {
				userCreated = true
				if err := os.MkdirAll(homeDir, 0o755); err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
	}

	// 1. Initial status: user absent, broker installed, nothing configured, policy defaults to read-only.
	st, err := InspectAgentAccess(opts)
	if err != nil {
		t.Fatalf("InspectAgentAccess initial failed: %v", err)
	}
	if st.UserExists || !st.BrokerInstalled || st.AuthorizedKeysConfigured || st.SudoersPresent || st.EffectivePolicy != "read-only" {
		t.Fatalf("unexpected initial status: %+v", st)
	}

	// 2. Enable creates user, writes authorized_keys (0600), sudoers (0440, validated via visudo), and policy (0644).
	if _, err := EnableAgentAccess(context.Background(), edKey, opts); err != nil {
		t.Fatalf("EnableAgentAccess failed: %v", err)
	}
	if !userCreated {
		t.Fatal("expected useradd to create user")
	}

	// Check recorded commands include useradd, passwd -l, and visudo -cf.
	var sawUseradd, sawPasswdLock, sawVisudo bool
	for _, cmd := range recordedCmds {
		joined := strings.Join(cmd, " ")
		if cmd[0] == "useradd" && strings.Contains(joined, "--system") {
			sawUseradd = true
		}
		if cmd[0] == "passwd" && len(cmd) >= 3 && cmd[1] == "-l" {
			sawPasswdLock = true
		}
		if cmd[0] == "/usr/sbin/visudo" && len(cmd) >= 3 && cmd[1] == "-cf" {
			sawVisudo = true
		}
	}
	if !sawUseradd || !sawPasswdLock || !sawVisudo {
		t.Fatalf("expected useradd, passwd -l, and visudo -cf; got %v", recordedCmds)
	}

	// Verify authorized_keys content and mode 0600.
	authKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	authInfo, err := os.Stat(authKeysPath)
	if err != nil {
		t.Fatalf("stat authorized_keys: %v", err)
	}
	if authInfo.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys mode = %04o, want 0600", authInfo.Mode().Perm())
	}
	authBytes, err := os.ReadFile(authKeysPath)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := `restrict,command="` + brokerPath + `" `
	if !strings.HasPrefix(string(authBytes), wantPrefix) {
		t.Fatalf("authorized_keys content = %q, want prefix %q", string(authBytes), wantPrefix)
	}

	// Verify sudoers content and mode 0440.
	sudoInfo, err := os.Stat(sudoersPath)
	if err != nil {
		t.Fatalf("stat sudoers: %v", err)
	}
	if sudoInfo.Mode().Perm() != 0o440 {
		t.Fatalf("sudoers mode = %04o, want 0440", sudoInfo.Mode().Perm())
	}
	sudoBytes, err := os.ReadFile(sudoersPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sudoBytes), "boetticher-agent ALL=(root) NOPASSWD: "+brokerPath) {
		t.Fatalf("sudoers content missing narrow rule: %s", string(sudoBytes))
	}

	// Verify policy file created with 0644 and parseable by agentbroker.LoadPolicy.
	polInfo, err := os.Stat(policyPath)
	if err != nil {
		t.Fatalf("stat policy: %v", err)
	}
	if polInfo.Mode().Perm() != 0o644 {
		t.Fatalf("policy mode = %04o, want 0644", polInfo.Mode().Perm())
	}
	pol, err := agentbroker.LoadPolicy(policyPath, opts.PolicyOwnerCheck)
	if err != nil {
		t.Fatalf("agentbroker.LoadPolicy failed on generated default policy: %v", err)
	}
	if pol.Tier2.SystemPower || pol.Tier2.FirewallTest || pol.Tier2.DNSRecords || pol.Tier2.DHCPReservations || len(pol.Tier2.ModuleApply) != 0 {
		t.Fatalf("default policy is not read-only: %+v", pol)
	}

	// 3. Status after enable reports everything configured with fingerprint and comment.
	st, err = InspectAgentAccess(opts)
	if err != nil {
		t.Fatalf("InspectAgentAccess after enable failed: %v", err)
	}
	if !st.UserExists || !st.BrokerInstalled || !st.AuthorizedKeysConfigured || !st.SudoersPresent {
		t.Fatalf("expected all configured after enable: %+v", st)
	}
	if st.KeyFingerprint != edFP || st.KeyComment != "agent@mac" || st.EffectivePolicy != "read-only" {
		t.Fatalf("unexpected status details: %+v", st)
	}

	// 4. Re-enabling preserves custom existing policy file.
	customPolicy := "tier2:\n  system_power: true\n"
	if err := os.WriteFile(policyPath, []byte(customPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableAgentAccess(context.Background(), edKey, opts); err != nil {
		t.Fatalf("re-enable failed: %v", err)
	}
	gotPolicyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPolicyBytes) != customPolicy {
		t.Fatalf("re-enable overwrote existing policy: got %q", string(gotPolicyBytes))
	}
	st, err = InspectAgentAccess(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st.EffectivePolicy, "system_power") {
		t.Fatalf("expected effective policy to mention system_power, got %q", st.EffectivePolicy)
	}

	// 5. Disable without --purge-policy removes authorized_keys and sudoers, preserves policy.
	if _, err := DisableAgentAccess(context.Background(), false, opts); err != nil {
		t.Fatalf("DisableAgentAccess failed: %v", err)
	}
	if _, err := os.Stat(authKeysPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("authorized_keys still present after disable: %v", err)
	}
	if _, err := os.Stat(sudoersPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sudoers still present after disable: %v", err)
	}
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("policy should be preserved without --purge-policy: %v", err)
	}

	// 6. Disable with --purge-policy removes policy file too.
	if _, err := DisableAgentAccess(context.Background(), true, opts); err != nil {
		t.Fatalf("DisableAgentAccess --purge-policy failed: %v", err)
	}
	if _, err := os.Stat(policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy still present after --purge-policy: %v", err)
	}
}

func TestEnableFailsCleanlyWhenVisudoRejects(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "boetticher-agent")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sudoersPath := filepath.Join(tmp, "sudoers.d", "boetticher-agent-broker")
	policyPath := filepath.Join(tmp, "etc", "agent-policy.yml")
	edKey, _ := generateTestEd25519PubKey(t, "agent@visudo")

	opts := AgentAccessOptions{
		BrokerPath:       filepath.Join(tmp, "broker"),
		SudoersPath:      sudoersPath,
		PolicyPath:       policyPath,
		PolicyOwnerCheck: func(os.FileInfo) error { return nil },
		IsRoot:           func() bool { return true },
		Chown:            func(string, int, int) error { return nil },
		LookupUser: func(name string) (AgentUserInfo, bool, error) {
			return AgentUserInfo{Username: name, UID: 999, GID: 999, HomeDir: homeDir}, true, nil
		},
		LookPath: func(name string) (string, error) {
			return "/usr/sbin/visudo", nil
		},
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "/usr/sbin/visudo" {
				return []byte("syntax error"), errors.New("exit status 1")
			}
			return nil, nil
		},
	}

	if _, err := EnableAgentAccess(context.Background(), edKey, opts); err == nil {
		t.Fatal("expected visudo failure to abort enable")
	}
	if _, err := os.Stat(sudoersPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sudoers file must not be installed when visudo fails: %v", err)
	}
}
