package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/agentbroker"
	"golang.org/x/crypto/ssh"
)

const (
	AgentAccessUser  = "boetticher-agent"
	AgentBrokerPath  = "/usr/local/libexec/boetticher-agent-broker"
	AgentSudoersPath = "/etc/sudoers.d/boetticher-agent-broker"
	AgentPolicyPath  = agentbroker.DefaultPolicyPath
)

const defaultAgentPolicyYAML = `# Managed by boetticher controller agent-access
# Default policy: Tier 1 read-only commands only.
tier2:
  system_power: false
  firewall_test: false
  dns_records: false
  dhcp_reservations: false
  module_apply: []
`

// AgentUserInfo describes the dedicated local agent system account.
type AgentUserInfo struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
}

// ValidatedSSHKey holds a strictly validated SSH public key and its non-secret metadata.
type ValidatedSSHKey struct {
	Type         string
	Fingerprint  string
	Comment      string
	CanonicalKey string
}

// AgentAccessOptions configures paths and injectable OS runners for agent access operations.
type AgentAccessOptions struct {
	User             string
	BrokerPath       string
	SudoersPath      string
	PolicyPath       string
	LookupUser       func(string) (AgentUserInfo, bool, error)
	Command          func(context.Context, string, ...string) ([]byte, error)
	LookPath         func(string) (string, error)
	PolicyOwnerCheck agentbroker.OwnerCheckFunc
	IsRoot           func() bool
	Chown            func(string, int, int) error
}

// AgentAccessStatus is the read-only snapshot of local agent SSH access state.
type AgentAccessStatus struct {
	User                     string
	UserExists               bool
	UserHomeDir              string
	BrokerPath               string
	BrokerInstalled          bool
	AuthorizedKeysPath       string
	AuthorizedKeysConfigured bool
	AuthorizedKeysError      string
	KeyType                  string
	KeyFingerprint           string
	KeyComment               string
	SudoersPath              string
	SudoersPresent           bool
	SudoersError             string
	PolicyPath               string
	PolicyFileExists         bool
	Policy                   agentbroker.Policy
	EffectivePolicy          string
	PolicyError              string
}

// AgentAccessChange describes one planned or executed state transition.
type AgentAccessChange struct {
	Target string
	Action string // create, update, remove, preserve, noop
	Detail string
}

// AgentAccessPlan holds the previewed changes for enable or disable.
type AgentAccessPlan struct {
	Changes []AgentAccessChange
	Key     ValidatedSSHKey
}

// HasChanges reports whether the plan contains any mutating action.
func (p AgentAccessPlan) HasChanges() bool {
	for _, c := range p.Changes {
		if c.Action == "create" || c.Action == "update" || c.Action == "remove" {
			return true
		}
	}
	return false
}

func normalizeAgentAccessOptions(opts AgentAccessOptions) AgentAccessOptions {
	if opts.User == "" {
		opts.User = AgentAccessUser
	}
	if opts.BrokerPath == "" {
		opts.BrokerPath = AgentBrokerPath
	}
	if opts.SudoersPath == "" {
		opts.SudoersPath = AgentSudoersPath
	}
	if opts.PolicyPath == "" {
		opts.PolicyPath = AgentPolicyPath
	}
	if opts.LookupUser == nil {
		opts.LookupUser = defaultLookupAgentUser
	}
	if opts.Command == nil {
		opts.Command = defaultCombinedCommand
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.PolicyOwnerCheck == nil {
		opts.PolicyOwnerCheck = agentbroker.DefaultOwnerCheck
	}
	if opts.IsRoot == nil {
		opts.IsRoot = func() bool { return os.Geteuid() == 0 }
	}
	if opts.Chown == nil {
		opts.Chown = os.Chown
	}
	return opts
}

func defaultLookupAgentUser(name string) (AgentUserInfo, bool, error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return AgentUserInfo{}, false, nil
		}
		return AgentUserInfo{}, false, fmt.Errorf("lookup user %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return AgentUserInfo{}, false, fmt.Errorf("parse uid for %q: %w", name, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return AgentUserInfo{}, false, fmt.Errorf("parse gid for %q: %w", name, err)
	}
	return AgentUserInfo{
		Username: u.Username,
		UID:      uid,
		GID:      gid,
		HomeDir:  u.HomeDir,
	}, true, nil
}

func defaultCombinedCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// ValidateAgentSSHPublicKey strictly validates a single-line SSH public key.
// Only ed25519, ecdsa, and rsa keys without embedded options or control characters are accepted.
func ValidateAgentSSHPublicKey(raw string) (ValidatedSSHKey, error) {
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return ValidatedSSHKey{}, errors.New("SSH public key must be a single line without newlines or control characters")
		}
	}
	trimmed := strings.Trim(raw, " ")
	if trimmed == "" {
		return ValidatedSSHKey{}, errors.New("SSH public key is required")
	}

	pubKey, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return ValidatedSSHKey{}, fmt.Errorf("invalid SSH public key: %w", err)
	}
	if len(options) > 0 {
		return ValidatedSSHKey{}, errors.New("SSH public key must not contain embedded authorized_keys options")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return ValidatedSSHKey{}, errors.New("SSH public key must contain a single key")
	}

	switch pubKey.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
	default:
		return ValidatedSSHKey{}, fmt.Errorf("unsupported SSH key type %q (allowed: ed25519, ecdsa, rsa)", pubKey.Type())
	}

	fields := strings.Fields(trimmed)
	if len(fields) < 2 || fields[0] != pubKey.Type() {
		return ValidatedSSHKey{}, errors.New("SSH public key must begin with its key algorithm")
	}

	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	cleanComment := strings.TrimSpace(comment)
	if cleanComment != "" {
		canonical += " " + cleanComment
	}

	return ValidatedSSHKey{
		Type:         pubKey.Type(),
		Fingerprint:  ssh.FingerprintSHA256(pubKey),
		Comment:      cleanComment,
		CanonicalKey: canonical,
	}, nil
}

func renderAuthorizedKeysLine(brokerPath string, key ValidatedSSHKey) string {
	return fmt.Sprintf("restrict,command=%q %s\n", brokerPath, key.CanonicalKey)
}

func renderSudoersContent(userName, brokerPath string) string {
	return fmt.Sprintf(
		"# Managed by boetticher controller agent-access\n"+
			"Defaults:%s !requiretty\n"+
			"Defaults:%s env_keep += \"SSH_ORIGINAL_COMMAND\"\n"+
			"%s ALL=(root) NOPASSWD: %s\n",
		userName, userName, userName, brokerPath,
	)
}

func formatEffectivePolicy(policy agentbroker.Policy) string {
	var tier2 []string
	if policy.Tier2.SystemPower {
		tier2 = append(tier2, "system_power")
	}
	if policy.Tier2.FirewallTest {
		tier2 = append(tier2, "firewall_test")
	}
	if policy.Tier2.DNSRecords {
		tier2 = append(tier2, "dns_records")
	}
	if policy.Tier2.DHCPReservations {
		tier2 = append(tier2, "dhcp_reservations")
	}
	if len(policy.Tier2.ModuleApply) > 0 {
		tier2 = append(tier2, "module_apply=["+strings.Join(policy.Tier2.ModuleApply, ",")+"]")
	}
	if len(tier2) == 0 {
		return "read-only"
	}
	return "read-only + tier2 (" + strings.Join(tier2, ", ") + ")"
}

// InspectAgentAccess reads local agent SSH access configuration without making any changes.
func InspectAgentAccess(options AgentAccessOptions) (AgentAccessStatus, error) {
	opts := normalizeAgentAccessOptions(options)
	status := AgentAccessStatus{
		User:        opts.User,
		BrokerPath:  opts.BrokerPath,
		SudoersPath: opts.SudoersPath,
		PolicyPath:  opts.PolicyPath,
	}

	userInfo, exists, err := opts.LookupUser(opts.User)
	if err != nil {
		return status, err
	}
	status.UserExists = exists
	status.UserHomeDir = userInfo.HomeDir
	if exists && userInfo.HomeDir != "" {
		status.AuthorizedKeysPath = filepath.Join(userInfo.HomeDir, ".ssh", "authorized_keys")
	} else {
		status.AuthorizedKeysPath = fmt.Sprintf("~%s/.ssh/authorized_keys", opts.User)
	}

	if info, err := os.Stat(opts.BrokerPath); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
		status.BrokerInstalled = true
	}

	if exists && userInfo.HomeDir != "" {
		inspectAuthorizedKeys(&status, opts.BrokerPath)
	}

	inspectSudoers(&status)
	inspectPolicy(&status, opts.PolicyOwnerCheck)

	return status, nil
}

func inspectAuthorizedKeys(status *AgentAccessStatus, brokerPath string) {
	linfo, err := os.Lstat(status.AuthorizedKeysPath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			status.AuthorizedKeysError = "unreadable (requires root)"
		} else {
			status.AuthorizedKeysError = err.Error()
		}
		return
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		status.AuthorizedKeysError = "refusing symlink"
		return
	}
	data, err := os.ReadFile(status.AuthorizedKeysPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			status.AuthorizedKeysError = "unreadable (requires root)"
		} else {
			status.AuthorizedKeysError = err.Error()
		}
		return
	}

	wantCmd := fmt.Sprintf("command=%q", brokerPath)
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pubKey, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			status.AuthorizedKeysError = "malformed authorized_keys entry"
			return
		}
		var hasRestrict, hasCommand bool
		for _, opt := range options {
			if opt == "restrict" {
				hasRestrict = true
			}
			if opt == wantCmd {
				hasCommand = true
			}
		}
		if hasRestrict && hasCommand {
			status.AuthorizedKeysConfigured = true
			status.KeyType = pubKey.Type()
			status.KeyFingerprint = ssh.FingerprintSHA256(pubKey)
			status.KeyComment = strings.TrimSpace(comment)
			return
		}
		status.AuthorizedKeysError = "present but missing required restrict forced-command option"
		return
	}
}

func inspectSudoers(status *AgentAccessStatus) {
	linfo, err := os.Lstat(status.SudoersPath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			status.SudoersError = "unreadable (requires root)"
		} else {
			status.SudoersError = err.Error()
		}
		return
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		status.SudoersError = "refusing symlink"
		return
	}
	status.SudoersPresent = true
}

func inspectPolicy(status *AgentAccessStatus, ownerCheck agentbroker.OwnerCheckFunc) {
	if _, err := os.Lstat(status.PolicyPath); err == nil {
		status.PolicyFileExists = true
	}
	policy, err := agentbroker.LoadPolicy(status.PolicyPath, ownerCheck)
	if err != nil {
		status.PolicyError = err.Error()
		status.EffectivePolicy = "invalid"
		return
	}
	status.Policy = policy
	status.EffectivePolicy = formatEffectivePolicy(policy)
}

// PlanEnableAgentAccess computes the read-only change preview for enabling agent access.
func PlanEnableAgentAccess(rawKey string, options AgentAccessOptions) (AgentAccessPlan, error) {
	opts := normalizeAgentAccessOptions(options)
	key, err := ValidateAgentSSHPublicKey(rawKey)
	if err != nil {
		return AgentAccessPlan{}, err
	}
	status, err := InspectAgentAccess(opts)
	if err != nil {
		return AgentAccessPlan{}, err
	}

	plan := AgentAccessPlan{Key: key}

	if !status.UserExists {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: opts.User,
			Action: "create",
			Detail: "create locked-password system user",
		})
	} else {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: opts.User,
			Action: "noop",
			Detail: "system user already exists",
		})
	}

	desiredAuth := renderAuthorizedKeysLine(opts.BrokerPath, key)
	if !status.UserExists {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: status.AuthorizedKeysPath,
			Action: "create",
			Detail: fmt.Sprintf("write 0600 forced-command authorized_keys (%s)", key.Fingerprint),
		})
	} else {
		action := plannedFileAction(status.AuthorizedKeysPath, []byte(desiredAuth), 0o600)
		detail := fmt.Sprintf("write 0600 forced-command authorized_keys (%s)", key.Fingerprint)
		if action == "noop" {
			detail = fmt.Sprintf("already configured (%s)", key.Fingerprint)
		}
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: status.AuthorizedKeysPath,
			Action: action,
			Detail: detail,
		})
	}

	desiredSudoers := renderSudoersContent(opts.User, opts.BrokerPath)
	sudoAction := plannedFileAction(opts.SudoersPath, []byte(desiredSudoers), 0o440)
	sudoDetail := fmt.Sprintf("write 0440 narrow NOPASSWD rule for %s", opts.BrokerPath)
	if sudoAction == "noop" {
		sudoDetail = "already configured"
	}
	plan.Changes = append(plan.Changes, AgentAccessChange{
		Target: opts.SudoersPath,
		Action: sudoAction,
		Detail: sudoDetail,
	})

	if !status.PolicyFileExists {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: opts.PolicyPath,
			Action: "create",
			Detail: "write 0644 default read-only agent policy",
		})
	} else {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: opts.PolicyPath,
			Action: "preserve",
			Detail: "preserve existing policy file",
		})
	}

	return plan, nil
}

// EnableAgentAccess creates the system user if needed and writes authorized_keys,
// sudoers (validated via visudo -cf when available), and default read-only policy if absent.
func EnableAgentAccess(ctx context.Context, rawKey string, options AgentAccessOptions) (AgentAccessPlan, error) {
	opts := normalizeAgentAccessOptions(options)
	key, err := ValidateAgentSSHPublicKey(rawKey)
	if err != nil {
		return AgentAccessPlan{}, err
	}
	if !opts.IsRoot() {
		return AgentAccessPlan{}, errors.New("controller agent-access enable requires root; run it with sudo")
	}

	plan, err := PlanEnableAgentAccess(rawKey, opts)
	if err != nil {
		return AgentAccessPlan{}, err
	}

	userInfo, exists, err := opts.LookupUser(opts.User)
	if err != nil {
		return AgentAccessPlan{}, err
	}
	if !exists {
		if out, err := opts.Command(ctx, "useradd", "--system", "--create-home", "--shell", "/bin/sh", opts.User); err != nil {
			return AgentAccessPlan{}, fmt.Errorf("create system user %q: %w (%s)", opts.User, err, strings.TrimSpace(string(out)))
		}
		if out, err := opts.Command(ctx, "passwd", "-l", opts.User); err != nil {
			return AgentAccessPlan{}, fmt.Errorf("lock password for %q: %w (%s)", opts.User, err, strings.TrimSpace(string(out)))
		}
		userInfo, exists, err = opts.LookupUser(opts.User)
		if err != nil {
			return AgentAccessPlan{}, err
		}
		if !exists || userInfo.HomeDir == "" {
			return AgentAccessPlan{}, fmt.Errorf("user %q was created but could not be resolved", opts.User)
		}
	}

	sshDir := filepath.Join(userInfo.HomeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return AgentAccessPlan{}, fmt.Errorf("create %s: %w", sshDir, err)
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return AgentAccessPlan{}, fmt.Errorf("chmod %s: %w", sshDir, err)
	}
	if err := opts.Chown(sshDir, userInfo.UID, userInfo.GID); err != nil {
		return AgentAccessPlan{}, fmt.Errorf("chown %s: %w", sshDir, err)
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	authContent := []byte(renderAuthorizedKeysLine(opts.BrokerPath, key))
	if err := writeAgentFileAtomic(authKeysPath, authContent, 0o600, userInfo.UID, userInfo.GID, opts.Chown, nil); err != nil {
		return AgentAccessPlan{}, fmt.Errorf("write %s: %w", authKeysPath, err)
	}

	sudoersContent := []byte(renderSudoersContent(opts.User, opts.BrokerPath))
	validateSudoers := func(tmpPath string) error {
		visudoPath, err := opts.LookPath("visudo")
		if err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				return nil
			}
			return nil
		}
		if out, err := opts.Command(ctx, visudoPath, "-cf", tmpPath); err != nil {
			return fmt.Errorf("visudo validation failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := writeAgentFileAtomic(opts.SudoersPath, sudoersContent, 0o440, 0, 0, opts.Chown, validateSudoers); err != nil {
		return AgentAccessPlan{}, fmt.Errorf("write %s: %w", opts.SudoersPath, err)
	}

	if _, err := os.Lstat(opts.PolicyPath); errors.Is(err, os.ErrNotExist) {
		if err := writeAgentFileAtomic(opts.PolicyPath, []byte(defaultAgentPolicyYAML), 0o644, 0, 0, opts.Chown, nil); err != nil {
			return AgentAccessPlan{}, fmt.Errorf("write %s: %w", opts.PolicyPath, err)
		}
	}

	return plan, nil
}

// PlanDisableAgentAccess computes the read-only change preview for revoking agent access.
func PlanDisableAgentAccess(purgePolicy bool, options AgentAccessOptions) (AgentAccessPlan, error) {
	opts := normalizeAgentAccessOptions(options)
	status, err := InspectAgentAccess(opts)
	if err != nil {
		return AgentAccessPlan{}, err
	}

	var plan AgentAccessPlan

	if status.UserExists && pathExists(status.AuthorizedKeysPath) {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: status.AuthorizedKeysPath,
			Action: "remove",
			Detail: "remove forced-command authorized_keys",
		})
	} else {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: status.AuthorizedKeysPath,
			Action: "noop",
			Detail: "already absent",
		})
	}

	if pathExists(opts.SudoersPath) {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: opts.SudoersPath,
			Action: "remove",
			Detail: "remove broker sudoers rule",
		})
	} else {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: opts.SudoersPath,
			Action: "noop",
			Detail: "already absent",
		})
	}

	if status.PolicyFileExists {
		if purgePolicy {
			plan.Changes = append(plan.Changes, AgentAccessChange{
				Target: opts.PolicyPath,
				Action: "remove",
				Detail: "remove agent policy (--purge-policy)",
			})
		} else {
			plan.Changes = append(plan.Changes, AgentAccessChange{
				Target: opts.PolicyPath,
				Action: "preserve",
				Detail: "preserve policy file (pass --purge-policy to remove)",
			})
		}
	} else {
		plan.Changes = append(plan.Changes, AgentAccessChange{
			Target: opts.PolicyPath,
			Action: "noop",
			Detail: "already absent",
		})
	}

	return plan, nil
}

// DisableAgentAccess immediately revokes agent SSH access by removing authorized_keys
// and the broker sudoers file, preserving agent-policy.yml unless purgePolicy is true.
func DisableAgentAccess(_ context.Context, purgePolicy bool, options AgentAccessOptions) (AgentAccessPlan, error) {
	opts := normalizeAgentAccessOptions(options)
	if !opts.IsRoot() {
		return AgentAccessPlan{}, errors.New("controller agent-access disable requires root; run it with sudo")
	}

	plan, err := PlanDisableAgentAccess(purgePolicy, opts)
	if err != nil {
		return AgentAccessPlan{}, err
	}

	userInfo, exists, err := opts.LookupUser(opts.User)
	if err != nil {
		return AgentAccessPlan{}, err
	}
	if exists && userInfo.HomeDir != "" {
		authKeysPath := filepath.Join(userInfo.HomeDir, ".ssh", "authorized_keys")
		if err := os.Remove(authKeysPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return AgentAccessPlan{}, fmt.Errorf("remove %s: %w", authKeysPath, err)
		}
	}

	if err := os.Remove(opts.SudoersPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return AgentAccessPlan{}, fmt.Errorf("remove %s: %w", opts.SudoersPath, err)
	}

	if purgePolicy {
		if err := os.Remove(opts.PolicyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return AgentAccessPlan{}, fmt.Errorf("remove %s: %w", opts.PolicyPath, err)
		}
	}

	return plan, nil
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func plannedFileAction(path string, desired []byte, perm os.FileMode) string {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "create"
	}
	if err != nil {
		return "update"
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != perm {
		return "update"
	}
	existing, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(existing, desired) {
		return "update"
	}
	return "noop"
}

func writeAgentFileAtomic(
	path string,
	data []byte,
	perm os.FileMode,
	uid, gid int,
	chownFn func(string, int, int) error,
	validate func(tmpPath string) error,
) error {
	if linfo, err := os.Lstat(path); err == nil {
		if linfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".boetticher-agent-access-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if chownFn != nil {
		if err := chownFn(tmpPath, uid, gid); err != nil {
			return err
		}
	}
	if validate != nil {
		if err := validate(tmpPath); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	renamed = true
	return nil
}
