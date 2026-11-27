package agentbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

const (
	// DefaultBoetticherBinary is the fixed boetticher binary executed directly
	// via execve without invoking a shell.
	DefaultBoetticherBinary = "/usr/local/bin/boetticher"

	exitCodeDenied = 126
)

// AuditRecord is emitted as one JSON line per broker invocation.
type AuditRecord struct {
	Timestamp  string   `json:"timestamp"`
	User       string   `json:"user,omitempty"`
	KeyComment string   `json:"key_comment,omitempty"`
	Argv       []string `json:"argv"`
	Decision   string   `json:"decision"`
	Tier       string   `json:"tier,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	ExitCode   int      `json:"exit_code"`
	DurationMS int64    `json:"duration_ms"`
}

// Executor runs the target binary directly with argv (never via a shell).
type Executor func(ctx context.Context, binary string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error)

// ExecDirect executes binary directly via os/exec (execve, never sh -c).
func ExecDirect(ctx context.Context, binary string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return exitCodeDenied, err
}

// Broker evaluates SSH_ORIGINAL_COMMAND against policy, executes the target
// boetticher binary directly, and writes a structured JSON audit record.
type Broker struct {
	Binary     string
	PolicyPath string
	OwnerCheck OwnerCheckFunc
	Exec       Executor
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	AuditOut   io.Writer
	Now        func() time.Time
}

// Run parses rawCommand, loads policy, evaluates access, executes on allow,
// writes one JSON audit record, and returns the process exit code.
func (b *Broker) Run(ctx context.Context, rawCommand, user, keyComment string) int {
	nowFn := b.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	start := nowFn()

	binary := b.Binary
	if binary == "" {
		binary = DefaultBoetticherBinary
	}
	execFn := b.Exec
	if execFn == nil {
		execFn = ExecDirect
	}
	stderr := b.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	auditOut := b.AuditOut
	if auditOut == nil {
		auditOut = stderr
	}

	emit := func(argv []string, decision, tier, reason string, exitCode int) int {
		elapsed := nowFn().Sub(start).Milliseconds()
		if elapsed < 0 {
			elapsed = 0
		}
		rec := AuditRecord{
			Timestamp:  start.UTC().Format(time.RFC3339Nano),
			User:       user,
			KeyComment: keyComment,
			Argv:       argv,
			Decision:   decision,
			Tier:       tier,
			Reason:     reason,
			ExitCode:   exitCode,
			DurationMS: elapsed,
		}
		if encoded, err := json.Marshal(rec); err == nil {
			_, _ = auditOut.Write(append(encoded, '\n'))
		}
		return exitCode
	}

	argv, err := ParseCommand(rawCommand)
	if err != nil {
		fmt.Fprintf(stderr, "boetticher-agent-broker: denied: %v\n", err)
		return emit(nil, "deny", "deny", err.Error(), exitCodeDenied)
	}

	policy, err := LoadPolicy(b.PolicyPath, b.OwnerCheck)
	if err != nil {
		fmt.Fprintf(stderr, "boetticher-agent-broker: denied: %v\n", err)
		return emit(argv, "deny", "deny", err.Error(), exitCodeDenied)
	}

	decision := Evaluate(argv, policy)
	if !decision.Allowed {
		fmt.Fprintf(stderr, "boetticher-agent-broker: denied: %s\n", decision.Reason)
		return emit(argv, "deny", decision.Tier, decision.Reason, exitCodeDenied)
	}

	exitCode, execErr := execFn(ctx, binary, argv[1:], b.Stdin, b.Stdout, stderr)
	reason := decision.Reason
	if execErr != nil && reason == "" {
		reason = execErr.Error()
	}
	return emit(argv, "allow", decision.Tier, reason, exitCode)
}
