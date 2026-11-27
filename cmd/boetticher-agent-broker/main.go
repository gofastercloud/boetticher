package main

import (
	"context"
	"io"
	"os"

	"github.com/gofastercloud/boetticher/internal/agentbroker"
)

func main() {
	os.Exit(run(
		context.Background(),
		os.Getenv,
		os.Stdin,
		os.Stdout,
		os.Stderr,
		os.Stderr,
		agentbroker.DefaultBoetticherBinary,
		agentbroker.DefaultPolicyPath,
		agentbroker.DefaultOwnerCheck,
		agentbroker.ExecDirect,
	))
}

func run(
	ctx context.Context,
	getenv func(string) string,
	stdin io.Reader,
	stdout, stderr, auditOut io.Writer,
	binary, policyPath string,
	ownerCheck agentbroker.OwnerCheckFunc,
	execFn agentbroker.Executor,
) int {
	user := getenv("SUDO_USER")
	if user == "" {
		user = getenv("USER")
	}
	keyComment := getenv("BOETTICHER_AGENT_KEY_COMMENT")
	broker := &agentbroker.Broker{
		Binary:     binary,
		PolicyPath: policyPath,
		OwnerCheck: ownerCheck,
		Exec:       execFn,
		Stdin:      stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		AuditOut:   auditOut,
	}
	return broker.Run(ctx, getenv("SSH_ORIGINAL_COMMAND"), user, keyComment)
}
