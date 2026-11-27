package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gofastercloud/boetticher/internal/agentlab"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	err := agentlab.Run(args, agentlab.Options{
		Stdin:  os.Stdin,
		Stdout: stdout,
		Stderr: stderr,
	})
	if err == nil {
		return 0
	}
	var exitErr agentlab.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	fmt.Fprintln(stderr, "agent-lab:", err)
	return 1
}
