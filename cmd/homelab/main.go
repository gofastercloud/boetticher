package main

import (
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "homelab:", err)
		os.Exit(1)
	}
}
