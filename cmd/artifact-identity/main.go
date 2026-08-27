package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/artifacts"
)

func main() {
	module := flag.String("module", "", "built-in artifact module name")
	provider := flag.String("provider", "", "optional typed module provider")
	flag.Parse()
	if *module == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: artifact-identity -module NAME [-provider NAME]")
		os.Exit(2)
	}
	artifact, err := artifacts.ArtifactFor(*module, *provider)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(artifact); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
