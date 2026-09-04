// Command local-builder-archive is maintainer-only plumbing for the native
// image builder. It is not part of the installed Boetticher operator CLI.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gofastercloud/boetticher/internal/artifacts"
)

func main() {
	mode := flag.String("mode", "", "archive mode: source or output")
	root := flag.String("root", "", "destination root for output mode")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("unexpected positional argument")
	}

	switch *mode {
	case "source":
		if *root == "" {
			fatal("source mode requires -root")
		}
		archive, err := artifacts.BuildSourceArchive(*root)
		if err != nil {
			fatal("build source archive: %v", err)
		}
		if _, err := os.Stdout.Write(archive); err != nil {
			fatal("write source archive: %v", err)
		}
	case "output":
		if *root == "" {
			fatal("output mode requires -root")
		}
		if err := artifacts.ExtractNativeBuilderOutputReader(os.Stdin, *root); err != nil {
			fatal("extract native builder output: %v", err)
		}
	default:
		fatal("usage: local-builder-archive -mode source -root CHECKOUT or -mode output -root CHECKOUT")
	}
}

func fatal(format string, args ...any) {
	if _, err := fmt.Fprintf(os.Stderr, format+"\n", args...); err != nil {
		_, _ = io.WriteString(os.Stderr, "local builder archive failed\n")
	}
	os.Exit(1)
}
