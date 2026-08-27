package main

import (
	"fmt"

	"github.com/gofastercloud/boetticher/internal/cli"
)

func main() {
	fmt.Print(cli.CommandReferenceMarkdown())
}
