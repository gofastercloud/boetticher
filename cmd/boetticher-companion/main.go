package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/companion"
)

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if len(os.Args) == 2 && os.Args[1] == "ready" {
		for i := 0; i < 30; i++ {
			if _, err := companion.ReadSnapshot(ctx, companion.LocalClient()); err == nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		return fmt.Errorf("local Companion service did not become ready")
	}
	if len(os.Args) == 2 && os.Args[1] == "status" {
		snapshot, err := companion.ReadSnapshot(ctx, companion.LocalClient())
		if err != nil {
			return err
		}
		if err = json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
			return err
		}
		return companion.Check(snapshot)
	}
	if len(os.Args) != 1 {
		return fmt.Errorf("usage: boetticher-companion [status]")
	}
	config, err := companion.LoadConfig(companion.ConfigPath)
	if err != nil {
		return err
	}
	credentialDir := os.Getenv("CREDENTIALS_DIRECTORY")
	if credentialDir == "" {
		return fmt.Errorf("missing credential directory")
	}
	token, err := os.ReadFile(filepath.Join(credentialDir, "pulse-token"))
	if err != nil {
		return err
	}
	state := companion.NewState(config)
	collector, err := companion.NewCollector(config, state, strings.TrimSpace(string(token)))
	if err != nil {
		return err
	}
	collector.Run(ctx)
	return companion.Serve(ctx, state)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
