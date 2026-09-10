package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/observability"
)

func runObservabilitySecrets(args []string, yes bool, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module observability secrets list|set|remove NAME [--yes]")
	}
	store := observability.SecretStore{}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: boetticher module observability secrets list")
		}
		config, err := loadLabConfig()
		if err != nil {
			return err
		}
		present, err := store.Load()
		if err != nil {
			return err
		}
		names := observability.RequiredSecretNames(config.Modules)
		sort.Strings(names)
		fmt.Fprintln(out, "Module observability secrets\nNAME\tSTATUS")
		for _, name := range names {
			status := "FAIL missing"
			if len(present[name]) != 0 {
				status = "PASS present"
			}
			fmt.Fprintf(out, "%s\t%s\n", name, status)
		}
		return nil
	case "set":
		if len(args) != 2 {
			return errors.New("usage: boetticher module observability secrets set NAME")
		}
		if input == nil {
			return errors.New("secret value must be supplied on standard input")
		}
		value, err := io.ReadAll(io.LimitReader(input, 64*1024+1))
		if err != nil {
			return err
		}
		value = []byte(strings.TrimSuffix(string(value), "\n"))
		if err := store.Set(args[1], value); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: stored\n", args[1])
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: boetticher module observability secrets remove NAME --yes")
		}
		if !yes {
			return errors.New("secret removal requires --yes")
		}
		changed, err := store.Remove(args[1])
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintf(out, "%s: removed\n", args[1])
		} else {
			fmt.Fprintf(out, "%s: already absent\n", args[1])
		}
		return nil
	case "rotate":
		if len(args) != 2 || args[1] != "grafana-password" {
			return errors.New("usage: boetticher module observability secrets rotate grafana-password --yes")
		}
		if !yes {
			return errors.New("Grafana password rotation requires --yes")
		}
		if input == nil {
			return errors.New("replacement Grafana password must be supplied on standard input")
		}
		current, err := store.Load()
		if err != nil {
			return err
		}
		old, found := current["grafana-admin-password"]
		if !found || len(old) == 0 {
			return errors.New("current Grafana password is absent from the protected store")
		}
		replacement, err := io.ReadAll(io.LimitReader(input, 64*1024+1))
		if err != nil {
			return err
		}
		replacement = []byte(strings.TrimSuffix(string(replacement), "\n"))
		if len(replacement) == 0 || len(replacement) > 64*1024 {
			return errors.New("replacement Grafana password is invalid")
		}
		config, err := loadLabConfig()
		if err != nil {
			return err
		}
		transport, err := observabilityTransport(config)
		if err != nil {
			return err
		}
		binding, _ := observability.BindingFor("observability")
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err := (observability.HostClient{Transport: transport}).RotateGrafanaPassword(ctx, binding, old, replacement); err != nil {
			return err
		}
		if err := store.Set("grafana-admin-password", replacement); err != nil {
			return fmt.Errorf("Grafana password changed but protected-store update failed: %w", err)
		}
		fmt.Fprintln(out, "grafana-admin-password: rotated and verified")
		return nil
	default:
		return fmt.Errorf("unknown observability secrets command %q", args[0])
	}
}
