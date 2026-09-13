package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

const controllerAuthorizationHelper = "/opt/boetticher/current/controller/proxmox/libexec/boetticher-authorize-controller-lab"

type hostAuthorizeOptions struct{ home, plan, yes bool }

func parseHostAuthorizeOptions(args []string) (hostAuthorizeOptions, error) {
	fs := flag.NewFlagSet("host authorize-controller", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o hostAuthorizeOptions
	fs.BoolVar(&o.home, "home-recovery", false, "use HOME recovery")
	fs.BoolVar(&o.plan, "plan", false, "preview")
	fs.BoolVar(&o.yes, "yes", false, "approve")
	if fs.Parse(args) != nil || fs.NArg() != 0 || o.plan && o.yes || !o.home {
		return hostAuthorizeOptions{}, errors.New("usage: boetticher host authorize-controller --home-recovery [--plan|--yes]")
	}
	return o, nil
}
func buildHostAuthorizeRequest(o hostAuthorizeOptions, b controllerhost.ControllerLABBinding, key string) ([]byte, error) {
	action := "plan"
	if o.yes {
		action = "apply"
	}
	return json.Marshal(map[string]string{"action": action, "lab_address": b.Address, "lab_mac": b.MAC, "public_key": strings.TrimSpace(key)})
}

func runHostAuthorizeController(args []string, input io.Reader, out io.Writer) error {
	options, err := parseHostAuthorizeOptions(args)
	if err != nil {
		return err
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	binding, err := controllerhost.LocalControllerLABBinding(config)
	if err != nil {
		return err
	}
	publicKey, err := controllerhost.PublicKey()
	if err != nil {
		return err
	}
	transport, err := controllerhost.HomeTransportFor(config)
	if err != nil {
		return err
	}
	payload, err := buildHostAuthorizeRequest(options, binding, publicKey)
	if err != nil {
		return err
	}
	action := "plan"
	if options.yes {
		action = "apply"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	helper, err := os.ReadFile(controllerAuthorizationHelper)
	if err != nil {
		return fmt.Errorf("read packaged controller authorization helper: %w", err)
	}
	if len(helper) == 0 || len(helper) > 128*1024 {
		return errors.New("packaged controller authorization helper is invalid")
	}
	command := "set -eu; python3 -c " + hostAuthorizationShellQuote(string(helper))
	result, err := transport.RunWithStdin(ctx, command, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if len(result.Stdout) == 0 {
		return errors.New("controller authorization helper returned no result")
	}
	var response struct {
		Changed *bool    `json:"changed"`
		Paths   []string `json:"paths,omitempty"`
		Error   string   `json:"error,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Changed == nil {
		if response.Error != "" {
			return fmt.Errorf("controller authorization helper: %s", response.Error)
		}
		return errors.New("controller authorization helper returned malformed result")
	}
	if action == "plan" {
		fmt.Fprintf(out, "Controller LAB authorization: plan ready (LAB source %s/%s -> Host %s -> 10.10.99.1:443; HOME authorization preserved; changed=%t)\n", binding.Address, binding.MAC, controllerhost.LabHostAddress, *response.Changed)
	} else if *response.Changed {
		fmt.Fprintln(out, "Controller LAB authorization: applied")
	} else {
		fmt.Fprintln(out, "Controller LAB authorization: no change")
	}
	return nil
}

func hostAuthorizationShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
