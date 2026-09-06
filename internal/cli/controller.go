package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/gofastercloud/boetticher/internal/controller"
)

func runController(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: boetticher controller <bootstrap|status>")
	}
	switch args[0] {
	case "bootstrap":
		return runControllerBootstrap(args[1:], out, errOut)
	case "status":
		return runControllerStatus(args[1:], out)
	case "reboot":
		return runControllerReboot(args[1:], out)
	default:
		return fmt.Errorf("unknown controller command %q", args[0])
	}
}

func runControllerReboot(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("controller reboot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "confirm rebooting the Controller")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !*yes {
		return errors.New("controller reboot requires --yes")
	}
	if os.Geteuid() != 0 {
		return errors.New("controller reboot requires root; run it with sudo")
	}
	if err := exec.Command("systemctl", "reboot").Run(); err != nil {
		return fmt.Errorf("Controller reboot failed: %w", err)
	}
	fmt.Fprintln(out, "Controller reboot requested.")
	return nil
}

func runControllerBootstrap(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("controller bootstrap", flag.ContinueOnError)
	fs.SetOutput(errOut)
	operator := fs.String("operator", "pi", "local controller operator account")
	confirm := fs.Bool("confirm-key-login", false, "confirm public-key SSH login has been tested")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: boetticher controller bootstrap --operator USER --confirm-key-login")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return controller.RunBootstrap(ctx, controller.BootstrapOptions{Operator: *operator, ConfirmKeyLogin: *confirm}, out, errOut)
}

func runControllerStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("controller status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	operator := fs.String("operator", "pi", "local controller operator account")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: boetticher controller status [--operator USER]")
	}
	checks, err := controller.RunStatus(context.Background(), controller.StatusOptions{Operator: *operator})
	if err != nil {
		return err
	}
	fail := false
	fmt.Fprintln(out, "Boetticher controller")
	for _, check := range checks {
		state := "FAIL"
		if check.Passed {
			state = "PASS"
		} else {
			fail = true
		}
		fmt.Fprintf(out, "%-5s %-22s %s\n", state, check.Name, check.Detail)
	}
	if fail {
		fmt.Fprintln(out, "\nController readiness: FAIL")
		return fmt.Errorf("controller readiness failed")
	}
	fmt.Fprintln(out, "\nController readiness: PASS")
	return nil
}
