package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/gofastercloud/boetticher/internal/controller"
)

func runControllerAgentAccess(args []string, out io.Writer) error {
	return runControllerAgentAccessWithOptions(args, controller.AgentAccessOptions{}, out)
}

func runControllerAgentAccessWithOptions(args []string, opts controller.AgentAccessOptions, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher controller agent-access <status|enable|disable>")
	}
	switch args[0] {
	case "status":
		return runControllerAgentAccessStatus(args[1:], opts, out)
	case "enable":
		return runControllerAgentAccessEnable(args[1:], opts, out)
	case "disable":
		return runControllerAgentAccessDisable(args[1:], opts, out)
	default:
		return fmt.Errorf("unknown controller agent-access command %q", args[0])
	}
}

func runControllerAgentAccessStatus(args []string, opts controller.AgentAccessOptions, out io.Writer) error {
	fs := flag.NewFlagSet("controller agent-access status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher controller agent-access status")
	}
	status, err := controller.InspectAgentAccess(opts)
	if err != nil {
		return err
	}
	renderAgentAccessStatus(out, status)
	return nil
}

func runControllerAgentAccessEnable(args []string, opts controller.AgentAccessOptions, out io.Writer) error {
	fs := flag.NewFlagSet("controller agent-access enable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	key := fs.String("key", "", "SSH public key for the agent account")
	planOnly := fs.Bool("plan", false, "preview changes without modifying the Controller")
	yes := fs.Bool("yes", false, "approve enabling restricted agent SSH access")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*planOnly && *yes) || *key == "" {
		return errors.New("usage: boetticher controller agent-access enable --key 'ssh-ed25519 ...' [--plan|--yes]")
	}

	if *planOnly {
		plan, err := controller.PlanEnableAgentAccess(*key, opts)
		if err != nil {
			return err
		}
		renderAgentAccessPlan(out, "Controller agent access enable (plan)", plan)
		return nil
	}
	if !*yes {
		plan, err := controller.PlanEnableAgentAccess(*key, opts)
		if err != nil {
			return err
		}
		renderAgentAccessPlan(out, "Controller agent access enable (preview)", plan)
		return errors.New("controller agent-access enable requires --yes to apply changes (use --plan to preview)")
	}

	plan, err := controller.EnableAgentAccess(context.Background(), *key, opts)
	if err != nil {
		return err
	}
	renderAgentAccessPlan(out, "Controller agent access enabled", plan)
	return nil
}

func runControllerAgentAccessDisable(args []string, opts controller.AgentAccessOptions, out io.Writer) error {
	fs := flag.NewFlagSet("controller agent-access disable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	planOnly := fs.Bool("plan", false, "preview changes without modifying the Controller")
	yes := fs.Bool("yes", false, "approve revoking restricted agent SSH access")
	purgePolicy := fs.Bool("purge-policy", false, "also remove /etc/boetticher/agent-policy.yml")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*planOnly && *yes) {
		return errors.New("usage: boetticher controller agent-access disable [--purge-policy] [--plan|--yes]")
	}

	if *planOnly {
		plan, err := controller.PlanDisableAgentAccess(*purgePolicy, opts)
		if err != nil {
			return err
		}
		renderAgentAccessPlan(out, "Controller agent access disable (plan)", plan)
		return nil
	}
	if !*yes {
		plan, err := controller.PlanDisableAgentAccess(*purgePolicy, opts)
		if err != nil {
			return err
		}
		renderAgentAccessPlan(out, "Controller agent access disable (preview)", plan)
		return errors.New("controller agent-access disable requires --yes to apply changes (use --plan to preview)")
	}

	plan, err := controller.DisableAgentAccess(context.Background(), *purgePolicy, opts)
	if err != nil {
		return err
	}
	renderAgentAccessPlan(out, "Controller agent access disabled", plan)
	return nil
}

func renderAgentAccessStatus(out io.Writer, status controller.AgentAccessStatus) {
	fmt.Fprintln(out, "Controller agent access")

	userState := "absent"
	if status.UserExists {
		userState = "present"
	}
	fmt.Fprintf(out, "  User:             %s (%s)\n", status.User, userState)

	brokerState := "absent"
	if status.BrokerInstalled {
		brokerState = "installed"
	}
	fmt.Fprintf(out, "  Broker binary:    %s (%s)\n", status.BrokerPath, brokerState)

	switch {
	case status.AuthorizedKeysConfigured:
		detail := fmt.Sprintf("%s %s", status.KeyType, status.KeyFingerprint)
		if status.KeyComment != "" {
			detail += " " + status.KeyComment
		}
		fmt.Fprintf(out, "  Authorized keys:  configured (%s)\n", detail)
	case status.AuthorizedKeysError != "":
		fmt.Fprintf(out, "  Authorized keys:  %s (%s)\n", status.AuthorizedKeysPath, status.AuthorizedKeysError)
	default:
		fmt.Fprintf(out, "  Authorized keys:  %s (absent)\n", status.AuthorizedKeysPath)
	}

	switch {
	case status.SudoersPresent:
		fmt.Fprintf(out, "  Sudoers rule:     %s (present)\n", status.SudoersPath)
	case status.SudoersError != "":
		fmt.Fprintf(out, "  Sudoers rule:     %s (%s)\n", status.SudoersPath, status.SudoersError)
	default:
		fmt.Fprintf(out, "  Sudoers rule:     %s (absent)\n", status.SudoersPath)
	}

	if status.PolicyFileExists {
		fmt.Fprintf(out, "  Policy file:      %s (present)\n", status.PolicyPath)
	} else {
		fmt.Fprintf(out, "  Policy file:      %s (absent; defaulting to read-only)\n", status.PolicyPath)
	}

	if status.PolicyError != "" {
		fmt.Fprintf(out, "  Effective policy: invalid (%s)\n", status.PolicyError)
	} else {
		fmt.Fprintf(out, "  Effective policy: %s\n", status.EffectivePolicy)
	}
}

func renderAgentAccessPlan(out io.Writer, heading string, plan controller.AgentAccessPlan) {
	fmt.Fprintln(out, heading)
	if plan.Key.Fingerprint != "" {
		keyLine := fmt.Sprintf("%s %s", plan.Key.Type, plan.Key.Fingerprint)
		if plan.Key.Comment != "" {
			keyLine += " " + plan.Key.Comment
		}
		fmt.Fprintf(out, "  Key: %s\n", keyLine)
	}
	for _, change := range plan.Changes {
		fmt.Fprintf(out, "  %-8s %s — %s\n", change.Action, change.Target, change.Detail)
	}
	if !plan.HasChanges() {
		fmt.Fprintln(out, "No changes required.")
	}
}
