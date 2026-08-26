package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runDHCP(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher dhcp status|leases")
	}
	command := args[0]
	fs := flag.NewFlagSet("dhcp "+command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	live := fs.Bool("live", false, "inspect the managed gateway over SSH")
	jsonOutput := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	plan, err := firewall.PlanFromSite(s)
	if err != nil {
		return err
	}
	if s.Gateway.Mode == model.GatewayModeExternal {
		if *jsonOutput {
			return writeCLIJSON(out, map[string]string{"mode": "external", "status": "DHCP is managed by the external firewall"})
		}
		fmt.Fprintln(out, "DHCP is managed by the operator-owned external firewall.")
		return nil
	}
	if command != "status" && command != "leases" {
		return fmt.Errorf("unknown dhcp command %q", command)
	}
	if command == "status" {
		value := map[string]any{"mode": plan.Mode, "service": "kea-dhcp4", "ddns_service": "kea-dhcp-ddns", "subnets": plan.DHCP, "live": false}
		if *jsonOutput {
			return writeCLIJSON(out, value)
		}
		fmt.Fprintln(out, "DHCP")
		fmt.Fprintln(out, "  Service       kea-dhcp4")
		fmt.Fprintln(out, "  DDNS          kea-dhcp-ddns")
		for _, subnet := range plan.DHCP {
			allocation := "reservations only"
			if subnet.Pool != "" {
				allocation = subnet.Pool
			}
			fmt.Fprintf(out, "  %-9s %-18s gateway=%s allocation=%s\n", subnet.Zone, subnet.Network, subnet.Gateway, allocation)
		}
		if *live {
			fmt.Fprintln(out, "  Live state    NOT TESTED (use firewall status --live for gateway service state)")
		}
		return nil
	}
	if *live {
		fmt.Fprintln(out, "Lease inspection is prepared for the managed gateway but requires a live Kea control socket.")
		return nil
	}
	if *jsonOutput {
		return writeCLIJSON(out, map[string]any{"mode": plan.Mode, "leases": []any{}, "status": "NOT TESTED"})
	}
	fmt.Fprintln(out, "DHCP leases: NOT TESTED (use --live after the managed gateway is deployed)")
	fmt.Fprintf(out, "Zones: %s\n", strings.Join(func() []string {
		names := make([]string, 0, len(plan.DHCP))
		for _, subnet := range plan.DHCP {
			names = append(names, subnet.Zone)
		}
		return names
	}(), ", "))
	return nil
}
