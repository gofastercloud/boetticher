package cli

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runDHCP(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher dhcp status|leases|reservation add|list|remove")
	}
	if args[0] == "reservation" {
		return runDHCPReservation(args[1:], out)
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
		data, err := gatewayCommand(*siteDir, s, "sudo", "cat", "/var/lib/kea/kea-leases4.csv")
		if err != nil {
			return err
		}
		leases, err := parseKeaLeaseCSV(data, plan)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return writeCLIJSON(out, map[string]any{"mode": plan.Mode, "leases": leases, "status": "PASS"})
		}
		printDHCPLeases(out, leases)
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

type dhcpLease struct {
	Zone     string `json:"zone"`
	IP       string `json:"ip_address"`
	Hostname string `json:"hostname,omitempty"`
	FQDN     string `json:"fqdn,omitempty"`
}

// parseKeaLeaseCSV reads the Debian Kea memfile database without asking the
// gateway to execute a mutating control command. Kea owns this CSV; the CLI
// only presents active leases and never writes it.
func parseKeaLeaseCSV(data []byte, plan firewall.Plan) ([]dhcpLease, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read Kea lease header: %w", err)
	}
	columns := make(map[string]int, len(header))
	for index, name := range header {
		columns[strings.TrimSpace(name)] = index
	}
	for _, required := range []string{"address", "subnet_id", "hostname", "state"} {
		if _, ok := columns[required]; !ok {
			return nil, fmt.Errorf("Kea lease database is missing %q column", required)
		}
	}
	zones := make(map[int]string, len(plan.DHCP))
	for _, subnet := range plan.DHCP {
		zones[subnet.ID] = subnet.Zone
	}
	leases := make([]dhcpLease, 0)
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read Kea lease row: %w", err)
		}
		if len(row) < len(header) {
			return nil, errors.New("Kea lease database contains a short row")
		}
		state, err := strconv.Atoi(row[columns["state"]])
		if err != nil {
			return nil, fmt.Errorf("decode Kea lease state: %w", err)
		}
		if state != 0 {
			continue
		}
		subnetID, err := strconv.Atoi(row[columns["subnet_id"]])
		if err != nil {
			return nil, fmt.Errorf("decode Kea subnet ID: %w", err)
		}
		zone, ok := zones[subnetID]
		if !ok {
			continue
		}
		hostname := strings.TrimSpace(row[columns["hostname"]])
		lease := dhcpLease{Zone: zone, IP: strings.TrimSpace(row[columns["address"]]), Hostname: hostname}
		if hostname != "" {
			if strings.Contains(hostname, ".") {
				lease.FQDN = strings.TrimSuffix(hostname, ".")
			} else {
				lease.FQDN = strings.ToLower(hostname) + "." + strings.ToLower(zone) + ".lab.home.arpa"
			}
		}
		leases = append(leases, lease)
	}
	return leases, nil
}

func printDHCPLeases(out interface{ Write([]byte) (int, error) }, leases []dhcpLease) {
	if len(leases) == 0 {
		fmt.Fprintln(out, "DHCP leases: none active")
		return
	}
	fmt.Fprintln(out, "DHCP leases")
	for _, lease := range leases {
		name := lease.Hostname
		if name == "" {
			name = "(unnamed)"
		}
		if lease.FQDN != "" {
			fmt.Fprintf(out, "  %-9s %-18s %-24s %s\n", lease.Zone, name, lease.IP, lease.FQDN)
		} else {
			fmt.Fprintf(out, "  %-9s %-18s %s\n", lease.Zone, name, lease.IP)
		}
	}
}
