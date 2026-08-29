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
	"time"

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
	if command != "status" && command != "leases" {
		return fmt.Errorf("unknown dhcp command %q", command)
	}
	if s.Gateway.Mode == model.GatewayModeExternal {
		result := map[string]any{
			"mode":            "external",
			"status":          "NOT TESTED",
			"operator_state":  "ACTION REQUIRED",
			"reason":          "DHCP is managed by the external firewall",
			"next_action":     "Inspect DHCP and DDNS using the external firewall's supported interface",
			"evidence_status": "NOT TESTED",
		}
		if *jsonOutput {
			if err := writeCLIJSON(out, result); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(out, "DHCP: ACTION REQUIRED")
			fmt.Fprintln(out, "  DHCP is managed by the operator-owned external firewall; Boetticher cannot inspect it.")
		}
		if *live {
			return errors.New("ACTION REQUIRED: live DHCP inspection is unavailable in external-firewall mode")
		}
		return nil
	}
	if command == "status" {
		value := map[string]any{
			"mode": plan.Mode, "service": "kea-dhcp4", "ddns_service": "kea-dhcp-ddns", "subnets": plan.DHCP,
			"status": "NOT TESTED", "evidence_status": "NOT TESTED", "operator_state": "ACTION REQUIRED",
			"reason":      "desired DHCP configuration has not been checked on the gateway",
			"next_action": "Run boetticher dhcp status --live",
		}
		if *live {
			liveStatus, observedAt, err := inspectManagedDHCP(*siteDir, s)
			if err != nil {
				return err
			}
			value["status"] = "PASS"
			value["evidence_status"] = "PASS"
			value["operator_state"] = "HEALTHY"
			value["observed_at"] = observedAt
			value["services"] = map[string]string{
				"kea-dhcp4-server":     liveStatus.Services["kea-dhcp4-server"],
				"kea-dhcp-ddns-server": liveStatus.Services["kea-dhcp-ddns-server"],
			}
			value["reason"] = "Kea DHCP and Kea DDNS are active on the managed gateway"
			value["next_action"] = "No action required"
		}
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
			liveStatus := value["services"].(map[string]string)
			fmt.Fprintf(out, "  Live state    PASS observed=%s\n", value["observed_at"])
			fmt.Fprintf(out, "  Kea DHCP      %s\n  Kea DDNS      %s\n", liveStatus["kea-dhcp4-server"], liveStatus["kea-dhcp-ddns-server"])
		} else {
			fmt.Fprintln(out, "  Evidence      NOT TESTED (run boetticher dhcp status --live)")
		}
		return nil
	}
	if *live {
		liveStatus, observedAt, err := inspectManagedDHCP(*siteDir, s)
		if err != nil {
			return err
		}
		data, err := gatewayCommand(*siteDir, s, "sudo", "/usr/lib/boetticher/inspect-firewall", "leases")
		if err != nil {
			return err
		}
		leases, err := parseKeaLeaseCSV(data, plan)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return writeCLIJSON(out, map[string]any{
				"mode": plan.Mode, "leases": leases, "status": "PASS", "evidence_status": "PASS", "observed_at": observedAt,
				"services": map[string]string{"kea-dhcp4-server": liveStatus.Services["kea-dhcp4-server"], "kea-dhcp-ddns-server": liveStatus.Services["kea-dhcp-ddns-server"]},
			})
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

func inspectManagedDHCP(siteDir string, s model.Site) (gatewayLiveStatus, string, error) {
	data, err := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status")
	if err != nil {
		return gatewayLiveStatus{}, "", fmt.Errorf("live DHCP inspection failed: %w", err)
	}
	liveStatus, err := parseGatewayStatus(string(data))
	if err != nil {
		return gatewayLiveStatus{}, "", fmt.Errorf("live DHCP inspection returned malformed gateway status: %w", err)
	}
	if err := validateDHCPServices(liveStatus); err != nil {
		return gatewayLiveStatus{}, "", err
	}
	return liveStatus, time.Now().UTC().Format(time.RFC3339), nil
}

func validateDHCPServices(liveStatus gatewayLiveStatus) error {
	for _, service := range []string{"kea-dhcp4-server", "kea-dhcp-ddns-server"} {
		state, ok := liveStatus.Services[service]
		if !ok || strings.TrimSpace(state) == "" {
			return fmt.Errorf("live DHCP inspection is incomplete: %s state is missing", service)
		}
		if strings.TrimSpace(state) != "active" {
			return fmt.Errorf("live DHCP inspection failed: %s is %q, expected active", service, state)
		}
	}
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
