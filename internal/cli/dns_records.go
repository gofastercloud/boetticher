package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runDHCPReservation(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher dhcp reservation add|list|remove")
	}
	action := args[0]
	fs := flag.NewFlagSet("dhcp reservation "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	hostname := fs.String("hostname", "", "one-label reservation hostname")
	address := fs.String("address", "", "reserved IPv4 address")
	mac := fs.String("mac", "", "Ethernet MAC address")
	vmid := fs.Int("vmid", 0, "user guest VMID for read-only MAC lookup")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	jsonOutput := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("dhcp reservation does not accept positional arguments")
	}

	config, resolved, err := loadComposedConfig(*siteDir)
	if err != nil {
		return err
	}
	switch action {
	case "list":
		reservations := append([]model.DHCPReservation(nil), config.DHCPReservations...)
		sort.Slice(reservations, func(i, j int) bool {
			if reservations[i].Hostname != reservations[j].Hostname {
				return reservations[i].Hostname < reservations[j].Hostname
			}
			return reservations[i].MAC < reservations[j].MAC
		})
		if *jsonOutput {
			return writeCLIJSON(out, reservations)
		}
		for _, reservation := range reservations {
			if reservation.VMID == 0 {
				fmt.Fprintf(out, "%s %s %s\n", reservation.Hostname, reservation.Address, reservation.MAC)
				continue
			}
			fmt.Fprintf(out, "%s %s %s vmid=%d\n", reservation.Hostname, reservation.Address, reservation.MAC, reservation.VMID)
		}
		return nil
	case "add":
		return addDHCPReservation(*siteDir, config, resolved, *hostname, *address, *mac, *vmid, *ageIdentity, *proxmoxCA, *insecure, *jsonOutput, out)
	case "remove":
		return removeDHCPReservation(*siteDir, config, resolved, *mac, *vmid, *ageIdentity, *proxmoxCA, *insecure, *jsonOutput, out)
	default:
		return fmt.Errorf("unknown dhcp reservation command %q", action)
	}
}

func addDHCPReservation(siteDir string, config model.SiteConfig, resolved model.Site, hostname, address, mac string, vmid int, ageIdentity, proxmoxCA string, insecure, jsonOutput bool, out io.Writer) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	address = canonicalIPv4(address)
	if hostname == "" || address == "" {
		return errors.New("dhcp reservation add requires --hostname and a valid --address")
	}
	canonicalMAC, err := resolveReservationMAC(siteDir, resolved, mac, vmid, ageIdentity, proxmoxCA, insecure)
	if err != nil {
		return err
	}
	reservation := model.DHCPReservation{Zone: "SERVERS", Hostname: hostname, Address: address, MAC: canonicalMAC, VMID: vmid}
	config.DHCPReservations = append(config.DHCPReservations, reservation)
	if err := validateComposedConfig(config); err != nil {
		return err
	}
	if err := site.SaveConfig(siteDir, config); err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, reservation)
	}
	fmt.Fprintf(out, "DHCP reservation added: %s %s %s\n", hostname, address, canonicalMAC)
	return nil
}

func removeDHCPReservation(siteDir string, config model.SiteConfig, resolved model.Site, mac string, vmid int, ageIdentity, proxmoxCA string, insecure, jsonOutput bool, out io.Writer) error {
	if mac == "" && vmid == 0 {
		return errors.New("dhcp reservation remove requires --mac or --vmid")
	}
	canonicalMAC, err := resolveReservationMAC(siteDir, resolved, mac, vmid, ageIdentity, proxmoxCA, insecure)
	if err != nil {
		return err
	}
	index := -1
	for i, reservation := range config.DHCPReservations {
		candidate, parseErr := canonicalMACAddress(reservation.MAC)
		if parseErr == nil && candidate == canonicalMAC {
			if index != -1 {
				return fmt.Errorf("multiple DHCP reservations match MAC %s", canonicalMAC)
			}
			index = i
		}
	}
	if index == -1 {
		return fmt.Errorf("no DHCP reservation matches MAC %s", canonicalMAC)
	}
	removed := config.DHCPReservations[index]
	config.DHCPReservations = append(config.DHCPReservations[:index], config.DHCPReservations[index+1:]...)
	if err := validateComposedConfig(config); err != nil {
		return err
	}
	if err := site.SaveConfig(siteDir, config); err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, removed)
	}
	fmt.Fprintf(out, "DHCP reservation removed: %s %s\n", removed.Hostname, canonicalMAC)
	return nil
}

func resolveReservationMAC(siteDir string, resolved model.Site, rawMAC string, vmid int, ageIdentity, proxmoxCA string, insecure bool) (string, error) {
	canonicalMAC := ""
	if rawMAC != "" {
		var err error
		canonicalMAC, err = canonicalMACAddress(rawMAC)
		if err != nil {
			return "", err
		}
	}
	if vmid != 0 {
		if vmid < model.UserGuestIDMin || vmid > model.UserGuestIDMax {
			return "", fmt.Errorf("VMID %d is outside the user-workload range", vmid)
		}
		lookedUp, err := lookupGuestMAC(siteDir, resolved, vmid, ageIdentity, proxmoxCA, insecure)
		if err != nil {
			return "", err
		}
		if canonicalMAC != "" && canonicalMAC != lookedUp {
			return "", fmt.Errorf("VMID %d resolves to MAC %s, not supplied MAC %s", vmid, lookedUp, canonicalMAC)
		}
		canonicalMAC = lookedUp
	}
	if canonicalMAC == "" {
		return "", errors.New("a valid --mac or --vmid is required")
	}
	return canonicalMAC, nil
}

func lookupGuestMAC(siteDir string, resolved model.Site, vmid int, ageIdentity, proxmoxCA string, insecure bool) (string, error) {
	client, _, err := loadProxmoxClient(siteDir, resolved, ageIdentity, proxmoxCA, insecure)
	if err != nil {
		return "", fmt.Errorf("look up VMID %d through Proxmox: %w", vmid, err)
	}
	node, err := client.SingleNode(context.Background())
	if err != nil {
		return "", fmt.Errorf("look up VMID %d node: %w", vmid, err)
	}
	_, config, err := client.GuestConfig(context.Background(), node, vmid)
	if err != nil {
		return "", fmt.Errorf("read VMID %d configuration: %w", vmid, err)
	}
	macs, err := guestConfigMACs(config)
	if err != nil {
		return "", fmt.Errorf("resolve VMID %d network identity: %w", vmid, err)
	}
	if len(macs) != 1 {
		return "", fmt.Errorf("VMID %d must expose exactly one unambiguous network MAC, found %d", vmid, len(macs))
	}
	return macs[0], nil
}

func guestConfigMACs(config map[string]any) ([]string, error) {
	keys := make([]string, 0)
	for key := range config {
		if len(key) >= 4 && strings.HasPrefix(key, "net") {
			if _, err := strconv.Atoi(key[3:]); err == nil {
				keys = append(keys, key)
			}
		}
	}
	sort.Strings(keys)
	macs := make([]string, 0, len(keys))
	seen := map[string]struct{}{}
	for _, key := range keys {
		value, ok := config[key].(string)
		if !ok {
			return nil, fmt.Errorf("%s is not a textual network configuration", key)
		}
		mac, err := macFromProxmoxNetworkValue(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if _, exists := seen[mac]; exists {
			return nil, fmt.Errorf("MAC %s is repeated", mac)
		}
		seen[mac] = struct{}{}
		macs = append(macs, mac)
	}
	return macs, nil
}

func macFromProxmoxNetworkValue(value string) (string, error) {
	for _, token := range strings.Split(value, ",") {
		parts := strings.SplitN(strings.TrimSpace(token), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		if key != "macaddr" && key != "hwaddr" && !strings.HasPrefix(key, "virtio") && !strings.HasPrefix(key, "e1000") {
			continue
		}
		if mac, err := canonicalMACAddress(parts[1]); err == nil {
			return mac, nil
		}
	}
	return "", errors.New("network configuration contains no valid MAC address")
}

func canonicalMACAddress(raw string) (string, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(parsed) != 6 {
		return "", fmt.Errorf("%q is not an Ethernet MAC address", raw)
	}
	return strings.ToLower(parsed.String()), nil
}

func canonicalIPv4(raw string) string {
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil || parsed.To4() == nil {
		return ""
	}
	return parsed.To4().String()
}

func loadComposedConfig(siteDir string) (model.SiteConfig, model.Site, error) {
	config, err := site.LoadConfig(siteDir)
	if err != nil {
		return model.SiteConfig{}, model.Site{}, err
	}
	resolved, _, err := modules.Compose(config)
	if err != nil {
		return model.SiteConfig{}, model.Site{}, err
	}
	pending, err := site.LoadPendingDNSDeletions(siteDir, resolved)
	if err != nil {
		return model.SiteConfig{}, model.Site{}, err
	}
	resolved.PendingDNSDeletions = pending
	return config, resolved, nil
}

func validateComposedConfig(config model.SiteConfig) error {
	_, _, err := modules.Compose(config)
	return err
}
