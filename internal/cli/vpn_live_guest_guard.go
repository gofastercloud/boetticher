package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

type vpnGuestCommandRunner interface {
	Run(context.Context, string) (controllerhost.Result, error)
}

type vpnGuestResource struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
	Node   string `json:"node"`
}

type vpnLiveGuest struct {
	VMID int
	Name string
	Type string
}

var guestNetKey = regexp.MustCompile(`^net[0-9]+$`)

// refuseVPNStopWithLiveProtectedGuests observes every live QEMU/LXC on the
// enrolled Host. It never adopts guests: a configured VPN client MAC match is
// sufficient to retain the tunnel, including for non-product guests.
func refuseVPNStopWithLiveProtectedGuests(ctx context.Context, runner vpnGuestCommandRunner, node string, modules clientservices.Modules) error {
	macs, err := vpnClientMACs(modules)
	if err != nil {
		return err
	}
	if len(macs) == 0 {
		return nil
	}
	if node == "" {
		return errors.New("refuse VPN stop: enrolled Proxmox node is missing")
	}
	resources, err := readVPNGuestResources(ctx, runner)
	if err != nil {
		return err
	}
	blocked := []vpnLiveGuest{}
	for _, guest := range resources {
		if guest.Node != node {
			continue
		}
		if guest.VMID < 1 || (guest.Type != "qemu" && guest.Type != "lxc") || (guest.Status != "running" && guest.Status != "stopped") {
			return errors.New("refuse VPN stop: enrolled Host guest inventory is incomplete")
		}
		if guest.Status == "stopped" {
			continue
		}
		command := "qm config "
		if guest.Type == "lxc" {
			command = "pct config "
		}
		result, err := runner.Run(ctx, command+fmt.Sprint(guest.VMID))
		if err != nil {
			return errors.New("refuse VPN stop: cannot inspect a live enrolled Host guest NIC configuration")
		}
		matched, err := guestUsesVPNMAC(guest.Type, result.Stdout, macs)
		if err != nil {
			return errors.New("refuse VPN stop: live enrolled Host guest NIC configuration is malformed")
		}
		if matched {
			name := guest.Name
			if name == "" {
				name = "unnamed"
			}
			blocked = append(blocked, vpnLiveGuest{VMID: guest.VMID, Name: name, Type: guest.Type})
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].VMID < blocked[j].VMID })
	items := make([]string, 0, len(blocked))
	for _, guest := range blocked {
		items = append(items, fmt.Sprintf("%d (%s %s)", guest.VMID, guest.Type, guest.Name))
	}
	return fmt.Errorf("refuse VPN stop while configured protected guests are running: %s", strings.Join(items, ", "))
}

func vpnClientMACs(modules clientservices.Modules) (map[string]struct{}, error) {
	if modules.VPN == nil || len(modules.VPN.Clients) == 0 {
		return map[string]struct{}{}, nil
	}
	if modules.DHCP == nil {
		return nil, errors.New("refuse VPN stop: configured VPN clients have no DHCP reservations")
	}
	reservations := map[string]string{}
	for _, reservation := range modules.DHCP.Reservations {
		name := strings.ToLower(strings.TrimSpace(reservation.Name))
		if name == "" {
			return nil, errors.New("refuse VPN stop: DHCP reservation inventory is malformed")
		}
		if _, exists := reservations[name]; exists {
			return nil, errors.New("refuse VPN stop: DHCP reservation names are ambiguous")
		}
		mac, err := canonicalMAC(reservation.MAC)
		if err != nil {
			return nil, errors.New("refuse VPN stop: configured DHCP reservation MAC is malformed")
		}
		reservations[name] = mac
	}
	result := map[string]struct{}{}
	for _, client := range modules.VPN.Clients {
		name := strings.ToLower(strings.TrimSpace(client))
		mac, ok := reservations[name]
		if name == "" || !ok {
			return nil, fmt.Errorf("refuse VPN stop: configured VPN client %q has no DHCP reservation", client)
		}
		result[mac] = struct{}{}
	}
	return result, nil
}

func readVPNGuestResources(ctx context.Context, runner vpnGuestCommandRunner) ([]vpnGuestResource, error) {
	result, err := runner.Run(ctx, "pvesh get /cluster/resources --type vm --output-format json")
	if err != nil {
		return nil, errors.New("refuse VPN stop: enrolled Host guest inventory is unavailable")
	}
	var direct []vpnGuestResource
	if err := json.Unmarshal(result.Stdout, &direct); err == nil && direct != nil {
		return direct, nil
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(result.Stdout, &envelope); err != nil || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, errors.New("refuse VPN stop: enrolled Host guest inventory is malformed")
	}
	if err := json.Unmarshal(envelope.Data, &direct); err != nil || direct == nil {
		return nil, errors.New("refuse VPN stop: enrolled Host guest inventory is malformed")
	}
	return direct, nil
}

func guestUsesVPNMAC(kind string, data []byte, wanted map[string]struct{}) (bool, error) {
	for _, raw := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok || !guestNetKey.MatchString(key) {
			continue
		}
		var macValue string
		if kind == "qemu" {
			_, macValue, ok = strings.Cut(strings.TrimSpace(value), "=")
			if ok {
				macValue, _, _ = strings.Cut(macValue, ",")
			}
		} else {
			for _, option := range strings.Split(strings.TrimSpace(value), ",") {
				key, candidate, found := strings.Cut(option, "=")
				if found && strings.EqualFold(key, "hwaddr") {
					macValue, ok = candidate, true
					break
				}
			}
		}
		if !ok || macValue == "" {
			return false, errors.New("guest NIC has no MAC")
		}
		mac, err := canonicalMAC(macValue)
		if err != nil {
			return false, err
		}
		if _, ok := wanted[mac]; ok {
			return true, nil
		}
	}
	return false, nil
}

func canonicalMAC(value string) (string, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(parsed) != 6 {
		return "", errors.New("invalid MAC")
	}
	return strings.ToLower(parsed.String()), nil
}
