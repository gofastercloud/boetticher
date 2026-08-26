package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/dave/labinabox/internal/model"
)

type GuestKind string

const (
	KindQEMU GuestKind = "qemu"
	KindLXC  GuestKind = "lxc"
)

type GuestPlan struct {
	VMID       int       `json:"vmid"`
	Name       string    `json:"name"`
	Kind       GuestKind `json:"kind"`
	Hostname   string    `json:"hostname"`
	Zone       string    `json:"zone"`
	Address    string    `json:"address"`
	VLAN       int       `json:"vlan"`
	Cores      int       `json:"cores"`
	MemoryMiB  int       `json:"memory_mib"`
	DiskGiB    int       `json:"disk_gib"`
	Monitoring bool      `json:"monitoring"`
	Backup     bool      `json:"backup"`
}

type Plan struct {
	ModelRevision string      `json:"model_revision"`
	Node          string      `json:"node"`
	Storage       string      `json:"storage"`
	Guests        []GuestPlan `json:"guests"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	storage := "local"
	if s.StorageProfile == "dedicated-data-disk" {
		storage = "local-lvm"
	}
	guests := []GuestPlan{
		{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Zone: "MGMT", Address: "10.10.99.1", VLAN: 99, Kind: KindQEMU, Cores: 2, MemoryMiB: 2048, DiskGiB: 16, Monitoring: true, Backup: true},
		{VMID: model.DNS01VMID, Name: "lab-dns-01", Hostname: "lab-dns-01", Zone: "SERVERS", Address: "10.10.20.10", VLAN: 20, Kind: KindLXC, Cores: 2, MemoryMiB: 1024, DiskGiB: 8, Monitoring: true, Backup: true},
		{VMID: model.DNS02VMID, Name: "lab-dns-02", Hostname: "lab-dns-02", Zone: "SERVERS", Address: "10.10.20.11", VLAN: 20, Kind: KindLXC, Cores: 2, MemoryMiB: 1024, DiskGiB: 8, Monitoring: true, Backup: true},
		{VMID: model.MonitorVMID, Name: "lab-monitor-01", Hostname: "lab-monitor-01", Zone: "MGMT", Address: "10.10.99.20", VLAN: 99, Kind: KindLXC, Cores: 2, MemoryMiB: 2048, DiskGiB: 16, Monitoring: true, Backup: true},
		{VMID: model.PortalVMID, Name: "lab-portal-01", Hostname: "lab-portal-01", Zone: "SERVERS", Address: "10.10.20.30", VLAN: 20, Kind: KindLXC, Cores: 1, MemoryMiB: 512, DiskGiB: 4, Monitoring: true, Backup: true},
	}
	return Plan{ModelRevision: revision, Node: s.ProxmoxNode, Storage: storage, Guests: guests}, nil
}

// Provision creates the fixed foundation objects and is safe to re-run. It
// never removes an object or changes an existing guest's disk/network shape;
// drift is returned to the caller for an explicit remediation decision.
func Provision(ctx context.Context, client *Client, plan Plan, opnsenseISO, debianTemplate string) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	if opnsenseISO == "" || debianTemplate == "" {
		return errors.New("OPNsense ISO and Debian template are required")
	}
	for _, guest := range plan.Guests {
		switch guest.Kind {
		case KindQEMU:
			if err := ensureQEMU(ctx, client, plan, guest, opnsenseISO); err != nil {
				return err
			}
		case KindLXC:
			if err := ensureLXC(ctx, client, plan, guest, debianTemplate); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported guest kind %q", guest.Kind)
		}
	}
	return nil
}

func EnsureFirewallVM(ctx context.Context, client *Client, plan Plan, opnsenseISO string) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	for _, guest := range plan.Guests {
		if guest.Kind == KindQEMU {
			return ensureQEMU(ctx, client, plan, guest, opnsenseISO)
		}
	}
	return errors.New("foundation plan has no firewall VM")
}

func ensureQEMU(ctx context.Context, client *Client, plan Plan, guest GuestPlan, iso string) error {
	var current map[string]any
	err := client.QEMUConfig(ctx, plan.Node, guest.VMID, &current)
	if err == nil {
		return validateExistingGuest(current, guest)
	}
	if !IsNotFound(err) {
		return fmt.Errorf("inspect VM %s: %w", guest.Name, err)
	}
	params := url.Values{
		"name":    {guest.Name},
		"memory":  {strconv.Itoa(guest.MemoryMiB)},
		"cores":   {strconv.Itoa(guest.Cores)},
		"scsihw":  {"virtio-scsi-single"},
		"ostype":  {"other"},
		"onboot":  {"1"},
		"agent":   {"1"},
		"boot":    {"order=scsi0;ide2;net0"},
		"net0":    {"virtio,bridge=vmbr0,firewall=1"},
		"net1":    {"virtio,bridge=vmbr1,tag=99,firewall=1"},
		"ide2":    {iso + ",media=cdrom"},
		"serial0": {"socket"},
	}
	if err := client.CreateVM(ctx, plan.Node, guest.VMID, params); err != nil {
		return fmt.Errorf("create OPNsense VM %s: %w", guest.Name, err)
	}
	return nil
}

func ensureLXC(ctx context.Context, client *Client, plan Plan, guest GuestPlan, template string) error {
	var current map[string]any
	err := client.LXCConfig(ctx, plan.Node, guest.VMID, &current)
	if err == nil {
		return validateExistingGuest(current, guest)
	}
	if !IsNotFound(err) {
		return fmt.Errorf("inspect container %s: %w", guest.Name, err)
	}
	params := url.Values{
		"hostname":     {guest.Hostname},
		"ostemplate":   {template},
		"memory":       {strconv.Itoa(guest.MemoryMiB)},
		"cores":        {strconv.Itoa(guest.Cores)},
		"unprivileged": {"1"},
		"onboot":       {"1"},
		"features":     {"nesting=0"},
		"rootfs":       {fmt.Sprintf("%s:%d", plan.Storage, guest.DiskGiB)},
		"net0":         {fmt.Sprintf("name=eth0,bridge=vmbr1,tag=%d,firewall=1,ip=%s/24,gw=%s", guest.VLAN, guest.Address, gatewayFor(guest.Zone))},
	}
	if err := client.CreateLXC(ctx, plan.Node, guest.VMID, params); err != nil {
		return fmt.Errorf("create container %s: %w", guest.Name, err)
	}
	return nil
}

func validateExistingGuest(current map[string]any, expected GuestPlan) error {
	for key, want := range map[string]string{"name": expected.Name, "hostname": expected.Hostname} {
		if got, ok := current[key].(string); ok && got != "" && got != want {
			return fmt.Errorf("guest %s has unexpected %s %q, expected %q", expected.Name, key, got, want)
		}
	}
	return nil
}

func gatewayFor(zone string) string {
	for _, prefix := range []string{"10.10.10", "10.10.20", "10.10.50", "10.10.99"} {
		if strings.HasSuffix(prefix, "."+map[string]string{"TRUSTED": "10", "SERVERS": "20", "SANDBOX": "50", "MGMT": "99"}[zone]) {
			return prefix + ".1"
		}
	}
	return ""
}
