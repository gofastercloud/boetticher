package firewallmodule

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

const providerOwnerTag = "boetticher-module-firewall"

type Status struct {
	Expected        bool
	Exists          bool
	Running         bool
	Name            string
	Management      string
	NetworkShapeOK  bool
	StorageIdentity bool
	OwnershipProven bool
	// Startup is the observed Proxmox startup property ("unset" when absent).
	// Drift is reported for apply to reconcile; it does not fail health.
	Startup string
}

// StartupLabel renders the provider's start-order state for status output.
func (s Status) StartupLabel() string {
	if ProviderStartupOrdered(s.Startup) {
		return s.Startup
	}
	return "drift (observed " + s.Startup + ", expected " + ProviderStartup + "); run boetticher module firewall apply"
}

func ValidateVLANBridge(interfaces []proxmox.NetworkInterface) error {
	var home, lab *proxmox.NetworkInterface
	for index := range interfaces {
		switch interfaces[index].Iface {
		case "vmbr0":
			home = &interfaces[index]
		case "vmbr1":
			lab = &interfaces[index]
		}
	}
	if home == nil || home.Type != "bridge" {
		return errors.New("required Host bridge vmbr0 is absent or incompatible; run or fix host apply")
	}
	if lab == nil || lab.Type != "bridge" || !lab.BridgeVLANAware || strings.TrimSpace(lab.BridgePorts) != "" && strings.TrimSpace(lab.BridgePorts) != "none" {
		return errors.New("required Host bridge vmbr1 is absent or incompatible; run or fix host apply")
	}
	return nil
}

func providerVMParams() url.Values {
	return url.Values{
		"name":    {ProviderName},
		"memory":  {"2048"},
		"cores":   {"2"},
		"ostype":  {"l26"},
		"onboot":  {"1"},
		"startup": {ProviderStartup},
		"agent":   {"1"},
		"boot":    {"order=scsi0;net0"},
		"scsihw":  {"virtio-scsi-single"},
		"tags":    {strings.Join([]string{model.TagBoetticher, model.TagManaged, model.TagModule, providerOwnerTag}, ";")},
		"net0":    {ProviderNIC0},
		"net1":    {ProviderNIC1},
		"serial0": {"socket"},
	}
}

func validateProviderVM(current map[string]any, storage string) error {
	name, _ := current["name"].(string)
	if name != ProviderName {
		return fmt.Errorf("HOLD: VMID %d has name %q, expected firewall provider %q", ProviderVMID, name, ProviderName)
	}
	tags, _ := current["tags"].(string)
	if !hasTag(tags, providerOwnerTag) || !hasTag(tags, model.TagBoetticher) {
		return errors.New("HOLD: firewall provider ownership tag is absent")
	}
	net0, _ := current["net0"].(string)
	net1, _ := current["net1"].(string)
	if !nicMatches(net0, ProviderNIC0, "vmbr0") || !nicMatches(net1, ProviderNIC1, "vmbr1") {
		return errors.New("HOLD: firewall provider NIC shape is not the expected vmbr0/vmbr1 pair")
	}
	for key := range current {
		if strings.HasPrefix(key, "net") && key != "net0" && key != "net1" {
			return fmt.Errorf("HOLD: firewall provider has undeclared network interface %s", key)
		}
	}
	if disk, ok := current[ProviderDisk].(string); ok && !strings.HasPrefix(disk, storage+":") {
		return fmt.Errorf("HOLD: firewall provider disk is not on %s", storage)
	}
	return nil
}

func hasTag(tags, wanted string) bool {
	for _, tag := range strings.Split(tags, ";") {
		if tag == wanted {
			return true
		}
	}
	return false
}

func ProviderSummary(status Status) string {
	if !status.Exists {
		return "absent"
	}
	state := "stopped"
	if status.Running {
		state = "running"
	}
	return ProviderName + " " + state + " (VMID " + strconv.Itoa(ProviderVMID) + ")"
}
