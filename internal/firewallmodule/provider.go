package firewallmodule

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

const providerOwnerTag = "boetticher-module-firewall"

type ApplyResult struct {
	Created bool
	Changed bool
	Running bool
}

type Status struct {
	Expected        bool
	Exists          bool
	Running         bool
	Name            string
	Management      string
	NetworkShapeOK  bool
	StorageIdentity bool
	OwnershipProven bool
}

// ValidateHostSubstrate proves the small read-only Host boundary required by
// this capability. It never creates or repairs a bridge or storage.
func ValidateHostSubstrate(ctx context.Context, client *proxmox.Client, node string) error {
	if client == nil || node == "" {
		return errors.New("Proxmox client and node are required")
	}
	interfaces := []proxmox.NetworkInterface{}
	if err := client.NodeNetwork(ctx, node, &interfaces); err != nil {
		return fmt.Errorf("inspect Host network substrate: %w", err)
	}
	if err := ValidateVLANBridge(interfaces); err != nil {
		return err
	}
	storage, err := client.NodeStorage(ctx, node)
	if err != nil {
		return fmt.Errorf("inspect Host storage substrate: %w", err)
	}
	for _, item := range storage {
		if item.Storage == "boetticher-data" && item.Active == 1 {
			return nil
		}
	}
	return errors.New("required Host storage boetticher-data is not active; run or fix host apply")
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

func EnsureProvider(ctx context.Context, client *proxmox.Client, node, storage string, image Image) (ApplyResult, error) {
	if client == nil || node == "" || storage == "" {
		return ApplyResult{}, errors.New("Proxmox client, node, and storage are required")
	}
	kind, current, err := client.GuestConfig(ctx, node, ProviderVMID)
	created := false
	changed := false
	if err != nil {
		if !proxmox.IsNotFound(err) {
			return ApplyResult{}, fmt.Errorf("inspect firewall provider VM: %w", err)
		}
		if image.Path == "" || image.Name == "" || image.SHA256 == "" {
			return ApplyResult{}, errors.New("qualified provider image is required for first creation")
		}
		params := providerVMParams()
		if err := client.CreateVM(ctx, node, ProviderVMID, params); err != nil {
			return ApplyResult{}, fmt.Errorf("create firewall provider %s: %w", ProviderName, err)
		}
		created, changed = true, true
		if err := uploadAndImport(ctx, client, node, storage, image); err != nil {
			return ApplyResult{}, err
		}
	} else {
		if kind != proxmox.KindQEMU {
			return ApplyResult{}, fmt.Errorf("HOLD: VMID %d is occupied by %s; refusing firewall provider adoption", ProviderVMID, kind)
		}
		if err := validateProviderVM(current, storage); err != nil {
			return ApplyResult{}, err
		}
		if _, ok := current[ProviderDisk].(string); !ok {
			if err := uploadAndImport(ctx, client, node, storage, image); err != nil {
				return ApplyResult{}, err
			}
			changed = true
		}
	}
	if err := client.EnsureVMRunning(ctx, node, ProviderVMID); err != nil {
		return ApplyResult{}, fmt.Errorf("start firewall provider: %w", err)
	}
	return ApplyResult{Created: created, Changed: changed, Running: true}, nil
}

func providerVMParams() url.Values {
	return url.Values{
		"name":    {ProviderName},
		"memory":  {"2048"},
		"cores":   {"2"},
		"ostype":  {"l26"},
		"onboot":  {"1"},
		"agent":   {"1"},
		"boot":    {"order=scsi0;net0"},
		"scsihw":  {"virtio-scsi-single"},
		"tags":    {strings.Join([]string{model.TagBoetticher, model.TagManaged, model.TagModule, providerOwnerTag}, ";")},
		"net0":    {ProviderNIC0},
		"net1":    {ProviderNIC1},
		"serial0": {"socket"},
	}
}

func uploadAndImport(ctx context.Context, client *proxmox.Client, node, storage string, image Image) error {
	if err := client.UploadStorageFile(ctx, node, "local", "import", image.Path, image.Name, image.SHA256); err != nil {
		return fmt.Errorf("upload firewall provider image: %w", err)
	}
	upid, err := client.ImportDisk(ctx, node, ProviderVMID, "local:import/"+image.Name, storage, "raw")
	if err != nil {
		return fmt.Errorf("import firewall provider disk: %w", err)
	}
	if err := client.WaitTask(ctx, node, upid); err != nil {
		return fmt.Errorf("wait for firewall provider disk: %w", err)
	}
	return nil
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

func ReadStatus(ctx context.Context, client *proxmox.Client, node string, desired DesiredState) (Status, error) {
	status := Status{Expected: true, Management: desired.ManagementAddress}
	kind, current, err := client.GuestConfig(ctx, node, ProviderVMID)
	if err != nil {
		if proxmox.IsNotFound(err) {
			return status, nil
		}
		return Status{}, err
	}
	status.Exists = true
	if kind != proxmox.KindQEMU {
		return status, fmt.Errorf("provider VMID %d is %s, expected qemu", ProviderVMID, kind)
	}
	if err := validateProviderVM(current, "boetticher-data"); err != nil {
		return status, err
	}
	status.Name, _ = current["name"].(string)
	status.OwnershipProven = hasTag(fmt.Sprint(current["tags"]), providerOwnerTag)
	net0, _ := current["net0"].(string)
	net1, _ := current["net1"].(string)
	status.NetworkShapeOK = nicMatches(net0, ProviderNIC0, "vmbr0") && nicMatches(net1, ProviderNIC1, "vmbr1")
	status.StorageIdentity = current[ProviderDisk] != nil
	vmStatus, err := client.QEMUStatus(ctx, node, ProviderVMID)
	if err != nil {
		return status, err
	}
	status.Running = vmStatus == "running"
	return status, nil
}

func DestroyProvider(ctx context.Context, client *proxmox.Client, node, storage string) error {
	kind, current, err := client.GuestConfig(ctx, node, ProviderVMID)
	if proxmox.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect firewall provider before teardown: %w", err)
	}
	if kind != proxmox.KindQEMU {
		return fmt.Errorf("HOLD: VMID %d is occupied by %s", ProviderVMID, kind)
	}
	if err := validateProviderVM(current, storage); err != nil {
		return err
	}
	state, err := client.QEMUStatus(ctx, node, ProviderVMID)
	if err != nil {
		return err
	}
	if state == "running" {
		if err := client.StopVM(ctx, node, ProviderVMID); err != nil {
			return fmt.Errorf("stop firewall provider before teardown: %w", err)
		}
	}
	if err := client.DestroyQEMU(ctx, node, ProviderVMID); err != nil {
		return fmt.Errorf("remove firewall provider: %w", err)
	}
	_, _, verifyErr := client.GuestConfig(ctx, node, ProviderVMID)
	if verifyErr == nil {
		return errors.New("HOLD: firewall provider still exists after teardown")
	}
	if !proxmox.IsNotFound(verifyErr) {
		return fmt.Errorf("verify firewall provider teardown: %w", verifyErr)
	}
	return nil
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
