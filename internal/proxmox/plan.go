package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
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
	Gateway    string    `json:"gateway"`
	VLAN       int       `json:"vlan"`
	Cores      int       `json:"cores"`
	MemoryMiB  int       `json:"memory_mib"`
	DiskGiB    int       `json:"disk_gib"`
	Monitoring bool      `json:"monitoring"`
	Backup     bool      `json:"backup"`
}

type Plan struct {
	ModelRevision string      `json:"model_revision"`
	ManagedBy     string      `json:"managed_by"`
	Node          string      `json:"node"`
	Storage       string      `json:"storage"`
	Guests        []GuestPlan `json:"guests"`
}

type NetworkInterface struct {
	Iface           string `json:"iface"`
	Type            string `json:"type"`
	Method          string `json:"method"`
	Address         string `json:"address"`
	Gateway         string `json:"gateway"`
	BridgePorts     string `json:"bridge_ports"`
	BridgeVLANAware bool   `json:"bridge_vlan_aware"`
	HWAddr          string `json:"hwaddr"`
	Driver          string `json:"driver"`
	Model           string `json:"model"`
	PCIAddress      string `json:"pci_address"`
	Bond            string `json:"bond"`
	SpeedMbps       int    `json:"speed"`
	Active          bool   `json:"active"`
}

func (n *NetworkInterface) UnmarshalJSON(data []byte) error {
	var raw struct {
		Iface               string          `json:"iface"`
		Type                string          `json:"type"`
		Method              string          `json:"method"`
		Address             string          `json:"address"`
		CIDR                string          `json:"cidr"`
		Gateway             string          `json:"gateway"`
		BridgePorts         string          `json:"bridge_ports"`
		BridgePortsDash     string          `json:"bridge-ports"`
		BridgeVLANAware     json.RawMessage `json:"bridge_vlan_aware"`
		BridgeVLANAwareDash json.RawMessage `json:"bridge-vlan-aware"`
		HWAddr              string          `json:"hwaddr"`
		Driver              string          `json:"driver"`
		Model               string          `json:"model"`
		Product             string          `json:"product"`
		PCIAddress          string          `json:"pci_address"`
		PCIAddressDash      string          `json:"pci-address"`
		PCI                 string          `json:"pci"`
		Bond                string          `json:"bond"`
		SpeedMbps           int             `json:"speed"`
		Active              json.RawMessage `json:"active"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	bridgePorts := raw.BridgePorts
	if bridgePorts == "" {
		bridgePorts = raw.BridgePortsDash
	}
	address := raw.Address
	if address == "" {
		address = raw.CIDR
	}
	aware := raw.BridgeVLANAware
	if len(aware) == 0 {
		aware = raw.BridgeVLANAwareDash
	}
	n.Iface, n.Type, n.Method, n.Address, n.Gateway = raw.Iface, raw.Type, raw.Method, address, raw.Gateway
	model := raw.Model
	if model == "" {
		model = raw.Product
	}
	pciAddress := raw.PCIAddress
	if pciAddress == "" {
		pciAddress = raw.PCIAddressDash
	}
	if pciAddress == "" {
		pciAddress = raw.PCI
	}
	n.BridgePorts, n.HWAddr, n.Driver, n.Model, n.PCIAddress, n.Bond, n.SpeedMbps = bridgePorts, raw.HWAddr, raw.Driver, model, pciAddress, raw.Bond, raw.SpeedMbps
	n.BridgeVLANAware = jsonBool(aware)
	n.Active = jsonBool(raw.Active)
	return nil
}

func jsonBool(data json.RawMessage) bool {
	if len(data) == 0 {
		return false
	}
	var value bool
	if json.Unmarshal(data, &value) == nil {
		return value
	}
	var number int
	return json.Unmarshal(data, &number) == nil && number != 0
}

func DiscoverPhysicalNetwork(ctx context.Context, client *Client, node, bootstrapAddress, configuredTrunk string) (networkmodel.Discovery, error) {
	return DiscoverPhysicalNetworkWithSelection(ctx, client, node, bootstrapAddress, configuredTrunk, "")
}

func DiscoverPhysicalNetworkWithSelection(ctx context.Context, client *Client, node, bootstrapAddress, configuredTrunk, selectedTrunk string) (networkmodel.Discovery, error) {
	if client == nil {
		return networkmodel.Discovery{}, errors.New("Proxmox client is required")
	}
	var interfaces []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &interfaces); err != nil {
		return networkmodel.Discovery{}, fmt.Errorf("inspect Proxmox physical network: %w", err)
	}
	return AnalyzePhysicalNetworkWithSelection(interfaces, bootstrapAddress, configuredTrunk, selectedTrunk)
}

func AnalyzePhysicalNetwork(interfaces []NetworkInterface, bootstrapAddress, configuredTrunk string) (networkmodel.Discovery, error) {
	return AnalyzePhysicalNetworkWithSelection(interfaces, bootstrapAddress, configuredTrunk, "")
}

func AnalyzePhysicalNetworkWithSelection(interfaces []NetworkInterface, bootstrapAddress, configuredTrunk, selectedTrunk string) (networkmodel.Discovery, error) {
	return analyzePhysicalNetwork(interfaces, bootstrapAddress, configuredTrunk, selectedTrunk, "")
}

// AnalyzePhysicalNetworkWithDefaultRoute is used by the pre-token SSH path,
// where the host's `ip -j route show default` result is stronger evidence than
// inferring the route from a Proxmox network row's gateway field.
func AnalyzePhysicalNetworkWithDefaultRoute(interfaces []NetworkInterface, bootstrapAddress, configuredTrunk, selectedTrunk, defaultRouteInterface string) (networkmodel.Discovery, error) {
	return analyzePhysicalNetwork(interfaces, bootstrapAddress, configuredTrunk, selectedTrunk, defaultRouteInterface)
}

func analyzePhysicalNetwork(interfaces []NetworkInterface, bootstrapAddress, configuredTrunk, selectedTrunk, observedDefaultRoute string) (networkmodel.Discovery, error) {
	var vmbr0 *NetworkInterface
	for i := range interfaces {
		if interfaces[i].Iface == "vmbr0" {
			vmbr0 = &interfaces[i]
			break
		}
	}
	if vmbr0 == nil || vmbr0.Type != "bridge" {
		return networkmodel.Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (vmbr0 is absent or not a bridge)")
	}
	members := strings.Fields(vmbr0.BridgePorts)
	if len(members) != 1 {
		return networkmodel.Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (vmbr0 does not have exactly one physical member)")
	}
	upstream := members[0]
	defaultRouteInterface := observedDefaultRoute
	if defaultRouteInterface != "" {
		found := false
		for _, iface := range interfaces {
			if iface.Iface == defaultRouteInterface {
				found = true
				break
			}
		}
		if !found {
			return networkmodel.Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (observed default-route interface is absent)")
		}
		defaultRouteInterface = normalizeRouteInterface(defaultRouteInterface, upstream)
	}
	if observedDefaultRoute == "" {
		for _, iface := range interfaces {
			if strings.TrimSpace(iface.Gateway) == "" {
				continue
			}
			routeInterface := normalizeRouteInterface(iface.Iface, upstream)
			if defaultRouteInterface != "" && defaultRouteInterface != routeInterface {
				return networkmodel.Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (multiple default-route interfaces are reported)")
			}
			defaultRouteInterface = routeInterface
		}
	}
	if defaultRouteInterface == "" {
		return networkmodel.Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (default route is not observed)")
	}
	evidence := networkmodel.Evidence{
		DefaultRouteInterface: defaultRouteInterface,
		BootstrapInterface:    upstream,
		BootstrapAddress:      bootstrapAddress,
		VMbr0Members:          members,
		ConfiguredTrunk:       configuredTrunk,
	}
	for _, iface := range interfaces {
		if iface.Type != "eth" {
			continue
		}
		addresses := []string{}
		ipv6Addresses := []string{}
		if iface.Address != "" {
			address := strings.TrimSpace(iface.Address)
			parsed := net.ParseIP(strings.TrimSpace(strings.Split(address, "/")[0]))
			if parsed != nil && parsed.To4() == nil {
				ipv6Addresses = append(ipv6Addresses, address)
			} else {
				addresses = append(addresses, address)
			}
		}
		observed := networkmodel.Interface{
			Name: iface.Iface, PermanentMAC: strings.ToLower(iface.HWAddr), Driver: iface.Driver,
			Model: iface.Model, PCIAddress: iface.PCIAddress, SpeedMbps: iface.SpeedMbps, Carrier: iface.Active, PhysicalEthernet: true,
			Addresses: addresses, IPv6Addresses: ipv6Addresses, Bond: iface.Bond,
			DefaultRoute: iface.Gateway != "",
		}
		if iface.Iface == upstream {
			if vmbr0.Address != "" {
				observed.Addresses = append(observed.Addresses, vmbr0.Address)
			}
			observed.ManagementPath = true
		}
		for _, bridge := range interfaces {
			if bridge.Type == "bridge" && containsBridgePort(bridge.BridgePorts, iface.Iface) {
				observed.Bridge = bridge.Iface
			}
		}
		evidence.Interfaces = append(evidence.Interfaces, observed)
	}
	return networkmodel.Analyze(evidence, selectedTrunk)
}

func normalizeRouteInterface(routeInterface, upstream string) string {
	if routeInterface == "vmbr0" {
		return upstream
	}
	return routeInterface
}

func containsBridgePort(ports, wanted string) bool {
	for _, port := range strings.Fields(ports) {
		if port == wanted {
			return true
		}
	}
	return false
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
		{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Zone: "MGMT", Address: "10.10.99.1", Gateway: "10.10.99.1", VLAN: 99, Kind: KindQEMU, Cores: 2, MemoryMiB: 2048, DiskGiB: 16, Monitoring: true, Backup: true},
		{VMID: model.DNS01VMID, Name: "lab-dns-01", Hostname: "lab-dns-01", Zone: "SERVERS", Address: "10.10.20.10", Gateway: "10.10.20.1", VLAN: 20, Kind: KindLXC, Cores: 2, MemoryMiB: 1024, DiskGiB: 8, Monitoring: true, Backup: true},
		{VMID: model.DNS02VMID, Name: "lab-dns-02", Hostname: "lab-dns-02", Zone: "SERVERS", Address: "10.10.20.11", Gateway: "10.10.20.1", VLAN: 20, Kind: KindLXC, Cores: 2, MemoryMiB: 1024, DiskGiB: 8, Monitoring: true, Backup: true},
		{VMID: model.MonitorVMID, Name: "lab-monitor-01", Hostname: "lab-monitor-01", Zone: "MGMT", Address: "10.10.99.20", Gateway: "10.10.99.1", VLAN: 99, Kind: KindLXC, Cores: 2, MemoryMiB: 2048, DiskGiB: 16, Monitoring: true, Backup: true},
		{VMID: model.PortalVMID, Name: "lab-portal-01", Hostname: "lab-portal-01", Zone: "SERVERS", Address: "10.10.20.30", Gateway: "10.10.20.1", VLAN: 20, Kind: KindLXC, Cores: 1, MemoryMiB: 512, DiskGiB: 4, Monitoring: true, Backup: true},
	}
	return Plan{ModelRevision: revision, ManagedBy: "Lab-in-a-Box", Node: s.ProxmoxNode, Storage: storage, Guests: guests}, nil
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
			if err := client.StartVM(ctx, plan.Node, guest.VMID); err != nil {
				return fmt.Errorf("start VM %s: %w", guest.Name, err)
			}
		case KindLXC:
			if err := ensureLXC(ctx, client, plan, guest, debianTemplate); err != nil {
				return err
			}
			if err := client.StartLXC(ctx, plan.Node, guest.VMID); err != nil {
				return fmt.Errorf("start container %s: %w", guest.Name, err)
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

func EnsureVirtualBridge(ctx context.Context, client *Client, node string) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	var interfaces []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &interfaces); err != nil {
		return fmt.Errorf("inspect Proxmox node network: %w", err)
	}
	for _, iface := range interfaces {
		if iface.Iface != "vmbr1" {
			continue
		}
		if iface.Type != "bridge" {
			return fmt.Errorf("vmbr1 exists but is not a Linux bridge")
		}
		if !iface.BridgeVLANAware {
			return errors.New("vmbr1 exists but is not VLAN-aware")
		}
		return nil
	}
	if err := client.CreateNodeNetwork(ctx, node, url.Values{
		"iface": {"vmbr1"}, "type": {"bridge"}, "bridge-ports": {"none"}, "bridge-vlan-aware": {"1"}, "autostart": {"1"},
	}); err != nil {
		return fmt.Errorf("create virtual-only vmbr1: %w", err)
	}
	return nil
}

func AttachTrunk(ctx context.Context, client *Client, node, physicalInterface, bootstrapAddress string) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	if !safeInterfaceName(physicalInterface) {
		return fmt.Errorf("invalid physical interface %q", physicalInterface)
	}
	var interfaces []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &interfaces); err != nil {
		return err
	}
	var bridge *NetworkInterface
	var candidate *NetworkInterface
	for i := range interfaces {
		iface := &interfaces[i]
		if iface.Iface == physicalInterface {
			copy := *iface
			candidate = &copy
		}
		if iface.Iface == physicalInterface && iface.Address == bootstrapAddress {
			return fmt.Errorf("refusing to attach %s: it carries the recorded HOME/bootstrap address", physicalInterface)
		}
		if iface.Iface != "vmbr1" && iface.Type == "bridge" && containsBridgePort(iface.BridgePorts, physicalInterface) {
			return fmt.Errorf("refusing to attach %s: it is part of the recorded HOME/bootstrap path", physicalInterface)
		}
		if iface.Iface == "vmbr1" {
			bridge = iface
		}
	}
	if candidate == nil || candidate.Type != "eth" {
		return fmt.Errorf("refusing to attach %s: it is not an observed physical Ethernet interface", physicalInterface)
	}
	if candidate.Address != "" || candidate.Gateway != "" || candidate.Bond != "" {
		return fmt.Errorf("refusing to attach %s: it has an address, route, or bond dependency", physicalInterface)
	}
	if candidate.HWAddr == "" && candidate.PCIAddress == "" {
		return fmt.Errorf("refusing to attach %s: stable hardware identity is unavailable", physicalInterface)
	}
	if bridge == nil {
		return errors.New("vmbr1 does not exist; run bootstrap first")
	}
	if bridge.BridgePorts != "" && bridge.BridgePorts != "none" && bridge.BridgePorts != physicalInterface {
		return fmt.Errorf("vmbr1 already has bridge ports %q", bridge.BridgePorts)
	}
	if err := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge-ports": {physicalInterface}, "bridge-vlan-aware": {"1"}}); err != nil {
		return fmt.Errorf("attach %s to vmbr1: %w", physicalInterface, err)
	}
	var after []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &after); err != nil {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge-ports": {"none"}, "bridge-vlan-aware": {"1"}}); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk attach verification failed and rollback failed: %v; verification: %w", rollbackErr, err)
		}
		return fmt.Errorf("trunk attach verification failed; rollback completed: %w", err)
	}
	if !bridgeHasPort(after, "vmbr1", physicalInterface) {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge-ports": {"none"}, "bridge-vlan-aware": {"1"}}); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk attach was not observed and rollback failed: %v", rollbackErr)
		}
		return fmt.Errorf("trunk attach was not observed after mutation; rollback completed")
	}
	return nil
}

func DetachTrunk(ctx context.Context, client *Client, node, physicalInterface, bootstrapAddress string) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	if !safeInterfaceName(physicalInterface) {
		return fmt.Errorf("invalid physical interface %q", physicalInterface)
	}
	var interfaces []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &interfaces); err != nil {
		return fmt.Errorf("inspect Proxmox network before detach: %w", err)
	}
	var bridge *NetworkInterface
	for i := range interfaces {
		iface := &interfaces[i]
		if iface.Iface == "vmbr1" {
			bridge = iface
		}
		if iface.Iface == physicalInterface && iface.Address == bootstrapAddress {
			return fmt.Errorf("refusing to detach %s: it carries the recorded HOME/bootstrap address", physicalInterface)
		}
		if iface.Iface == "vmbr0" && containsBridgePort(iface.BridgePorts, physicalInterface) {
			return fmt.Errorf("refusing to detach %s: it is the vmbr0 upstream member", physicalInterface)
		}
	}
	if bridge == nil || bridge.Type != "bridge" || !bridge.BridgeVLANAware || !containsBridgePort(bridge.BridgePorts, physicalInterface) {
		return fmt.Errorf("refusing to detach %s: it is not the current vmbr1 physical member", physicalInterface)
	}
	if err := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge-ports": {"none"}, "bridge-vlan-aware": {"1"}}); err != nil {
		return fmt.Errorf("detach %s from vmbr1: %w", physicalInterface, err)
	}
	var after []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &after); err != nil {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge-ports": {physicalInterface}, "bridge-vlan-aware": {"1"}}); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk detach verification failed and rollback failed: %v; verification: %w", rollbackErr, err)
		}
		return fmt.Errorf("trunk detach verification failed; rollback completed: %w", err)
	}
	if bridgeHasPort(after, "vmbr1", physicalInterface) {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge-ports": {physicalInterface}, "bridge-vlan-aware": {"1"}}); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk detach was not observed and rollback failed: %v", rollbackErr)
		}
		return fmt.Errorf("trunk detach was not observed after mutation; rollback completed")
	}
	return nil
}

func bridgeHasPort(interfaces []NetworkInterface, bridgeName, port string) bool {
	for _, iface := range interfaces {
		if iface.Iface == bridgeName && iface.Type == "bridge" && iface.BridgeVLANAware && containsBridgePort(iface.BridgePorts, port) {
			return true
		}
	}
	return false
}

// ValidatePhysicalBinding checks only the Lab-in-a-Box-owned vmbr0/vmbr1
// boundary. Unrelated host bridges, bonds, VLANs, and SDN objects are not
// adopted or reconciled.
func ValidatePhysicalBinding(s model.Site, interfaces []NetworkInterface) (string, error) {
	var vmbr0, vmbr1 *NetworkInterface
	byName := make(map[string]NetworkInterface, len(interfaces))
	for _, iface := range interfaces {
		byName[iface.Iface] = iface
		if iface.Iface == "vmbr0" {
			copy := iface
			vmbr0 = &copy
		}
		if iface.Iface == "vmbr1" {
			copy := iface
			vmbr1 = &copy
		}
	}
	if vmbr0 == nil || vmbr0.Type != "bridge" || len(strings.Fields(vmbr0.BridgePorts)) != 1 {
		return "", errors.New("vmbr0 upstream bridge is absent or does not have exactly one physical member")
	}
	if vmbr0.Address == "" || !hasAddressValue(vmbr0.Address, s.BootstrapAddress) {
		return "", errors.New("recorded bootstrap address is not present on vmbr0")
	}
	upstreamName := strings.Fields(vmbr0.BridgePorts)[0]
	upstream, ok := byName[upstreamName]
	if !ok || upstream.Type != "eth" {
		return "", errors.New("vmbr0 member is not an observed physical Ethernet interface")
	}
	if !bindingMatches(s.PhysicalNetwork.Upstream.Name, s.PhysicalNetwork.Upstream.PermanentMAC, s.PhysicalNetwork.Upstream.PCIAddress, upstreamName, upstream.HWAddr, upstream.PCIAddress) {
		return "", fmt.Errorf("upstream binding does not match observed interface %s", upstreamName)
	}
	upstreamRenamed := s.PhysicalNetwork.Upstream.Name != "" && upstreamName != s.PhysicalNetwork.Upstream.Name
	if vmbr1 == nil || vmbr1.Type != "bridge" || !vmbr1.BridgeVLANAware {
		return "", errors.New("vmbr1 is absent or not VLAN-aware")
	}
	trunkMembers := strings.Fields(vmbr1.BridgePorts)
	if s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
		if len(trunkMembers) != 0 && !(len(trunkMembers) == 1 && trunkMembers[0] == "none") {
			return "", fmt.Errorf("vmbr1 has an unexpected physical member %q in virtual-only mode", vmbr1.BridgePorts)
		}
		if upstreamRenamed {
			return fmt.Sprintf("upstream renamed from %s to %s; stable identity matches", s.PhysicalNetwork.Upstream.Name, upstreamName), nil
		}
		return "vmbr0 upstream and vmbr1 virtual-only binding are current", nil
	}
	if len(trunkMembers) != 1 || trunkMembers[0] == "none" {
		return "", errors.New("physical-trunk mode has no single vmbr1 physical member")
	}
	trunkName := trunkMembers[0]
	trunk, ok := byName[trunkName]
	if !ok || trunk.Type != "eth" {
		return "", errors.New("vmbr1 member is not an observed physical Ethernet interface")
	}
	if trunk.Address != "" || trunk.Gateway != "" {
		return "", fmt.Errorf("vmbr1 physical member %s has an unexpected address or gateway", trunkName)
	}
	if !bindingMatches(s.PhysicalNetwork.Trunk.Name, s.PhysicalNetwork.Trunk.PermanentMAC, s.PhysicalNetwork.Trunk.PCIAddress, trunkName, trunk.HWAddr, trunk.PCIAddress) {
		return "", fmt.Errorf("trunk binding does not match observed interface %s", trunkName)
	}
	if upstreamRenamed {
		if trunkName != s.PhysicalNetwork.Trunk.Name {
			return fmt.Sprintf("upstream renamed from %s to %s and physical trunk renamed from %s to %s; stable identities match", s.PhysicalNetwork.Upstream.Name, upstreamName, s.PhysicalNetwork.Trunk.Name, trunkName), nil
		}
		return fmt.Sprintf("upstream renamed from %s to %s; stable identity matches", s.PhysicalNetwork.Upstream.Name, upstreamName), nil
	}
	if trunkName != s.PhysicalNetwork.Trunk.Name {
		return fmt.Sprintf("physical trunk renamed from %s to %s; stable identity matches", s.PhysicalNetwork.Trunk.Name, trunkName), nil
	}
	return "vmbr0 upstream and vmbr1 physical trunk binding are current", nil
}

func bindingMatches(expectedName, expectedMAC, expectedPCI, observedName, observedMAC, observedPCI string) bool {
	if expectedMAC != "" {
		return observedMAC != "" && strings.EqualFold(expectedMAC, observedMAC)
	}
	if expectedPCI != "" {
		return observedPCI != "" && strings.EqualFold(expectedPCI, observedPCI)
	}
	return expectedName == observedName
}

func hasAddressValue(value, wanted string) bool {
	return strings.TrimSpace(strings.Split(value, "/")[0]) == strings.TrimSpace(wanted)
}

func safeInterfaceName(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
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
		"net1":    {"virtio,bridge=vmbr1,firewall=1"},
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
