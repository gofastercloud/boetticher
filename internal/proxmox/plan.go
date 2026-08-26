package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/storage"
)

type GuestKind string

const (
	KindQEMU GuestKind = "qemu"
	KindLXC  GuestKind = "lxc"
)

type GuestPlan struct {
	VMID       int                                 `json:"vmid"`
	Name       string                              `json:"name"`
	Kind       GuestKind                           `json:"kind"`
	Hostname   string                              `json:"hostname"`
	Zone       string                              `json:"zone"`
	Address    string                              `json:"address"`
	Gateway    string                              `json:"gateway"`
	VLAN       int                                 `json:"vlan"`
	Cores      int                                 `json:"cores"`
	MemoryMiB  int                                 `json:"memory_mib"`
	DiskGiB    int                                 `json:"disk_gib"`
	Monitoring bool                                `json:"monitoring"`
	Backup     bool                                `json:"backup"`
	Tags       []string                            `json:"tags,omitempty"`
	NICs       []GuestNIC                          `json:"nics,omitempty"`
	Owner      string                              `json:"owner,omitempty"`
	Artifact   model.Artifact                      `json:"artifact,omitempty"`
	Persistent []model.PersistentState             `json:"persistent,omitempty"`
	Volumes    []model.PersistentVolumeDeclaration `json:"volumes,omitempty"`
}

type GuestNIC struct {
	Name    string `json:"name"`
	Bridge  string `json:"bridge"`
	VLAN    int    `json:"vlan,omitempty"`
	Address string `json:"address,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	Method  string `json:"method"`
	MAC     string `json:"mac"`
}

type Plan struct {
	ModelRevision   string      `json:"model_revision"`
	ManagedBy       string      `json:"managed_by"`
	Node            string      `json:"node"`
	Storage         string      `json:"storage"`
	GatewayImage    string      `json:"gateway_image"`
	GatewayImageURL string      `json:"gateway_image_url"`
	GatewaySHA512   string      `json:"gateway_sha512"`
	Guests          []GuestPlan `json:"guests"`
	// ArtifactFiles is controller-local evidence and is intentionally excluded
	// from canonical model output. It maps qualified definitions to the exact
	// bytes that may be imported into Proxmox.
	ArtifactFiles map[string]string `json:"-"`
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
	storagePlan, err := storage.PlanFromSite(s)
	if err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	guestStorage := "local"
	if s.StorageProfile == "dedicated-data-disk" {
		guestStorage = storage.GuestStorageID
	}
	guests := make([]GuestPlan, 0, len(s.PlatformComponents()))
	for _, component := range s.PlatformComponents() {
		if component.VMID == 0 {
			continue
		}
		guest := GuestPlan{
			VMID: component.VMID, Name: component.Name, Hostname: component.Hostname, Zone: component.Zone,
			Address: component.Address, Gateway: gatewayFor(component.Zone), VLAN: vlanFor(s, component.Zone),
			Kind: KindLXC, Cores: 2, MemoryMiB: 1024, DiskGiB: 8,
			Monitoring: component.Monitoring, Backup: component.Backup, Tags: componentTags(s, component.Name),
		}
		if component.Module != "" {
			for _, declaration := range s.Declarations {
				if declaration.Module == component.Module {
					guest.Owner = "boetticher/module/" + component.Module
					guest.Artifact = declaration.Artifact
					guest.Persistent = append([]model.PersistentState(nil), declaration.Persistent...)
					guest.Volumes = append([]model.PersistentVolumeDeclaration(nil), declaration.Volumes...)
					for index := range guest.Volumes {
						for _, resolved := range storagePlan.Volumes {
							if resolved.Module == guest.Volumes[index].Module && resolved.Name == guest.Volumes[index].Name && resolved.Guest == guest.Volumes[index].Guest {
								guest.Volumes[index].Storage = resolved.Storage
							}
						}
					}
					break
				}
			}
			if guest.Artifact.Name == "" {
				provider := ""
				if component.Module == "dns" {
					provider = s.ModuleConfig["dns"].Provider
					if provider == "" {
						provider = string(model.DNSProviderBlocky)
					}
				}
				if artifact, artifactErr := artifacts.ArtifactFor(component.Module, provider); artifactErr == nil {
					guest.Artifact = artifact
				}
			}
			guest.Owner = "boetticher/module/" + component.Module
			if len(guest.Persistent) == 0 {
				guest.Persistent = fixturePersistent(component.Module, component.Name)
			}
		}
		if component.Name == "lab-portal-01" {
			if artifact, artifactErr := artifacts.ArtifactFor("portal"); artifactErr == nil {
				guest.Artifact = artifact
			}
			guest.Owner = "boetticher/core/portal"
			guest.Persistent = fixturePersistent("portal", component.Name)
		}
		switch component.Name {
		case "lab-fw-01":
			guest.Kind, guest.Cores, guest.MemoryMiB, guest.DiskGiB = KindQEMU, 2, 2048, 16
			guest.NICs = gatewayNICs(s)
		case "lab-monitor-01":
			guest.MemoryMiB, guest.DiskGiB = 2048, 16
		case "lab-portal-01":
			guest.Cores, guest.MemoryMiB, guest.DiskGiB = 1, 512, 4
		}
		guests = append(guests, guest)
	}
	sort.Slice(guests, func(i, j int) bool { return guests[i].VMID < guests[j].VMID })
	return Plan{ModelRevision: revision, ManagedBy: "boetticher", Node: s.ProxmoxNode, Storage: guestStorage, GatewayImage: model.QualifiedGatewayImage, GatewayImageURL: model.QualifiedGatewayImageURL, GatewaySHA512: model.QualifiedGatewayImageSHA512, Guests: guests, ArtifactFiles: map[string]string{}}, nil
}

func artifactKey(artifact model.Artifact) string {
	return strings.Join([]string{artifact.Name, artifact.Version, artifact.Provider, artifact.Architecture, artifact.Kind, artifact.DefinitionSHA256, artifact.ContentSHA256}, "|")
}

// ResolveQualifiedArtifacts binds every appliance in a Proxmox plan to
// controller-side qualification evidence. It does not mutate Proxmox or the
// canonical model. Missing evidence is a HOLD before any guest mutation.
func ResolveQualifiedArtifacts(root string, plan Plan, require bool) (Plan, error) {
	resolved := plan
	resolved.Guests = append([]GuestPlan(nil), plan.Guests...)
	resolved.ArtifactFiles = map[string]string{}
	for index := range resolved.Guests {
		guest := &resolved.Guests[index]
		if guest.Artifact.Name == "" {
			continue
		}
		artifact, evidence, err := artifacts.ResolveArtifactEvidence(root, guest.Artifact)
		if err != nil {
			if require {
				return Plan{}, fmt.Errorf("HOLD: %s: %w", guest.Name, err)
			}
			continue
		}
		guest.Artifact = artifact
		if evidence.ArtifactPath != "" {
			resolved.ArtifactFiles[artifactKey(artifact)] = evidence.ArtifactPath
		}
	}
	return resolved, nil
}

func fixturePersistent(module, guest string) []model.PersistentState {
	identity := model.PersistentState{Name: "ssh-identity", Guest: guest, Path: "/var/lib/boetticher/identity/ssh", Kind: "endpoint-identity", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}
	var state *model.PersistentState
	switch module {
	case "dns":
		state = &model.PersistentState{Name: "powerdns-database", Guest: guest, Path: "/var/lib/powerdns", Kind: "application-database", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}
	case "monitoring":
		state = &model.PersistentState{Name: "postgresql-data", Guest: guest, Path: "/var/lib/postgresql", Kind: "application-database", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}
	case "firewall":
		state = &model.PersistentState{Name: "kea-leases", Guest: guest, Path: "/var/lib/kea", Kind: "lease-state", Backup: true, Replacement: "retain-across-rootfs-replacement"}
	}
	result := []model.PersistentState{identity}
	if state != nil {
		result = append(result, *state)
	}
	return result
}

func gatewayNICs(s model.Site) []GuestNIC {
	nics := []GuestNIC{{Name: "wan0", Bridge: "vmbr0", Method: "dhcp", MAC: "02:00:00:00:01:01"}}
	for _, zone := range s.Normalize().Network.Zones {
		nics = append(nics, GuestNIC{Name: strings.ToLower(zone.Name) + "0", Bridge: "vmbr1", VLAN: zone.VLAN, Address: zone.Gateway + "/24", Method: "static", MAC: fmt.Sprintf("02:00:00:00:01:%02x", len(nics)+1)})
	}
	return nics
}

func vlanFor(s model.Site, zoneName string) int {
	for _, zone := range s.Network.Zones {
		if zone.Name == zoneName {
			return zone.VLAN
		}
	}
	return 0
}

func componentTags(s model.Site, name string) []string {
	for _, component := range s.PlatformComponents() {
		if component.Name == name {
			tags := append([]string(nil), component.Tags...)
			sort.Strings(tags)
			return tags
		}
	}
	return nil
}

func componentMonitoring(s model.Site, name string) bool {
	for _, component := range s.PlatformComponents() {
		if component.Name == name {
			return component.Monitoring
		}
	}
	return false
}

func componentBackup(s model.Site, name string) bool {
	for _, component := range s.PlatformComponents() {
		if component.Name == name {
			return component.Backup
		}
	}
	return false
}

// Provision creates the declared foundation guests and is safe to re-run. It
// never removes an object or changes an existing guest's disk/network shape;
// drift is returned to the caller for an explicit remediation decision.
func Provision(ctx context.Context, client *Client, plan Plan, _ ...string) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	for _, guest := range plan.Guests {
		switch guest.Kind {
		case KindQEMU:
			// The gateway VM is created by the bootstrap image path.
			continue
		case KindLXC:
			if err := ensureLXC(ctx, client, plan, guest); err != nil {
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

func EnsureFirewallVM(ctx context.Context, client *Client, plan Plan) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	for _, guest := range plan.Guests {
		if guest.Kind == KindQEMU {
			filename := fmt.Sprintf("%s-%s-%s.qcow2", guest.Artifact.Name, guest.Artifact.Version, guest.Artifact.Architecture)
			source := plan.ArtifactFiles[artifactKey(guest.Artifact)]
			if err := ensureArtifactInStorage(ctx, client, plan.Node, "local", "images", filename, guest.Artifact.ContentSHA256, source); err != nil {
				return fmt.Errorf("prepare qualified firewall artifact: %w", err)
			}
			imageFileID := "local:images/" + filename
			return ensureQEMU(ctx, client, plan, guest, imageFileID)
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

// ValidatePhysicalBinding checks only the boetticher-owned vmbr0/vmbr1
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
		if err := validateExistingGuestIdentity(current, guest); err != nil {
			return err
		}
		if err := validateExistingQEMUVolumes(current, plan, guest); err != nil {
			return err
		}
		return ensureExistingGuestTags(ctx, client, plan, guest, current)
	}
	if !IsNotFound(err) {
		return fmt.Errorf("inspect VM %s: %w", guest.Name, err)
	}
	params := url.Values{
		"name":        {guest.Name},
		"description": {artifactDescription(guest.Artifact)},
		"memory":      {strconv.Itoa(guest.MemoryMiB)},
		"cores":       {strconv.Itoa(guest.Cores)},
		"scsihw":      {"virtio-scsi-single"},
		"ostype":      {"l26"},
		"onboot":      {"1"},
		"agent":       {"1"},
		"boot":        {"order=scsi0;net0"},
		"serial0":     {"socket"},
		"tags":        {strings.Join(guest.Tags, ";")},
	}
	volumeParams, err := qemuPersistentVolumeParams(plan, guest)
	if err != nil {
		return fmt.Errorf("validate persistent volumes for %s: %w", guest.Name, err)
	}
	for key, value := range volumeParams {
		params.Set(key, value)
	}
	for index, nic := range guest.NICs {
		value := fmt.Sprintf("virtio,bridge=%s,firewall=1,macaddr=%s", nic.Bridge, nic.MAC)
		if nic.VLAN != 0 {
			value += fmt.Sprintf(",tag=%d", nic.VLAN)
		}
		params.Set(fmt.Sprintf("net%d", index), value)
	}
	if err := client.CreateVM(ctx, plan.Node, guest.VMID, params); err != nil {
		return fmt.Errorf("create gateway VM %s: %w", guest.Name, err)
	}
	upid, err := client.ImportDisk(ctx, plan.Node, guest.VMID, iso, plan.Storage, "qcow2")
	if err != nil {
		return fmt.Errorf("import gateway image into %s: %w", plan.Storage, err)
	}
	if err := client.WaitTask(ctx, plan.Node, upid); err != nil {
		return fmt.Errorf("wait for gateway image import: %w", err)
	}
	var imported map[string]any
	if err := client.QEMUConfig(ctx, plan.Node, guest.VMID, &imported); err != nil {
		return fmt.Errorf("inspect imported gateway disk: %w", err)
	}
	unused, ok := imported["unused0"].(string)
	if !ok || unused == "" {
		return errors.New("gateway disk import completed without an unused disk reference")
	}
	if err := client.SetVMConfig(ctx, plan.Node, guest.VMID, url.Values{"scsi0": {unused}, "delete": {"unused0"}}); err != nil {
		return fmt.Errorf("attach imported gateway disk: %w", err)
	}
	return nil
}

// qemuPersistentVolumeParams attaches declared persistent data disks to the
// appliance VM. The guest artifact owns the mount contract; Core owns the
// Proxmox volume identity and backup flag. A module never selects a raw disk.
func qemuPersistentVolumeParams(plan Plan, guest GuestPlan) (map[string]string, error) {
	params := make(map[string]string, len(guest.Volumes))
	for index, volume := range guest.Volumes {
		if volume.Storage == "" || volume.SizeGiB <= 0 || volume.MountPath == "" {
			return nil, fmt.Errorf("volume %s requires Core-resolved storage, positive size, and mount path", volume.Name)
		}
		backup := "0"
		if volume.Backup {
			backup = "1"
		}
		params[fmt.Sprintf("scsi%d", index+1)] = fmt.Sprintf("%s:%d,backup=%s", volume.Storage, volume.SizeGiB, backup)
	}
	return params, nil
}

func validateExistingQEMUVolumes(current map[string]any, plan Plan, guest GuestPlan) error {
	wanted, err := qemuPersistentVolumeParams(plan, guest)
	if err != nil {
		return err
	}
	for key, expected := range wanted {
		observed, _ := current[key].(string)
		if observed == "" || !strings.HasPrefix(observed, strings.Split(expected, ",")[0]) {
			return fmt.Errorf("HOLD: guest %s has persistent volume %s=%q, expected storage/size %q", guest.Name, key, observed, expected)
		}
	}
	return nil
}

func ensureLXC(ctx context.Context, client *Client, plan Plan, guest GuestPlan) error {
	var current map[string]any
	err := client.LXCConfig(ctx, plan.Node, guest.VMID, &current)
	if err == nil {
		if err := validateExistingGuestIdentity(current, guest); err != nil {
			return err
		}
		if err := validateExistingGuestVolumes(current, guest); err != nil {
			return err
		}
		return ensureExistingGuestTags(ctx, client, plan, guest, current)
	}
	if !IsNotFound(err) {
		return fmt.Errorf("inspect container %s: %w", guest.Name, err)
	}
	if guest.Artifact.Name == "" || guest.Artifact.DefinitionSHA256 == "" {
		return fmt.Errorf("HOLD: guest %s has no resolved appliance artifact", guest.Name)
	}
	if guest.Artifact.ContentSHA256 == "" {
		return fmt.Errorf("NOT BUILT: guest %s artifact %s has no qualified content checksum", guest.Name, guest.Artifact.Name)
	}
	filename := guest.Artifact.Name + "-" + guest.Artifact.Version + "-" + guest.Artifact.Architecture + ".tar.zst"
	if err := ensureArtifactInStorage(ctx, client, plan.Node, "local", "vztmpl", filename, guest.Artifact.ContentSHA256, plan.ArtifactFiles[artifactKey(guest.Artifact)]); err != nil {
		return fmt.Errorf("prepare appliance template for %s: %w", guest.Name, err)
	}
	template := "local:vztmpl/" + filename
	params := url.Values{
		"hostname":     {guest.Hostname},
		"description":  {artifactDescription(guest.Artifact)},
		"ostemplate":   {template},
		"memory":       {strconv.Itoa(guest.MemoryMiB)},
		"cores":        {strconv.Itoa(guest.Cores)},
		"unprivileged": {"1"},
		"onboot":       {"1"},
		"features":     {"nesting=0"},
		"rootfs":       {fmt.Sprintf("%s:%d", plan.Storage, guest.DiskGiB)},
		"tags":         {strings.Join(guest.Tags, ";")},
		"net0":         {fmt.Sprintf("name=eth0,bridge=vmbr1,tag=%d,firewall=1,ip=%s/24,gw=%s", guest.VLAN, guest.Address, gatewayFor(guest.Zone))},
	}
	for index, volume := range guest.Volumes {
		value, err := persistentVolumeParam(volume)
		if err != nil {
			return fmt.Errorf("validate persistent volume %s for %s: %w", volume.Name, guest.Name, err)
		}
		params.Set(fmt.Sprintf("mp%d", index), value)
	}
	if err := client.CreateLXC(ctx, plan.Node, guest.VMID, params); err != nil {
		return fmt.Errorf("create container %s: %w", guest.Name, err)
	}
	return nil
}

func persistentVolumeParam(volume model.PersistentVolumeDeclaration) (string, error) {
	if volume.Storage == "" || volume.SizeGiB <= 0 || volume.MountPath == "" || strings.ContainsAny(volume.MountPath, ",\r\n") || !strings.HasPrefix(volume.MountPath, "/") {
		return "", errors.New("volume requires Core-resolved storage, positive size, and an absolute safe mount path")
	}
	backup := "0"
	if volume.Backup {
		backup = "1"
	}
	return fmt.Sprintf("%s:%d,mp=%s,backup=%s", volume.Storage, volume.SizeGiB, volume.MountPath, backup), nil
}

func validateExistingGuestVolumes(current map[string]any, expected GuestPlan) error {
	for index, volume := range expected.Volumes {
		wanted, err := persistentVolumeParam(volume)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("mp%d", index)
		observed, _ := current[key].(string)
		if observed != wanted {
			return fmt.Errorf("HOLD: guest %s has persistent volume %s=%q, expected %q", expected.Name, key, observed, wanted)
		}
	}
	return nil
}

func ensureArtifactInStorage(ctx context.Context, client *Client, node, storage, content, filename, checksum, source string) error {
	if checksum == "" {
		return errors.New("artifact content checksum is required")
	}
	entries, err := client.StorageContent(ctx, node, storage, content)
	if err != nil {
		return fmt.Errorf("inspect %s artifact storage: %w", content, err)
	}
	for _, entry := range entries {
		if entry.Filename != filename && !strings.HasSuffix(entry.VolID, "/"+filename) {
			continue
		}
		observed := entry.Checksum
		if observed == "" {
			observed = entry.CSum
		}
		if observed == "" {
			return fmt.Errorf("stored artifact %s has no checksum evidence", filename)
		}
		if !strings.EqualFold(observed, checksum) {
			return fmt.Errorf("stored artifact %s checksum %s does not match qualified %s", filename, observed, checksum)
		}
		return nil
	}
	if source == "" {
		return fmt.Errorf("qualified artifact %s is not present in Proxmox storage and no local artifact bytes are recorded", filename)
	}
	actual, err := artifacts.ContentSHA256ForFile(source)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, checksum) {
		return fmt.Errorf("local artifact %s checksum %s does not match qualified %s", filename, actual, checksum)
	}
	if err := client.UploadStorageFile(ctx, node, storage, content, source, filename); err != nil {
		return fmt.Errorf("upload %s: %w", filename, err)
	}
	return nil
}

func validateExistingGuest(current map[string]any, expected GuestPlan) error {
	if err := validateExistingGuestIdentity(current, expected); err != nil {
		return err
	}
	got, _ := current["tags"].(string)
	if canonicalTags(got) != canonicalTags(strings.Join(expected.Tags, ";")) {
		return fmt.Errorf("guest %s has unexpected tags %q, expected %q", expected.Name, got, strings.Join(expected.Tags, ";"))
	}
	return nil
}

func validateExistingGuestIdentity(current map[string]any, expected GuestPlan) error {
	for key, want := range map[string]string{"name": expected.Name, "hostname": expected.Hostname} {
		if got, ok := current[key].(string); ok && got != "" && got != want {
			return fmt.Errorf("guest %s has unexpected %s %q, expected %q", expected.Name, key, got, want)
		}
	}
	if expected.Artifact.Name != "" {
		observed, _ := current["description"].(string)
		wanted := artifactDescription(expected.Artifact)
		if observed != wanted {
			return fmt.Errorf("HOLD: guest %s has artifact identity %q, expected %q; appliance replacement is required", expected.Name, observed, wanted)
		}
	}
	return nil
}

func artifactDescription(artifact model.Artifact) string {
	return fmt.Sprintf("boetticher-artifact=%s@%s definition=%s content=%s", artifact.Name, artifact.Version, artifact.DefinitionSHA256, artifact.ContentSHA256)
}

func ensureExistingGuestTags(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) error {
	want := strings.Join(guest.Tags, ";")
	got, _ := current["tags"].(string)
	if canonicalTags(got) == canonicalTags(want) {
		return nil
	}
	params := url.Values{"tags": {want}}
	var err error
	if guest.Kind == KindQEMU {
		err = client.SetVMConfig(ctx, plan.Node, guest.VMID, params)
	} else {
		err = client.SetLXCConfig(ctx, plan.Node, guest.VMID, params)
	}
	if err != nil {
		return fmt.Errorf("apply boetticher tags to %s: %w", guest.Name, err)
	}
	return nil
}

func canonicalTags(value string) string {
	parts := strings.Split(value, ";")
	filtered := parts[:0]
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			filtered = append(filtered, strings.TrimSpace(part))
		}
	}
	sort.Strings(filtered)
	return strings.Join(filtered, ";")
}

func gatewayFor(zone string) string {
	for _, prefix := range []string{"10.10.10", "10.10.20", "10.10.50", "10.10.99"} {
		if strings.HasSuffix(prefix, "."+map[string]string{"TRUSTED": "10", "SERVERS": "20", "SANDBOX": "50", "MGMT": "99"}[zone]) {
			return prefix + ".1"
		}
	}
	return ""
}
