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
	"time"

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
	ArtifactFiles     map[string]string `json:"-"`
	OperatorPublicKey string            `json:"-"`
	CloudInitFiles    CloudInitFiles    `json:"-"`
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
		AltNames            []string        `json:"altnames"`
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
	hwAddr := raw.HWAddr
	if hwAddr == "" {
		hwAddr = predictableMAC(raw.Iface, raw.AltNames)
	}
	n.BridgePorts, n.HWAddr, n.Driver, n.Model, n.PCIAddress, n.Bond, n.SpeedMbps = bridgePorts, hwAddr, raw.Driver, model, pciAddress, raw.Bond, raw.SpeedMbps
	n.BridgeVLANAware = jsonBool(aware)
	n.Active = jsonBool(raw.Active)
	return nil
}

// predictableMAC recovers hardware identity from Linux's stable enx<mac>
// interface naming when a Proxmox network response omits hwaddr. Only the
// exact 12-hex-digit form is accepted; arbitrary interface names remain
// ambiguous and continue to fail closed.
func predictableMAC(iface string, altNames []string) string {
	names := append([]string{iface}, altNames...)
	for _, name := range names {
		if len(name) != len("enx")+12 || !strings.HasPrefix(name, "enx") {
			continue
		}
		var result strings.Builder
		for i, value := range name[3:] {
			if !isHexRune(value) {
				result.Reset()
				break
			}
			if i > 0 && i%2 == 0 {
				result.WriteByte(':')
			}
			result.WriteRune(value)
		}
		if result.Len() == 17 {
			return strings.ToLower(result.String())
		}
	}
	return ""
}

func isHexRune(value rune) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
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
	// A loaded site is always composed and must carry declaration-owned
	// appliance identity. The uncomposed path exists only for the explicit
	// NewDefaultSite provider fixtures used by package tests.
	composed := len(s.Modules) > 0 || len(s.Declarations) > 0
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
			declarationFound := false
			for _, declaration := range s.Declarations {
				if declaration.Module == component.Module {
					declarationFound = true
					guest.Owner = "boetticher/module/" + component.Module
					guest.Artifact = declaration.Artifact
					guest.Persistent = persistentForGuest(declaration.Persistent, component.Name)
					guest.Volumes = volumesForGuest(declaration.Volumes, component.Name)
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
			if composed && !declarationFound {
				return Plan{}, fmt.Errorf("HOLD: composed module guest %s has no declaration for module %s", component.Name, component.Module)
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
			guest.Volumes = fixtureVolumes("portal", component.Name)
			for index := range guest.Volumes {
				for _, resolved := range storagePlan.Volumes {
					if resolved.Module == guest.Volumes[index].Module && resolved.Name == guest.Volumes[index].Name && resolved.Guest == guest.Volumes[index].Guest {
						guest.Volumes[index].Storage = resolved.Storage
					}
				}
			}
		}
		if component.Module != "" && guest.Artifact.Kind != "" {
			switch guest.Artifact.Kind {
			case string(KindQEMU):
				guest.Kind = KindQEMU
			case string(KindLXC):
				guest.Kind = KindLXC
			default:
				return Plan{}, fmt.Errorf("HOLD: guest %s has unsupported declared artifact kind %q", guest.Name, guest.Artifact.Kind)
			}
		}
		// Artifact kind is authoritative for composed module guests. The
		// firewall name still selects its fixed network topology and sizing,
		// but must not be the source of guest-kind ownership.
		switch component.Name {
		case "lab-fw-01":
			guest.Cores, guest.MemoryMiB, guest.DiskGiB = 2, 2048, 16
			guest.NICs = gatewayNICs(s)
		case "lab-monitor-01":
			guest.MemoryMiB, guest.DiskGiB = 2048, 16
		case "lab-portal-01":
			guest.Cores, guest.MemoryMiB, guest.DiskGiB = 1, 512, 4
		}
		guests = append(guests, guest)
	}
	sort.SliceStable(guests, func(i, j int) bool {
		left, right := deploymentOrder(s, guests[i]), deploymentOrder(s, guests[j])
		if left != right {
			return left < right
		}
		return guests[i].VMID < guests[j].VMID
	})
	// Node is a runtime binding. Static plans retain the logical identity only
	// as a placeholder for projections; every live caller must bind the node
	// returned by Client.SingleNode before using a node-scoped operation.
	return Plan{ModelRevision: revision, ManagedBy: "boetticher", Node: s.LogicalProxmoxIdentity, Storage: guestStorage, GatewayImage: model.QualifiedGatewayImage, GatewayImageURL: model.QualifiedGatewayImageURL, GatewaySHA512: model.QualifiedGatewayImageSHA512, Guests: guests, ArtifactFiles: map[string]string{}}, nil
}

// deploymentOrder follows the resolved module graph carried by Site. This
// keeps appliance ordering correct for capability providers and future
// first-party modules without making VMID order an implicit dependency.
func deploymentOrder(s model.Site, guest GuestPlan) int {
	if guest.Owner == "boetticher/core/portal" {
		return 1000000
	}
	const moduleOwnerPrefix = "boetticher/module/"
	if strings.HasPrefix(guest.Owner, moduleOwnerPrefix) {
		name := strings.TrimPrefix(guest.Owner, moduleOwnerPrefix)
		for index, module := range s.Modules {
			if module.Name == name && module.Enabled {
				return (index + 1) * 100
			}
		}
	}
	// NewDefaultSite is an intentionally small provider-test fixture that does
	// not carry resolved module metadata. Preserve deterministic fixture plans
	// while production Site values always use the resolved graph above.
	if guest.Kind == KindQEMU && guest.Owner == "boetticher/module/firewall" {
		return 10
	}
	switch guest.Owner {
	case "boetticher/module/dns":
		return 20
	case "boetticher/module/logging":
		return 30
	case "boetticher/module/monitoring":
		return 40
	default:
		return 60
	}
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

func persistentForGuest(states []model.PersistentState, guest string) []model.PersistentState {
	filtered := make([]model.PersistentState, 0, len(states))
	for _, state := range states {
		if state.Guest == guest {
			filtered = append(filtered, state)
		}
	}
	return filtered
}

func volumesForGuest(volumes []model.PersistentVolumeDeclaration, guest string) []model.PersistentVolumeDeclaration {
	filtered := make([]model.PersistentVolumeDeclaration, 0, len(volumes))
	for _, volume := range volumes {
		if volume.Guest == guest {
			filtered = append(filtered, volume)
		}
	}
	return filtered
}

func fixtureVolumes(module, guest string) []model.PersistentVolumeDeclaration {
	identity := model.PersistentVolumeDeclaration{Name: "ssh-identity", Module: module, Guest: guest, SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh", Placement: model.StorageDefault, Backup: true}
	return []model.PersistentVolumeDeclaration{identity}
}

func gatewayNICs(s model.Site) []GuestNIC {
	nics := []GuestNIC{{Name: "wan0", Bridge: "vmbr0", Method: "dhcp", MAC: "02:00:00:00:01:01"}}
	for _, zone := range s.Normalize().Network.Zones {
		nics = append(nics, GuestNIC{Name: strings.ToLower(zone.Name) + "0", Bridge: "vmbr1", VLAN: zone.VLAN, Address: zone.Gateway, Method: "static", MAC: fmt.Sprintf("02:00:00:00:01:%02x", len(nics)+1)})
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
			// The gateway is handled by the staged deploy path so its
			// reachability and policy gates run before dependent guests.
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

// ProvisionModule creates and starts only one declared module's guests. Core
// uses this bounded operation to place readiness gates between dependency
// stages; it does not create an alternate deployment path.
func ProvisionModule(ctx context.Context, client *Client, plan Plan, module string) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	if module == "" {
		return errors.New("module name is required")
	}
	found := false
	for _, guest := range plan.Guests {
		matches := guest.Owner == "boetticher/module/"+module
		if module == "portal" {
			matches = guest.Name == "lab-portal-01"
		}
		if !matches || guest.Kind != KindLXC {
			continue
		}
		found = true
		if err := ensureLXC(ctx, client, plan, guest); err != nil {
			return err
		}
		if err := client.StartLXC(ctx, plan.Node, guest.VMID); err != nil {
			return fmt.Errorf("start %s: %w", guest.Name, err)
		}
	}
	if !found {
		return fmt.Errorf("module %s has no LXC guest in the resolved plan", module)
	}
	return nil
}

func EnsureFirewallVM(ctx context.Context, client *Client, plan Plan) error {
	if client == nil {
		return errors.New("Proxmox client is required")
	}
	for _, guest := range plan.Guests {
		if guest.Kind == KindQEMU {
			return ensureQEMU(ctx, client, plan, guest)
		}
	}
	return errors.New("foundation plan has no firewall VM")
}

const builderOwnerTag = "boetticher-builder"

// EnsureBuilderVM creates the transient Linux build environment from the
// pinned Debian input. It is Core bootstrap infrastructure, not a module or a
// user workload, and an existing object must prove that ownership before it is
// touched.
func EnsureBuilderVM(ctx context.Context, client *Client, plan Plan, publicKey string) (created bool, err error) {
	if client == nil {
		return false, errors.New("Proxmox client is required")
	}
	kind, current, err := client.GuestConfig(ctx, plan.Node, model.BuilderVMID)
	if err == nil {
		if kind != KindQEMU {
			return false, fmt.Errorf("HOLD: VMID %d is occupied by an unowned %s guest, not the temporary builder", model.BuilderVMID, kind)
		}
		if name, _ := current["name"].(string); name != "lab-builder-01" {
			return false, fmt.Errorf("HOLD: VMID %d is not the expected temporary builder", model.BuilderVMID)
		}
		if !hasOwnerTag(currentTags(current), builderOwnerTag) {
			return false, fmt.Errorf("HOLD: VMID %d lacks canonical builder ownership proof %q", model.BuilderVMID, builderOwnerTag)
		}
		if err := DestroyBuilderVM(ctx, client, plan.Node); err != nil {
			return false, fmt.Errorf("remove existing temporary builder before a fresh build: %w", err)
		}
	} else if !IsNotFound(err) {
		return false, fmt.Errorf("inspect temporary builder: %w", err)
	}
	image, err := client.EnsureCloudImage(ctx, plan.Node, "local", plan.GatewayImage+".qcow2", plan.GatewayImageURL, plan.GatewaySHA512)
	if err != nil {
		return false, fmt.Errorf("prepare pinned builder input: %w", err)
	}
	builder := artifacts.Builder()
	params := url.Values{
		"name":      {"lab-builder-01"},
		"memory":    {strconv.Itoa(builder.MemoryMiB)},
		"cores":     {strconv.Itoa(builder.Cores)},
		"cpu":       {"host"},
		"scsihw":    {"virtio-scsi-single"},
		"ostype":    {"l26"},
		"onboot":    {"0"},
		"agent":     {"1"},
		"boot":      {"order=scsi0;ide2;net0"},
		"tags":      {strings.Join([]string{model.TagBoetticher, model.TagManaged, model.TagPlatform, builderOwnerTag}, ";")},
		"net0":      {"virtio,bridge=vmbr0,macaddr=" + model.BuilderMAC},
		"ide2":      {"local:cloudinit"},
		"ipconfig0": {"ip=dhcp"},
		"ciuser":    {model.DefaultAdminSSHUser},
	}
	cloudInit, err := RenderBuilderCloudInitWithKey(publicKey)
	if err != nil {
		return false, fmt.Errorf("render builder cloud-init: %w", err)
	}
	// Arm snippet cleanup before the first upload. A partial upload must not
	// leave VM190-specific cloud-init material behind on Proxmox.
	snippetsUploaded := true
	defer func() {
		if err != nil && snippetsUploaded {
			if cleanupErr := cleanupBuilderSnippets(ctx, client, plan.Node); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	for _, snippet := range []struct {
		key   string
		value string
	}{
		{key: "meta", value: cloudInit.MetaData},
		{key: "user", value: cloudInit.UserData},
		{key: "network", value: cloudInit.NetworkConfig},
	} {
		key, value := snippet.key, snippet.value
		if value == "" {
			return false, errors.New("builder cloud-init input is incomplete")
		}
		names := cloudInitSnippetNames(model.BuilderVMID)
		if err := client.UploadStorageText(ctx, plan.Node, "local", "snippets", names[key], value); err != nil {
			return false, fmt.Errorf("upload builder cloud-init %s: %w", key, err)
		}
	}
	params.Set("cicustom", cloudInitCICustom(model.BuilderVMID))
	params.Set("ipconfig0", "ip=dhcp")
	// Arm caller cleanup before submitting the create task. Proxmox may have
	// created the guest even when the API request or task wait reports an
	// error, and a failed attempt must not leave a dirty builder behind.
	created = true
	if err := client.CreateVM(ctx, plan.Node, model.BuilderVMID, params); err != nil {
		return created, fmt.Errorf("create temporary builder: %w", err)
	}
	snippetsUploaded = false
	upid, err := client.ImportDisk(ctx, plan.Node, model.BuilderVMID, image, plan.Storage, "qcow2")
	if err != nil {
		return created, fmt.Errorf("import builder input: %w", err)
	}
	if err := client.WaitTask(ctx, plan.Node, upid); err != nil {
		return created, fmt.Errorf("wait for builder input: %w", err)
	}
	if err := client.ResizeQEMUDisk(ctx, plan.Node, model.BuilderVMID, "scsi0", builder.DiskGiB); err != nil {
		return created, fmt.Errorf("size builder disk: %w", err)
	}
	return created, nil
}

// WaitForQEMUIPv4 waits for the guest agent to report a routable IPv4 address
// for a temporary DHCP-backed appliance. Hostnames and guessed addresses are
// not accepted as reachability evidence.
func WaitForQEMUIPv4(ctx context.Context, client *Client, node string, vmid, attempts int, interval time.Duration) (string, error) {
	if client == nil || node == "" || vmid <= 0 || attempts < 1 {
		return "", errors.New("QEMU address readiness identity is invalid")
	}
	if interval <= 0 {
		interval = time.Second
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		interfaces, err := client.QEMUAgentNetworkInterfaces(ctx, node, vmid)
		if err == nil {
			for _, iface := range interfaces {
				for _, address := range iface.IPAddresses {
					ip := net.ParseIP(address.IPAddress).To4()
					if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
						continue
					}
					return ip.String(), nil
				}
			}
		} else {
			lastErr = err
		}
		if attempt+1 < attempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", fmt.Errorf("QEMU address readiness cancelled: %w", ctx.Err())
			case <-timer.C:
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("guest agent reported no routable IPv4 address")
	}
	return "", fmt.Errorf("HOLD: QEMU guest %d did not report a routable IPv4 address after %d attempts: %w", vmid, attempts, lastErr)
}

func DestroyBuilderVM(ctx context.Context, client *Client, node string) (returnErr error) {
	if client == nil || node == "" {
		return errors.New("Proxmox client and node are required")
	}
	kind, current, err := client.GuestConfig(ctx, node, model.BuilderVMID)
	if IsNotFound(err) {
		return cleanupBuilderSnippets(ctx, client, node)
	}
	if err != nil {
		return fmt.Errorf("inspect temporary builder before destruction: %w", err)
	}
	if kind != KindQEMU {
		return fmt.Errorf("HOLD: refusing to destroy VMID %d because it is an unowned %s guest", model.BuilderVMID, kind)
	}
	if name, _ := current["name"].(string); name != "lab-builder-01" || !hasOwnerTag(currentTags(current), builderOwnerTag) {
		return fmt.Errorf("HOLD: refusing to destroy unproven VMID %d builder ownership", model.BuilderVMID)
	}
	// Once identity and ownership are proven, remove only the exact builder
	// snippets even if stopping or deletion later fails. This leaves no stale
	// VM190 bootstrap material after a bounded cleanup attempt.
	defer func() {
		if cleanupErr := cleanupBuilderSnippets(ctx, client, node); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()
	status, err := client.QEMUStatus(ctx, node, model.BuilderVMID)
	if err != nil {
		return fmt.Errorf("inspect temporary builder status: %w", err)
	}
	if status == "running" {
		if err := client.StopVM(ctx, node, model.BuilderVMID); err != nil {
			return fmt.Errorf("stop temporary builder: %w", err)
		}
	}
	if err := client.DestroyQEMU(ctx, node, model.BuilderVMID); err != nil {
		return fmt.Errorf("destroy temporary builder: %w", err)
	}
	if err := WaitForGuestAbsent(ctx, client, node, model.BuilderVMID, 30, time.Second); err != nil {
		return err
	}
	return cleanupBuilderSnippets(ctx, client, node)
}

// WaitForGuestAbsent verifies that Proxmox has finished removing a guest.
// Cleanup never treats an accepted delete request as proof that the reserved
// identity is available for a fresh builder.
func WaitForGuestAbsent(ctx context.Context, client *Client, node string, vmid, attempts int, interval time.Duration) error {
	if client == nil || node == "" || vmid <= 0 || attempts < 1 {
		return errors.New("guest absence readiness identity is invalid")
	}
	if interval <= 0 {
		interval = time.Second
	}
	for attempt := 0; attempt < attempts; attempt++ {
		_, _, err := client.GuestConfig(ctx, node, vmid)
		if IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect guest %d while waiting for removal: %w", vmid, err)
		}
		if attempt+1 < attempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("HOLD: guest %d remains present after deletion", vmid)
}

func cleanupBuilderSnippets(ctx context.Context, client *Client, node string) error {
	names := cloudInitSnippetNames(model.BuilderVMID)
	for _, name := range []string{names["meta"], names["user"], names["network"]} {
		if err := client.DeleteStorageSnippet(ctx, node, "local", name); err != nil && !IsNotFound(err) {
			return fmt.Errorf("remove builder cloud-init snippet %s: %w", name, err)
		}
	}
	return nil
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
		"iface": {"vmbr1"}, "type": {"bridge"}, "bridge_vlan_aware": {"1"}, "autostart": {"1"},
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
	if err := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge_ports": {physicalInterface}, "bridge_vlan_aware": {"1"}}); err != nil {
		return fmt.Errorf("attach %s to vmbr1: %w", physicalInterface, err)
	}
	var after []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &after); err != nil {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge_ports": {"none"}, "bridge_vlan_aware": {"1"}}); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk attach verification failed and rollback failed: %v; verification: %w", rollbackErr, err)
		}
		return fmt.Errorf("trunk attach verification failed; rollback completed: %w", err)
	}
	if !bridgeHasPort(after, "vmbr1", physicalInterface) {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge_ports": {"none"}, "bridge_vlan_aware": {"1"}}); rollbackErr != nil {
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
	if err := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge_ports": {"none"}, "bridge_vlan_aware": {"1"}}); err != nil {
		return fmt.Errorf("detach %s from vmbr1: %w", physicalInterface, err)
	}
	var after []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &after); err != nil {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge_ports": {physicalInterface}, "bridge_vlan_aware": {"1"}}); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk detach verification failed and rollback failed: %v; verification: %w", rollbackErr, err)
		}
		return fmt.Errorf("trunk detach verification failed; rollback completed: %w", err)
	}
	if bridgeHasPort(after, "vmbr1", physicalInterface) {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"bridge_ports": {physicalInterface}, "bridge_vlan_aware": {"1"}}); rollbackErr != nil {
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

func ensureQEMU(ctx context.Context, client *Client, plan Plan, guest GuestPlan) error {
	kind, current, err := client.GuestConfig(ctx, plan.Node, guest.VMID)
	if err == nil {
		if kind != KindQEMU {
			return fmt.Errorf("HOLD: VMID %d is occupied by an unowned %s guest, expected QEMU %s", guest.VMID, kind, guest.Name)
		}
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
	filename := fmt.Sprintf("%s-%s-%s.qcow2", guest.Artifact.Name, guest.Artifact.Version, guest.Artifact.Architecture)
	source := plan.ArtifactFiles[artifactKey(guest.Artifact)]
	if err := ensureArtifactInStorage(ctx, client, plan.Node, "local", "import", filename, guest.Artifact.ContentSHA256, source); err != nil {
		return fmt.Errorf("prepare qualified %s artifact: %w", guest.Name, err)
	}
	imageFileID := "local:import/" + filename
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
	if guest.Name == "lab-fw-01" && plan.CloudInitFiles.UserData != "" {
		names := cloudInitSnippetNames(guest.VMID)
		for key, value := range map[string]string{"meta": plan.CloudInitFiles.MetaData, "user": plan.CloudInitFiles.UserData, "network": plan.CloudInitFiles.NetworkConfig} {
			if value == "" {
				return errors.New("firewall cloud-init input is incomplete")
			}
			if err := client.UploadStorageText(ctx, plan.Node, "local", "snippets", names[key], value); err != nil {
				return fmt.Errorf("upload firewall cloud-init %s: %w", key, err)
			}
		}
		params.Set("cicustom", cloudInitCICustom(guest.VMID))
		params.Set("ide2", "local:cloudinit")
		params.Set("ciuser", model.DefaultAdminSSHUser)
		params.Set("ipconfig0", "ip=dhcp")
	}
	if plan.OperatorPublicKey != "" {
		if err := ValidatePublicKey(plan.OperatorPublicKey); err != nil {
			return err
		}
		// Proxmox declares this field as urlencoded and decodes it once more
		// after the application/x-www-form-urlencoded request is parsed.
		params.Set("sshkeys", url.PathEscape(plan.OperatorPublicKey))
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
	upid, err := client.ImportDisk(ctx, plan.Node, guest.VMID, imageFileID, plan.Storage, "qcow2")
	if err != nil {
		return fmt.Errorf("import gateway image into %s: %w", plan.Storage, err)
	}
	if err := client.WaitTask(ctx, plan.Node, upid); err != nil {
		return fmt.Errorf("wait for gateway image import: %w", err)
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
		serial, err := persistentVolumeSerial(volume)
		if err != nil {
			return nil, err
		}
		params[fmt.Sprintf("scsi%d", index+1)] = fmt.Sprintf("%s:%d,backup=%s,serial=%s", volume.Storage, volume.SizeGiB, backup, serial)
	}
	return params, nil
}

func validateExistingQEMUVolumes(current map[string]any, plan Plan, guest GuestPlan) error {
	for index, volume := range guest.Volumes {
		expected, err := qemuPersistentVolumeParam(plan, volume)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("scsi%d", index+1)
		observed, _ := current[key].(string)
		if observed == "" {
			return fmt.Errorf("HOLD: guest %s has no persistent volume identity for %s, expected %q", guest.Name, key, expected)
		}
		observedParts := strings.Split(observed, ",")
		if observedParts[0] != strings.Split(expected, ",")[0] {
			return fmt.Errorf("HOLD: guest %s has persistent volume %s=%q, expected storage/size %q", guest.Name, key, observed, expected)
		}
		observedOptions := make(map[string]string, len(observedParts)-1)
		for _, option := range observedParts[1:] {
			name, value, ok := strings.Cut(option, "=")
			if ok {
				observedOptions[name] = value
			}
		}
		expectedOptions := make(map[string]string)
		for _, option := range strings.Split(expected, ",")[1:] {
			name, value, ok := strings.Cut(option, "=")
			if ok {
				expectedOptions[name] = value
			}
		}
		for _, name := range []string{"backup", "serial"} {
			if observedOptions[name] != expectedOptions[name] {
				return fmt.Errorf("HOLD: guest %s has persistent volume %s option %s=%q, expected %q", guest.Name, key, name, observedOptions[name], expectedOptions[name])
			}
		}
	}
	return nil
}

func qemuPersistentVolumeParam(plan Plan, volume model.PersistentVolumeDeclaration) (string, error) {
	params, err := qemuPersistentVolumeParams(plan, GuestPlan{Volumes: []model.PersistentVolumeDeclaration{volume}})
	if err != nil {
		return "", err
	}
	return params["scsi1"], nil
}

func ensureLXC(ctx context.Context, client *Client, plan Plan, guest GuestPlan) error {
	kind, current, err := client.GuestConfig(ctx, plan.Node, guest.VMID)
	if err == nil {
		if kind != KindLXC {
			return fmt.Errorf("HOLD: VMID %d is occupied by an unowned %s guest, expected LXC %s", guest.VMID, kind, guest.Name)
		}
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
	bootstrapParams, err := lxcBootstrapKeyParams(plan.OperatorPublicKey)
	if err != nil {
		return fmt.Errorf("validate appliance bootstrap key for %s: %w", guest.Name, err)
	}
	for key, values := range bootstrapParams {
		for _, value := range values {
			params.Add(key, value)
		}
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

// lxcBootstrapKeyParams is the only operator-key input accepted by appliance
// creation. Proxmox writes this key into the container's root bootstrap
// identity; the image first-boot service copies it to labadmin and removes the
// bootstrap copy before normal deployment configuration begins.
func lxcBootstrapKeyParams(publicKey string) (url.Values, error) {
	if publicKey == "" {
		return url.Values{}, nil
	}
	if err := ValidatePublicKey(publicKey); err != nil {
		return nil, err
	}
	return url.Values{"ssh-public-keys": {publicKey}}, nil
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

func persistentVolumeSerial(volume model.PersistentVolumeDeclaration) (string, error) {
	if volume.Module == "" || volume.Guest == "" || volume.Name == "" {
		return "", errors.New("persistent volume identity is incomplete")
	}
	for _, value := range []string{volume.Module, volume.Guest, volume.Name} {
		for _, r := range value {
			if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return "", fmt.Errorf("persistent volume identity %q contains an unsafe character", value)
			}
		}
	}
	return "boetticher-" + volume.Module + "-" + volume.Guest + "-" + volume.Name, nil
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
	if found, err := verifyStoredArtifact(entries, filename, checksum, false); err != nil {
		if content != "import" || !strings.HasSuffix(err.Error(), "has no checksum evidence") {
			return err
		}
		// Import listings omit checksums. Re-upload the qualified local bytes so
		// the upload task can re-establish checksum evidence before use.
	} else if found {
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
	if err := client.UploadStorageFile(ctx, node, storage, content, source, filename, checksum); err != nil {
		return fmt.Errorf("upload %s: %w", filename, err)
	}
	entries, err = client.StorageContent(ctx, node, storage, content)
	if err != nil {
		return fmt.Errorf("verify uploaded %s artifact storage: %w", filename, err)
	}
	found, err := verifyStoredArtifact(entries, filename, checksum, content == "import")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("uploaded artifact %s is not visible in Proxmox storage", filename)
	}
	return nil
}

// verifyStoredArtifact is the post-upload identity gate. A successful upload
// task is not evidence that Proxmox stored the qualified bytes under the
// expected content identity; the storage listing must expose the same
// checksum before the artifact can be used for guest creation.
func verifyStoredArtifact(entries []StorageContent, filename, checksum string, allowMissingChecksum bool) (bool, error) {
	for _, entry := range entries {
		if entry.Filename != filename && !strings.HasSuffix(entry.VolID, "/"+filename) {
			continue
		}
		observed := entry.Checksum
		if observed == "" {
			observed = entry.CSum
		}
		if observed == "" {
			if allowMissingChecksum {
				// Import content listings omit checksums. A just-completed upload
				// task already verified the requested checksum, so its presence is
				// sufficient evidence for this post-upload check.
				return true, nil
			}
			return false, fmt.Errorf("stored artifact %s has no checksum evidence", filename)
		}
		if !strings.EqualFold(observed, checksum) {
			return false, fmt.Errorf("stored artifact %s checksum %s does not match qualified %s", filename, observed, checksum)
		}
		return true, nil
	}
	return false, nil
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
	if expected.Owner == "boetticher/core/portal" {
		if !hasOwnerTag(currentTags(current), model.TagCorePortal) {
			return fmt.Errorf("HOLD: guest %s lacks canonical ownership proof %q", expected.Name, model.TagCorePortal)
		}
	} else if expected.Owner != "" {
		module := strings.TrimPrefix(expected.Owner, "boetticher/module/")
		ownerTag := model.ModuleOwnershipTag(module)
		if ownerTag == "" || !hasOwnerTag(currentTags(current), ownerTag) {
			return fmt.Errorf("HOLD: guest %s lacks canonical ownership proof %q", expected.Name, ownerTag)
		}
	}
	return nil
}

func artifactDescription(artifact model.Artifact) string {
	return fmt.Sprintf("boetticher-artifact=%s@%s definition=%s content=%s", artifact.Name, artifact.Version, artifact.DefinitionSHA256, artifact.ContentSHA256)
}

func ensureExistingGuestTags(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) error {
	if guest.Owner == "boetticher/core/portal" {
		if !hasOwnerTag(currentTags(current), model.TagCorePortal) {
			return fmt.Errorf("HOLD: refusing to establish ownership for %s; canonical tag %q is absent", guest.Name, model.TagCorePortal)
		}
	} else if guest.Owner != "" {
		module := strings.TrimPrefix(guest.Owner, "boetticher/module/")
		ownerTag := model.ModuleOwnershipTag(module)
		if ownerTag == "" || !hasOwnerTag(currentTags(current), ownerTag) {
			return fmt.Errorf("HOLD: refusing to establish ownership for %s; canonical tag %q is absent", guest.Name, ownerTag)
		}
	}
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

func currentTags(current map[string]any) string {
	tags, _ := current["tags"].(string)
	return tags
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
