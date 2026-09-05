package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/telemetry"
	"github.com/gofastercloud/boetticher/internal/usbexport"
)

type GuestKind string

const (
	KindQEMU GuestKind = "qemu"
	KindLXC  GuestKind = "lxc"
)

type GuestPlan struct {
	Nameservers     []string                            `json:"nameservers,omitempty"`
	VMID            int                                 `json:"vmid"`
	Name            string                              `json:"name"`
	Kind            GuestKind                           `json:"kind"`
	Hostname        string                              `json:"hostname"`
	Zone            string                              `json:"zone"`
	Address         string                              `json:"address"`
	MAC             string                              `json:"mac,omitempty"`
	Gateway         string                              `json:"gateway"`
	VLAN            int                                 `json:"vlan"`
	Cores           int                                 `json:"cores"`
	MemoryMiB       int                                 `json:"memory_mib"`
	DiskGiB         int                                 `json:"disk_gib"`
	Monitoring      bool                                `json:"monitoring"`
	Backup          bool                                `json:"backup"`
	Tags            []string                            `json:"tags,omitempty"`
	NICs            []GuestNIC                          `json:"nics,omitempty"`
	Owner           string                              `json:"owner,omitempty"`
	Artifact        model.Artifact                      `json:"artifact,omitempty"`
	Persistent      []model.PersistentState             `json:"persistent,omitempty"`
	Volumes         []model.PersistentVolumeDeclaration `json:"volumes,omitempty"`
	Security        model.GuestSecurityDeclaration      `json:"security,omitempty"`
	ManagedUSBSlots []string                            `json:"managed_usb_slots,omitempty"`
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
	ModelRevision string `json:"model_revision"`
	ManagedBy     string `json:"managed_by"`
	Node          string `json:"node"`
	Storage       string `json:"storage"`
	// Nameservers is the platform resolver pair applied to every LXC's
	// Proxmox network contract. It is runtime planning data rather than a
	// canonical model projection; pinning it prevents PVE from restoring its
	// HOME resolver into /etc/resolv.conf after a guest reboot.
	Nameservers     []string    `json:"-"`
	GatewayImage    string      `json:"gateway_image"`
	GatewayImageURL string      `json:"gateway_image_url"`
	GatewaySHA512   string      `json:"gateway_sha512"`
	Guests          []GuestPlan `json:"guests"`
	// ArtifactFiles is controller-local evidence and is intentionally excluded
	// from canonical model output. It maps qualified definitions to the exact
	// bytes that may be imported into Proxmox.
	ArtifactFiles        map[string]string `json:"-"`
	OperatorPublicKey    string            `json:"-"`
	CloudInitFiles       CloudInitFiles    `json:"-"`
	DestructiveConfirmed bool              `json:"-"`
	// ForceFirewallRootReplacement is a deliberately narrow recovery action.
	// It replaces only the managed firewall root disk after the attached
	// declared persistent volumes have been proven, and never applies to any
	// other appliance.
	ForceFirewallRootReplacement bool `json:"-"`
	// ForceLegacyLXCRecreation is a separately confirmed recovery action for
	// Boetticher-owned LXCs that still use the exact legacy local raw layout.
	// It discards their declared state and recreates them on the planned
	// storage; QEMU guests and non-legacy LXCs are never selected.
	ForceLegacyLXCRecreation bool `json:"-"`
	// PrivilegedRunner is the already-authorized, bounded root bootstrap path.
	// Proxmox rejects /dev/net/tun on the scoped API identity, so device-bearing
	// LXC creation applies the exact device setting through this path after the
	// unprivileged container has been created. It is runtime-only and never part
	// of serialized plan or evidence output.
	PrivilegedRunner  ArgsCommandRunner `json:"-"`
	PrivilegedAddress string            `json:"-"`
	PrivilegedUser    string            `json:"-"`
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

type ipLinkHardware struct {
	Iface    string `json:"ifname"`
	LinkType string `json:"link_type"`
	Address  string `json:"address"`
}

// enrichNetworkInterfaceHardware fills the stable hardware identity that
// some Proxmox versions omit for an otherwise valid physical interface. The
// read-only Linux link evidence is joined by the exact interface name and is
// accepted only for Ethernet devices with a six-byte MAC address.
func enrichNetworkInterfaceHardware(ctx context.Context, runner CommandRunner, address, user string, interfaces []NetworkInterface) error {
	if runner == nil || len(interfaces) == 0 {
		return nil
	}
	output, err := runner.Run(ctx, address, user, "ip -j link show")
	if err != nil {
		return fmt.Errorf("read Linux physical interface identity: %w", err)
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return nil
	}
	var links []ipLinkHardware
	if err := json.Unmarshal(output, &links); err != nil {
		return fmt.Errorf("decode Linux physical interface identity: %w", err)
	}
	byName := make(map[string]string, len(links))
	for _, link := range links {
		if link.Iface == "" || link.LinkType != "ether" {
			continue
		}
		mac, err := net.ParseMAC(link.Address)
		if err != nil || len(mac) != 6 {
			continue
		}
		byName[link.Iface] = strings.ToLower(mac.String())
	}
	for index := range interfaces {
		if interfaces[index].Type == "eth" && interfaces[index].HWAddr == "" {
			interfaces[index].HWAddr = byName[interfaces[index].Iface]
		}
	}
	return nil
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
	infraZone, err := s.ZoneForType(model.ZoneTypeInfrastructure)
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
	usbManifests, err := usbexport.PlanFromSite(s)
	if err != nil {
		return Plan{}, err
	}
	usbSlots := map[int][]string{}
	for _, manifest := range usbManifests {
		usbSlots[manifest.VMID] = append([]string(nil), manifest.ManagedSlots...)
	}
	guests := make([]GuestPlan, 0, len(s.PlatformComponents()))
	for _, component := range s.PlatformComponents() {
		if component.VMID == 0 {
			continue
		}
		guestMAC := component.MAC
		if guestMAC == "" && component.Module != "" {
			guestMAC = networkmodel.ManagedModuleMAC(component.VMID)
		}
		guest := GuestPlan{
			Nameservers: model.EffectiveResolvers(s, component),
			VMID:        component.VMID, Name: component.Name, Hostname: component.Hostname, Zone: component.Zone,
			Address: component.Address, MAC: guestMAC, Gateway: gatewayFor(component.Zone), VLAN: vlanFor(s, component.Zone),
			Kind: KindLXC, Cores: 2, MemoryMiB: 1024, DiskGiB: 8,
			Monitoring: component.Monitoring, Backup: component.Backup, Tags: componentTags(s, component.Name), ManagedUSBSlots: usbSlots[component.VMID],
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
					guest.Security = declaration.Security
					guest.Security.Devices = append([]model.DeviceRequirement(nil), declaration.Security.Devices...)
					sort.SliceStable(guest.Security.Devices, func(i, j int) bool {
						left, right := guest.Security.Devices[i].Name, guest.Security.Devices[j].Name
						if left == "" {
							left = guest.Security.Devices[i].Path
						}
						if right == "" {
							right = guest.Security.Devices[j].Path
						}
						return left < right
					})
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
				if artifact, artifactErr := artifacts.ArtifactFor(component.Module); artifactErr == nil {
					guest.Artifact = artifact
				}
			}
			guest.Owner = "boetticher/module/" + component.Module
			if len(guest.Persistent) == 0 {
				guest.Persistent = fixturePersistent(component.Module, component.Name)
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
	return Plan{ModelRevision: revision, ManagedBy: "boetticher", Node: s.LogicalProxmoxIdentity, Storage: guestStorage, Nameservers: append([]string(nil), infraZone.DNSAddresses...), GatewayImage: model.QualifiedGatewayImage, GatewayImageURL: model.QualifiedGatewayImageURL, GatewaySHA512: model.QualifiedGatewayImageSHA512, Guests: guests, ArtifactFiles: map[string]string{}}, nil
}

// deploymentOrder follows the resolved module graph carried by Site. This
// keeps appliance ordering correct for capability providers and future
// first-party modules without making VMID order an implicit dependency.
func deploymentOrder(s model.Site, guest GuestPlan) int {
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
	return strings.Join([]string{artifact.Name, artifact.Version, artifact.Architecture, artifact.Kind, artifact.ContentSHA256}, "|")
}

// ResolveQualifiedArtifacts binds every appliance in a Proxmox plan to an
// authenticated release artifact or local maintainer artifact. It does not
// mutate Proxmox or the canonical model. Local artifacts still require a
// qualified evidence record; imported releases are authenticated by manifest
// signature and exact artifact bytes.
func ResolveQualifiedArtifacts(root string, plan Plan, require bool) (Plan, error) {
	resolved := plan
	resolved.Guests = append([]GuestPlan(nil), plan.Guests...)
	resolved.ArtifactFiles = map[string]string{}
	_, _, importedErr := artifacts.ImportedReleaseManifest(root)
	importedRelease := importedErr == nil
	if importedErr != nil && !errors.Is(importedErr, os.ErrNotExist) {
		releaseManifestPath := filepath.Join(root, "generated", "release", artifacts.ReleaseManifestName)
		if _, statErr := os.Stat(releaseManifestPath); statErr == nil {
			return Plan{}, fmt.Errorf("HOLD: imported release is invalid: %w", importedErr)
		}
	}
	for index := range resolved.Guests {
		guest := &resolved.Guests[index]
		if guest.Artifact.Name == "" {
			continue
		}
		var artifact model.Artifact
		var evidence artifacts.Evidence
		var err error
		if importedRelease {
			artifact, evidence, err = artifacts.ResolveImportedArtifact(root, guest.Artifact)
		} else {
			artifact, evidence, err = artifacts.ResolveArtifactEvidence(root, guest.Artifact)
		}
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
		state = &model.PersistentState{Name: "pulse-state", Guest: guest, Path: "/var/lib/pulse", Kind: "monitoring-state", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}
	case "firewall":
		state = &model.PersistentState{Name: "kea-leases", Guest: guest, Path: "/var/lib/kea", Kind: "lease-state", Backup: true, Replacement: "retain-across-rootfs-replacement"}
	}
	result := []model.PersistentState{identity}
	if state != nil {
		result = append(result, *state)
	}
	if module == "firewall" {
		result = append(result, model.PersistentState{Name: "firewall-telemetry", Guest: guest, Path: firewall.TelemetryStatePath, Kind: "firewall-telemetry-database", Backup: true, Sensitive: false, Replacement: "retain-across-rootfs-replacement"})
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

func gatewayNICs(s model.Site) []GuestNIC {
	nics := []GuestNIC{{Name: "wan0", Bridge: "vmbr0", Method: "dhcp", MAC: s.Gateway.Upstream.MAC}}
	for _, zoneType := range []model.ZoneType{model.ZoneTypeTrusted, model.ZoneTypeServers, model.ZoneTypeSandbox, model.ZoneTypeManagement, model.ZoneTypeTransit, model.ZoneTypeInfrastructure} {
		zone, err := s.ZoneForType(zoneType)
		if err != nil {
			continue
		}
		nics = append(nics, GuestNIC{Name: strings.ToLower(zone.Name) + "0", Bridge: "vmbr1", VLAN: zone.VLAN, Address: zone.Gateway, Method: "static", MAC: model.GatewayInterfaceMAC(len(nics) + 1)})
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

func lxcNetworkParam(guest GuestPlan) string {
	if guest.MAC == model.ArrGuestMAC {
		return fmt.Sprintf("name=eth0,bridge=vmbr1,tag=%d,firewall=1,hwaddr=%s,ip=dhcp", guest.VLAN, guest.MAC)
	}
	if guest.MAC != "" {
		return fmt.Sprintf("name=eth0,bridge=vmbr1,tag=%d,firewall=1,hwaddr=%s,ip=%s/24,gw=%s", guest.VLAN, guest.MAC, guest.Address, guest.Gateway)
	}
	return fmt.Sprintf("name=eth0,bridge=vmbr1,tag=%d,firewall=1,ip=%s/24,gw=%s", guest.VLAN, guest.Address, gatewayFor(guest.Zone))
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
		if !matches || guest.Kind != KindLXC {
			continue
		}
		found = true
		if err := ensureLXC(ctx, client, plan, guest); err != nil {
			return err
		}
		if err := client.EnsureLXCRunning(ctx, plan.Node, guest.VMID); err != nil {
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

// EnsureVirtualOnlyBridge keeps the Boetticher-owned vmbr1 bridge present but
// deliberately unclaimed. It removes a single stale physical member only
// after DetachTrunk has proved that member is neither the HOME/bootstrap path
// nor vmbr0's upstream. Ambiguous multi-port bridges remain a hard failure.
func EnsureVirtualOnlyBridge(ctx context.Context, client *Client, node, bootstrapAddress string) error {
	if err := EnsureVirtualBridge(ctx, client, node); err != nil {
		return err
	}
	var interfaces []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &interfaces); err != nil {
		return fmt.Errorf("inspect virtual-only vmbr1: %w", err)
	}
	for _, iface := range interfaces {
		if iface.Iface != "vmbr1" {
			continue
		}
		members := strings.Fields(iface.BridgePorts)
		if len(members) == 0 || (len(members) == 1 && members[0] == "none") {
			return nil
		}
		if len(members) != 1 || !safeInterfaceName(members[0]) {
			return fmt.Errorf("HOLD: virtual-only vmbr1 has ambiguous physical members %q", iface.BridgePorts)
		}
		if err := DetachTrunk(ctx, client, node, members[0], bootstrapAddress); err != nil {
			return fmt.Errorf("detach stale virtual-only vmbr1 member %s: %w", members[0], err)
		}
		return nil
	}
	return errors.New("vmbr1 is absent after virtual-only bridge reconciliation")
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
	if err := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"type": {"bridge"}, "bridge_ports": {physicalInterface}, "bridge_vlan_aware": {"1"}}); err != nil {
		return fmt.Errorf("attach %s to vmbr1: %w", physicalInterface, err)
	}
	if err := client.ReloadNodeNetwork(ctx, node); err != nil {
		return fmt.Errorf("reload network after attaching %s: %w", physicalInterface, err)
	}
	var after []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &after); err != nil {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", virtualOnlyBridgeParams()); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk attach verification failed and rollback failed: %v; verification: %w", rollbackErr, err)
		}
		return fmt.Errorf("trunk attach verification failed; rollback completed: %w", err)
	}
	if !bridgeHasPort(after, "vmbr1", physicalInterface) {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", virtualOnlyBridgeParams()); rollbackErr != nil {
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
	if err := client.UpdateNodeNetwork(ctx, node, "vmbr1", virtualOnlyBridgeParams()); err != nil {
		return fmt.Errorf("detach %s from vmbr1: %w", physicalInterface, err)
	}
	if err := client.ReloadNodeNetwork(ctx, node); err != nil {
		return fmt.Errorf("reload network after detaching %s: %w", physicalInterface, err)
	}
	var after []NetworkInterface
	if err := client.NodeNetwork(ctx, node, &after); err != nil {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"type": {"bridge"}, "bridge_ports": {physicalInterface}, "bridge_vlan_aware": {"1"}}); rollbackErr != nil {
			return fmt.Errorf("HOLD: trunk detach verification failed and rollback failed: %v; verification: %w", rollbackErr, err)
		}
		return fmt.Errorf("trunk detach verification failed; rollback completed: %w", err)
	}
	if bridgeHasPort(after, "vmbr1", physicalInterface) {
		if rollbackErr := client.UpdateNodeNetwork(ctx, node, "vmbr1", url.Values{"type": {"bridge"}, "bridge_ports": {physicalInterface}, "bridge_vlan_aware": {"1"}}); rollbackErr != nil {
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

// virtualOnlyBridgeParams clears bridge ports through the Proxmox API's
// supported delete field. PVE 9 rejects the old literal bridge_ports=none as
// an interface name, while --delete bridge_ports preserves the desired empty
// virtual-only bridge across supported releases.
func virtualOnlyBridgeParams() url.Values {
	return url.Values{"type": {"bridge"}, "delete": {"bridge_ports"}, "bridge_vlan_aware": {"1"}}
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
		if err := validateExistingGuestIdentityFields(current, guest); err != nil {
			return err
		}
		forceFirewallRootReplacement := plan.ForceFirewallRootReplacement && guest.Name == "lab-fw-01"
		if guestArtifactNeedsReplacement(current, guest) || forceFirewallRootReplacement {
			if !plan.DestructiveConfirmed {
				if forceFirewallRootReplacement {
					return fmt.Errorf("HOLD: managed firewall root replacement requires --confirm")
				}
				return fmt.Errorf("HOLD: guest %s has artifact identity mismatch; appliance replacement requires --confirm", guest.Name)
			}
			if forceFirewallRootReplacement {
				if err := validateForcedFirewallRootReplacementVolumes(current, plan, guest); err != nil {
					return err
				}
			}
			if err := replaceQEMURootDisk(ctx, client, plan, guest); err != nil {
				return err
			}
			current["description"] = artifactDescription(guest.Artifact)
		} else if guest.Name == "lab-fw-01" && plan.CloudInitFiles.UserData != "" {
			if err := uploadFirewallCloudInit(ctx, client, plan, guest.VMID); err != nil {
				return err
			}
		}
		if err := reconcileQEMUNetworkInterfaces(ctx, client, plan, guest, current); err != nil {
			return err
		}
		if err := migrateLegacyQEMUPersistentVolumeSerials(ctx, client, plan, guest, current); err != nil {
			return err
		}
		if err := migrateQEMUPersistentVolumes(ctx, client, plan, guest, current); err != nil {
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
		if err := uploadFirewallCloudInit(ctx, client, plan, guest.VMID); err != nil {
			return err
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
	nicParams, err := qemuNICParams(guest)
	if err != nil {
		return fmt.Errorf("validate network interfaces for %s: %w", guest.Name, err)
	}
	for key, value := range nicParams {
		params.Set(key, value)
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
		expectedParts := strings.Split(expected, ",")
		expectedStorage, expectedSize, expectedOK := strings.Cut(expectedParts[0], ":")
		observedStorage, _, observedOK := strings.Cut(observedParts[0], ":")
		if !expectedOK || !observedOK || observedStorage != expectedStorage {
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
		for _, option := range expectedParts[1:] {
			name, value, ok := strings.Cut(option, "=")
			if ok {
				expectedOptions[name] = value
			}
		}
		if size := observedOptions["size"]; size != "" && size != expectedSize+"G" {
			return fmt.Errorf("HOLD: guest %s has persistent volume %s=%q, expected storage/size %q", guest.Name, key, observed, expected)
		}
		for _, name := range []string{"backup", "serial"} {
			if observedOptions[name] != expectedOptions[name] {
				return fmt.Errorf("HOLD: guest %s has persistent volume %s option %s=%q, expected %q", guest.Name, key, name, observedOptions[name], expectedOptions[name])
			}
		}
	}
	return nil
}

func validateNoUndeclaredQEMUPersistentVolumes(current map[string]any, expected GuestPlan) error {
	for key := range current {
		if strings.HasPrefix(key, "scsi") {
			index, ok := qemuSCSIIndex(key)
			if ok && index == 0 {
				continue
			}
			if !ok || index > len(expected.Volumes) {
				return fmt.Errorf("HOLD: guest %s has an undeclared persistent volume %s", expected.Name, key)
			}
			continue
		}
		for _, prefix := range []string{"sata", "virtio", "efidisk", "tpmstate", "unused"} {
			if strings.HasPrefix(key, prefix) {
				return fmt.Errorf("HOLD: guest %s has an undeclared persistent volume %s", expected.Name, key)
			}
		}
		if strings.HasPrefix(key, "ide") && key != "ide2" {
			return fmt.Errorf("HOLD: guest %s has an undeclared persistent volume %s", expected.Name, key)
		}
		if key == "ide2" {
			observed, _ := current[key].(string)
			if observed != "local:cloudinit" {
				return fmt.Errorf("HOLD: guest %s has an unexpected auxiliary disk %s", expected.Name, key)
			}
		}
	}
	return nil
}

// validateForcedFirewallRootReplacementVolumes proves that a manual firewall
// root recovery cannot detach, overwrite, or silently adopt a persistent disk.
// Storage migration remains permitted afterwards, so the source storage does
// not need to equal the current declaration; its stable volume identity does.
func validateForcedFirewallRootReplacementVolumes(current map[string]any, plan Plan, guest GuestPlan) error {
	for key := range current {
		index, ok := qemuSCSIIndex(key)
		if !ok || index == 0 {
			continue
		}
		if index > len(guest.Volumes) {
			return fmt.Errorf("HOLD: refusing forced firewall root replacement; guest %s has undeclared persistent volume %s", guest.Name, key)
		}
	}
	for index, volume := range guest.Volumes {
		expected, err := qemuPersistentVolumeParam(plan, volume)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("scsi%d", index+1)
		observed, _ := current[key].(string)
		if !qemuVolumeMatchesPersistentIdentity(observed, expected) {
			return fmt.Errorf("HOLD: refusing forced firewall root replacement; persistent volume %s=%q does not prove the declared contract %q", key, observed, expected)
		}
	}
	return nil
}

func qemuSCSIIndex(value string) (int, bool) {
	if !strings.HasPrefix(value, "scsi") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(value, "scsi"))
	if err != nil || index < 0 || value != "scsi"+strconv.Itoa(index) {
		return 0, false
	}
	return index, true
}

func qemuPersistentVolumeParam(plan Plan, volume model.PersistentVolumeDeclaration) (string, error) {
	params, err := qemuPersistentVolumeParams(plan, GuestPlan{Volumes: []model.PersistentVolumeDeclaration{volume}})
	if err != nil {
		return "", err
	}
	return params["scsi1"], nil
}

func qemuNICParams(guest GuestPlan) (map[string]string, error) {
	params := map[string]string{}
	for index, nic := range guest.NICs {
		value, err := qemuNICParam(nic)
		if err != nil {
			return nil, err
		}
		params[fmt.Sprintf("net%d", index)] = value
	}
	return params, nil
}

func qemuNICParam(nic GuestNIC) (string, error) {
	if !safeInterfaceName(nic.Name) || !safeInterfaceName(nic.Bridge) || nic.VLAN < 0 || nic.VLAN > 4094 {
		return "", fmt.Errorf("network interface %q has an unsafe name, bridge, or VLAN", nic.Name)
	}
	mac, err := net.ParseMAC(nic.MAC)
	if err != nil || len(mac) != 6 {
		return "", fmt.Errorf("network interface %q has an invalid MAC identity", nic.Name)
	}
	value := fmt.Sprintf("virtio,bridge=%s,firewall=1,macaddr=%s", nic.Bridge, strings.ToLower(mac.String()))
	if nic.VLAN != 0 {
		value += fmt.Sprintf(",tag=%d", nic.VLAN)
	}
	return value, nil
}

// reconcileQEMUNetworkInterfaces keeps the owned appliance's Proxmox NIC
// contract aligned with the cloud-init transport contract. This prevents an
// old VM MAC from making a replacement firewall unbootable. Unknown NICs are
// held rather than removed, and a previously running guest is restored if a
// configuration update fails.
func reconcileQEMUNetworkInterfaces(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) (err error) {
	params, err := qemuNICReconciliationParams(current, guest)
	if err != nil {
		return err
	}
	if len(params) == 0 {
		return nil
	}

	refreshed := map[string]any{}
	if err := client.QEMUConfig(ctx, plan.Node, guest.VMID, &refreshed); err != nil {
		return fmt.Errorf("inspect %s before network reconciliation: %w", guest.Name, err)
	}
	params, err = qemuNICReconciliationParams(refreshed, guest)
	if err != nil {
		return err
	}
	if len(params) == 0 {
		replaceQEMUConfig(current, refreshed)
		return nil
	}

	status, err := client.QEMUStatus(ctx, plan.Node, guest.VMID)
	if err != nil {
		return fmt.Errorf("inspect %s status before network reconciliation: %w", guest.Name, err)
	}
	if status != "running" && status != "stopped" {
		return fmt.Errorf("HOLD: guest %s is %q; refusing network reconciliation outside a running or stopped state", guest.Name, status)
	}
	wasRunning := status == "running"
	if wasRunning {
		if err := client.StopVM(ctx, plan.Node, guest.VMID); err != nil {
			return fmt.Errorf("stop %s before network reconciliation: %w", guest.Name, err)
		}
		defer func() {
			if startErr := client.StartVM(ctx, plan.Node, guest.VMID); startErr != nil {
				if err == nil {
					err = fmt.Errorf("restore %s after network reconciliation: %w", guest.Name, startErr)
				} else {
					err = fmt.Errorf("%w; additionally failed to restore %s after network reconciliation: %v", err, guest.Name, startErr)
				}
			}
		}()
	}

	refreshed = map[string]any{}
	if err := client.QEMUConfig(ctx, plan.Node, guest.VMID, &refreshed); err != nil {
		return fmt.Errorf("inspect %s before applying network reconciliation: %w", guest.Name, err)
	}
	params, err = qemuNICReconciliationParams(refreshed, guest)
	if err != nil {
		return err
	}
	if len(params) == 0 {
		replaceQEMUConfig(current, refreshed)
		return nil
	}
	if err := client.SetVMConfig(ctx, plan.Node, guest.VMID, params); err != nil {
		return fmt.Errorf("reconcile network interfaces for %s: %w", guest.Name, err)
	}

	refreshed = map[string]any{}
	if err := client.QEMUConfig(ctx, plan.Node, guest.VMID, &refreshed); err != nil {
		return fmt.Errorf("verify %s network reconciliation: %w", guest.Name, err)
	}
	if err := validateExistingQEMUNetworkInterfaces(refreshed, guest); err != nil {
		return err
	}
	replaceQEMUConfig(current, refreshed)
	return nil
}

func qemuNICReconciliationParams(current map[string]any, guest GuestPlan) (url.Values, error) {
	if err := validateNoUndeclaredQEMUNetworkInterfaces(current, guest); err != nil {
		return nil, err
	}
	params := url.Values{}
	for index, nic := range guest.NICs {
		key := fmt.Sprintf("net%d", index)
		observed, _ := current[key].(string)
		if qemuNICMatches(observed, nic) {
			continue
		}
		value, err := qemuNICParam(nic)
		if err != nil {
			return nil, err
		}
		params.Set(key, value)
	}
	return params, nil
}

func validateExistingQEMUNetworkInterfaces(current map[string]any, guest GuestPlan) error {
	if err := validateNoUndeclaredQEMUNetworkInterfaces(current, guest); err != nil {
		return err
	}
	for index, nic := range guest.NICs {
		key := fmt.Sprintf("net%d", index)
		observed, _ := current[key].(string)
		if !qemuNICMatches(observed, nic) {
			return fmt.Errorf("HOLD: guest %s has network interface %s=%q, expected the declared %s contract", guest.Name, key, observed, nic.Name)
		}
	}
	return nil
}

func validateNoUndeclaredQEMUNetworkInterfaces(current map[string]any, guest GuestPlan) error {
	for key := range current {
		if !strings.HasPrefix(key, "net") {
			continue
		}
		index, ok := qemuNICIndex(key)
		if !ok || index >= len(guest.NICs) {
			return fmt.Errorf("HOLD: guest %s has undeclared network interface %s", guest.Name, key)
		}
	}
	return nil
}

func qemuNICIndex(value string) (int, bool) {
	if !strings.HasPrefix(value, "net") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(value, "net"))
	if err != nil || index < 0 || value != "net"+strconv.Itoa(index) {
		return 0, false
	}
	return index, true
}

func qemuNICMatches(observed string, nic GuestNIC) bool {
	parts := strings.Split(observed, ",")
	if len(parts) == 0 {
		return false
	}
	model, inlineMAC, hasInlineMAC := strings.Cut(parts[0], "=")
	if model != "virtio" {
		return false
	}
	options := qemuVolumeOptions(parts[1:])
	optionMAC := options["macaddr"]
	if hasInlineMAC && optionMAC != "" && !strings.EqualFold(inlineMAC, optionMAC) {
		return false
	}
	observedMAC := inlineMAC
	if observedMAC == "" {
		observedMAC = optionMAC
	}
	if !strings.EqualFold(observedMAC, nic.MAC) || options["bridge"] != nic.Bridge || options["firewall"] != "1" {
		return false
	}
	if nic.VLAN == 0 {
		return options["tag"] == ""
	}
	return options["tag"] == strconv.Itoa(nic.VLAN)
}

func replaceQEMUConfig(current, refreshed map[string]any) {
	for key := range current {
		delete(current, key)
	}
	for key, value := range refreshed {
		current[key] = value
	}
}

func replaceLXCConfig(current, refreshed map[string]any) {
	for key := range current {
		delete(current, key)
	}
	for key, value := range refreshed {
		current[key] = value
	}
}

func ensureLXC(ctx context.Context, client *Client, plan Plan, guest GuestPlan) error {
	return ensureLXCWithRetainedVolumes(ctx, client, plan, guest, nil)
}

// ensureLXCWithRetainedVolumes carries already-proven persistent mount-point
// references through an explicitly confirmed rootfs replacement. It never
// turns a retained volume into a size-only allocation request.
func ensureLXCWithRetainedVolumes(ctx context.Context, client *Client, plan Plan, guest GuestPlan, retained map[string]string) error {
	if err := validateLXCDeviceContract(guest); err != nil {
		return err
	}
	kind, current, err := client.GuestConfig(ctx, plan.Node, guest.VMID)
	if err == nil {
		if kind != KindLXC {
			return fmt.Errorf("HOLD: VMID %d is occupied by an unowned %s guest, expected LXC %s", guest.VMID, kind, guest.Name)
		}
		if plan.ForceLegacyLXCRecreation {
			recreate, err := legacyLXCRecreationRequired(current, guest)
			if err != nil {
				return err
			}
			if recreate {
				if !plan.DestructiveConfirmed {
					return fmt.Errorf("HOLD: legacy LXC recreation requires --confirm")
				}
				if err := prepareLegacyLXCRecreation(ctx, client, plan, guest); err != nil {
					return err
				}
				if err := discardLegacyLXC(ctx, client, plan, guest); err != nil {
					return err
				}
				recreatedPlan := plan
				recreatedPlan.ForceLegacyLXCRecreation = false
				return ensureLXCWithRetainedVolumes(ctx, client, recreatedPlan, guest, nil)
			}
		}
		if err := validateExistingGuestIdentityFields(current, guest); err != nil {
			return fmt.Errorf("HOLD: refusing to reconcile unowned container %s: %w", guest.Name, err)
		}
		if err := ensureGuestMACFilter(ctx, client, plan, guest); err != nil {
			return err
		}
		if err := validateNoUndeclaredLXCVolumes(current, guest); err != nil {
			return err
		}
		if err := migrateLXCPersistentVolumes(ctx, client, plan, guest, current); err != nil {
			return err
		}
		if err := validateExistingGuestVolumes(current, guest); err != nil {
			return err
		}
		if guestArtifactNeedsReplacement(current, guest) {
			if !plan.DestructiveConfirmed {
				return fmt.Errorf("HOLD: guest %s has artifact identity mismatch; appliance replacement requires --confirm", guest.Name)
			}
			retainedVolumes, err := replaceLXC(ctx, client, plan, guest, current)
			if err != nil {
				return err
			}
			return ensureLXCWithRetainedVolumes(ctx, client, plan, guest, retainedVolumes)
		}
		if err := validateExistingGuestIdentity(current, guest); err != nil {
			return err
		}
		if err := ensureExistingLXCNameserver(ctx, client, plan, guest, current); err != nil {
			return err
		}
		return ensureExistingGuestTags(ctx, client, plan, guest, current)
	}
	if !IsNotFound(err) {
		return fmt.Errorf("inspect container %s: %w", guest.Name, err)
	}
	if err := validateLXCPrivilegedDeviceAuthority(plan, guest); err != nil {
		return err
	}
	template, err := lxcTemplate(ctx, client, plan, guest)
	if err != nil {
		return err
	}
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
		"net0":         {lxcNetworkParam(guest)},
	}
	if servers := guestNameservers(plan, guest); len(servers) > 0 {
		params.Set("nameserver", strings.Join(servers, " "))
	}
	if guest.Security.Unprivileged {
		params.Set("unprivileged", "1")
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
		key := fmt.Sprintf("mp%d", index)
		if retained != nil {
			value, ok := retained[key]
			if !ok {
				return fmt.Errorf("HOLD: retained persistent volume %s for %s is absent", key, guest.Name)
			}
			expected, err := persistentVolumeParam(volume)
			if err != nil {
				return fmt.Errorf("validate retained persistent volume %s for %s: %w", volume.Name, guest.Name, err)
			}
			if !lxcPersistentVolumeMatches(value, expected, guest.VMID, index+1) {
				return fmt.Errorf("HOLD: retained persistent volume %s for %s does not prove the declared storage, canonical volume identity, mount path, backup setting, and size", key, guest.Name)
			}
			params.Set(key, value)
			continue
		}
		value, err := persistentVolumeParam(volume)
		if err != nil {
			return fmt.Errorf("validate persistent volume %s for %s: %w", volume.Name, guest.Name, err)
		}
		params.Set(key, value)
	}
	if retained != nil && len(retained) != len(guest.Volumes) {
		return fmt.Errorf("HOLD: retained persistent volumes for %s do not match the declared volume count", guest.Name)
	}
	if err := client.CreateLXC(ctx, plan.Node, guest.VMID, params); err != nil {
		return fmt.Errorf("create container %s: %w", guest.Name, err)
	}
	if err := configureLXCDevices(ctx, plan, guest); err != nil {
		return fmt.Errorf("HOLD: configure created container %s security contract: %w", guest.Name, err)
	}
	// Creation is not sufficient evidence that Proxmox applied the security
	// contract. Inspect the resulting object before ProvisionModule/Provision
	// can issue a start request. A missing or altered device allowance is a
	// HOLD; the newly created guest is never started or configured further.
	kind, current, err = client.GuestConfig(ctx, plan.Node, guest.VMID)
	if err != nil {
		return fmt.Errorf("HOLD: verify created container %s security contract: %w", guest.Name, err)
	}
	if kind != KindLXC {
		return fmt.Errorf("HOLD: created guest %s was reported as %s, expected LXC", guest.Name, kind)
	}
	if err := validateExistingGuestIdentity(current, guest); err != nil {
		return fmt.Errorf("HOLD: verify created container %s identity/security contract: %w", guest.Name, err)
	}
	if err := validateExistingGuestVolumes(current, guest); err != nil {
		return fmt.Errorf("HOLD: verify created container %s persistent volumes: %w", guest.Name, err)
	}
	if err := ensureGuestMACFilter(ctx, client, plan, guest); err != nil {
		return err
	}
	return nil
}

// ensureGuestMACFilter enables Proxmox's guest-level MAC filtering for module
// guests with a declared stable MAC. This is the hypervisor/bridge boundary
// that prevents a compromised guest from replacing the MAC used by the
// gateway's source-identity rules. Policies remain ACCEPT so Boetticher's
// managed gateway remains the owner of service authorization.
func ensureGuestMACFilter(ctx context.Context, client *Client, plan Plan, guest GuestPlan) error {
	if guest.MAC == "" || guest.Owner == "" {
		return nil
	}
	if err := client.SetGuestNetworkFilters(ctx, plan.Node, guest.Kind, guest.VMID, guest.MAC != model.ArrGuestMAC); err != nil {
		return fmt.Errorf("HOLD: enable Proxmox MAC filtering for %s: %w", guest.Name, err)
	}
	return nil
}

func lxcTemplate(ctx context.Context, client *Client, plan Plan, guest GuestPlan) (string, error) {
	if guest.Artifact.Name == "" || guest.Artifact.DefinitionSHA256 == "" {
		return "", fmt.Errorf("HOLD: guest %s has no resolved appliance artifact", guest.Name)
	}
	if guest.Artifact.ContentSHA256 == "" {
		return "", fmt.Errorf("NOT BUILT: guest %s artifact %s has no qualified content checksum", guest.Name, guest.Artifact.Name)
	}
	filename := guest.Artifact.Name + "-" + guest.Artifact.Version + "-" + guest.Artifact.Architecture + ".tar.zst"
	if err := ensureArtifactInStorage(ctx, client, plan.Node, "local", "vztmpl", filename, guest.Artifact.ContentSHA256, plan.ArtifactFiles[artifactKey(guest.Artifact)]); err != nil {
		return "", fmt.Errorf("prepare appliance template for %s: %w", guest.Name, err)
	}
	return "local:vztmpl/" + filename, nil
}

func prepareLegacyLXCRecreation(ctx context.Context, client *Client, plan Plan, guest GuestPlan) error {
	if err := validateLXCPrivilegedDeviceAuthority(plan, guest); err != nil {
		return err
	}
	if _, err := lxcBootstrapKeyParams(plan.OperatorPublicKey); err != nil {
		return fmt.Errorf("validate appliance bootstrap key for %s before legacy LXC recreation: %w", guest.Name, err)
	}
	for _, volume := range guest.Volumes {
		if _, err := persistentVolumeParam(volume); err != nil {
			return fmt.Errorf("validate persistent volume %s for %s before legacy LXC recreation: %w", volume.Name, guest.Name, err)
		}
	}
	_, err := lxcTemplate(ctx, client, plan, guest)
	return err
}

func legacyLXCRecreationRequired(current map[string]any, guest GuestPlan) (bool, error) {
	rootfs, _ := current["rootfs"].(string)
	rootfsStorage := lxcVolumeStorageID(rootfs)
	if rootfsStorage == "" {
		return false, fmt.Errorf("HOLD: guest %s has malformed rootfs identity", guest.Name)
	}
	legacy := rootfsStorage == "local"
	for index := range guest.Volumes {
		mountpoint := fmt.Sprintf("mp%d", index)
		observed, _ := current[mountpoint].(string)
		storage := lxcVolumeStorageID(observed)
		if storage == "" {
			return false, fmt.Errorf("HOLD: guest %s has malformed persistent volume %s", guest.Name, mountpoint)
		}
		legacy = legacy || storage == "local"
	}
	if !legacy {
		return false, nil
	}
	if err := validateLegacyLXCRecreation(current, guest); err != nil {
		return false, err
	}
	return true, nil
}

// ValidateLegacyLXCRecreation proves the complete set of currently existing
// legacy LXC recovery candidates before deployment stops or deletes any
// appliance. It is read-only: artifact staging and destructive recovery stay
// in ensureLXCWithRetainedVolumes after this ownership gate has passed.
func ValidateLegacyLXCRecreation(ctx context.Context, client *Client, plan Plan) ([]string, error) {
	if !plan.ForceLegacyLXCRecreation {
		return nil, nil
	}
	if client == nil || plan.Node == "" {
		return nil, errors.New("Proxmox client and node are required for legacy LXC recovery validation")
	}
	targets := make([]string, 0)
	for _, guest := range plan.Guests {
		if guest.Kind != KindLXC {
			continue
		}
		kind, current, err := client.GuestConfig(ctx, plan.Node, guest.VMID)
		if IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect %s before legacy LXC recovery: %w", guest.Name, err)
		}
		if kind != KindLXC {
			return nil, fmt.Errorf("HOLD: VMID %d is occupied by an unowned %s guest, expected LXC %s", guest.VMID, kind, guest.Name)
		}
		recreate, err := legacyLXCRecreationRequired(current, guest)
		if err != nil {
			return nil, fmt.Errorf("validate legacy LXC recovery for %s: %w", guest.Name, err)
		}
		if recreate {
			targets = append(targets, guest.Name)
		}
	}
	return targets, nil
}

func validateLegacyLXCRecreation(current map[string]any, guest GuestPlan) error {
	if guest.VMID <= 0 || guest.DiskGiB <= 0 {
		return fmt.Errorf("HOLD: guest %s lacks a valid legacy LXC recovery identity", guest.Name)
	}
	if err := validateLegacyLXCIdentity(current, guest); err != nil {
		return err
	}
	if err := validateNoUndeclaredLXCVolumes(current, guest); err != nil {
		return err
	}
	rootfs, _ := current["rootfs"].(string)
	if !legacyLXCRootfsMatches(rootfs, guest) {
		return fmt.Errorf("HOLD: guest %s rootfs does not have the exact legacy raw layout", guest.Name)
	}
	for index, volume := range guest.Volumes {
		expected, err := persistentVolumeParam(volume)
		if err != nil {
			return err
		}
		mountpoint := fmt.Sprintf("mp%d", index)
		observed, _ := current[mountpoint].(string)
		if !exactLegacyLXCRawVolume(observed, guest.VMID, index+1) || !lxcVolumeMatchesPersistentIdentity(observed, expected, guest.VMID, index+1) {
			return fmt.Errorf("HOLD: guest %s persistent volume %s does not have the exact legacy raw layout", guest.Name, mountpoint)
		}
	}
	return nil
}

func validateLegacyLXCIdentity(current map[string]any, guest GuestPlan) error {
	if err := validateExistingGuestIdentityFields(current, guest); err == nil {
		if got, _ := current["tags"].(string); canonicalTags(got) != canonicalTags(strings.Join(guest.Tags, ";")) {
			return fmt.Errorf("HOLD: guest %s has unexpected tags %q before legacy LXC recreation", guest.Name, got)
		}
		return nil
	}
	predecessor, ok := retiredLiteLLMPredecessor(guest)
	if !ok {
		return validateExistingGuestIdentityFields(current, guest)
	}
	if !retiredLiteLLMArtifactIdentity(current) {
		return fmt.Errorf("HOLD: guest %s is not the exact retired LiteLLM predecessor: artifact identity is not a qualified LiteLLM 1.0.0 appliance", guest.Name)
	}
	if err := validateExistingGuestIdentityFields(current, predecessor); err != nil {
		return fmt.Errorf("HOLD: guest %s is not the exact retired LiteLLM predecessor: %w", guest.Name, err)
	}
	if got, _ := current["tags"].(string); canonicalTags(got) != canonicalTags(strings.Join(predecessor.Tags, ";")) {
		return fmt.Errorf("HOLD: guest %s is not the exact retired LiteLLM predecessor: unexpected tags %q", guest.Name, got)
	}
	return nil
}

// retiredLiteLLMPredecessor is deliberately a single exact migration bridge.
// It applies only while a legacy raw LXC at the Bifrost VMID still carries the
// former LiteLLM identity. Ordinary convergence remains strict and never
// treats a renamed or unowned guest as replaceable.
func retiredLiteLLMPredecessor(guest GuestPlan) (GuestPlan, bool) {
	if guest.VMID != 210 || guest.Name != "lab-bifrost-01" || guest.Hostname != "lab-bifrost-01" || guest.Owner != "boetticher/module/bifrost" || guest.Artifact.Name != "boetticher-bifrost" {
		return GuestPlan{}, false
	}
	predecessor := guest
	predecessor.Name = "lab-litellm-01"
	predecessor.Hostname = "lab-litellm-01"
	predecessor.Owner = "boetticher/module/litellm"
	predecessor.Tags = []string{model.TagBoetticher, model.TagManaged, model.TagModule, "module-litellm", model.ModuleOwnershipTag("litellm"), model.TagBackup}
	return predecessor, true
}

func retiredLiteLLMArtifactIdentity(current map[string]any) bool {
	description, _ := current["description"].(string)
	fields := strings.Fields(normalizeArtifactDescription(description))
	if len(fields) != 3 || fields[0] != "boetticher-artifact=boetticher-litellm@1.0.0" {
		return false
	}
	return exactArtifactDigestField(fields[1], "definition=") && exactArtifactDigestField(fields[2], "content=")
}

func exactArtifactDigestField(value, prefix string) bool {
	digest, ok := strings.CutPrefix(value, prefix)
	if !ok || len(digest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func legacyLXCRawVolumeID(vmid, disk int) string {
	return fmt.Sprintf("local:%d/vm-%d-disk-%d.raw", vmid, vmid, disk)
}

func exactLegacyLXCRawVolume(observed string, vmid, disk int) bool {
	first, _, _ := strings.Cut(observed, ",")
	return first == legacyLXCRawVolumeID(vmid, disk)
}

func legacyLXCRootfsMatches(observed string, guest GuestPlan) bool {
	if !exactLegacyLXCRawVolume(observed, guest.VMID, 0) {
		return false
	}
	_, options, _ := strings.Cut(observed, ",")
	return qemuVolumeOptions(strings.Split(options, ","))["size"] == strconv.Itoa(guest.DiskGiB)+"G"
}

func discardLegacyLXC(ctx context.Context, client *Client, plan Plan, guest GuestPlan) (err error) {
	kind, current, err := client.GuestConfig(ctx, plan.Node, guest.VMID)
	if err != nil {
		return fmt.Errorf("reinspect %s before legacy LXC recreation: %w", guest.Name, err)
	}
	if kind != KindLXC {
		return fmt.Errorf("HOLD: guest %s changed to %s before legacy LXC recreation", guest.Name, kind)
	}
	if err := validateLegacyLXCRecreation(current, guest); err != nil {
		return fmt.Errorf("HOLD: guest %s failed the final legacy identity check: %w", guest.Name, err)
	}
	status, err := client.LXCStatus(ctx, plan.Node, guest.VMID)
	if err != nil {
		return fmt.Errorf("inspect %s status before legacy LXC recreation: %w", guest.Name, err)
	}
	if status != "running" && status != "stopped" {
		return fmt.Errorf("HOLD: guest %s is %q; refusing legacy LXC recreation outside a running or stopped state", guest.Name, status)
	}
	if status == "running" {
		if err = client.StopLXC(ctx, plan.Node, guest.VMID); err != nil {
			return fmt.Errorf("stop %s before legacy LXC recreation: %w", guest.Name, err)
		}
		defer func() {
			if err == nil {
				return
			}
			if startErr := client.StartLXC(ctx, plan.Node, guest.VMID); startErr != nil {
				err = fmt.Errorf("%w; additionally failed to restore %s after legacy LXC recreation failure: %v", err, guest.Name, startErr)
			}
		}()
	}
	if err = client.DestroyLXC(ctx, plan.Node, guest.VMID); err != nil {
		return fmt.Errorf("discard legacy state for %s before recreation: %w", guest.Name, err)
	}
	return nil
}

func validateLXCDeviceContract(guest GuestPlan) error {
	if len(guest.Security.Capabilities) != 0 {
		return fmt.Errorf("HOLD: guest %s requests unrelated Linux capabilities", guest.Name)
	}
	if !guest.Security.Unprivileged && len(guest.Security.Devices) != 0 {
		return fmt.Errorf("HOLD: guest %s declares devices without an unprivileged contract", guest.Name)
	}
	for _, device := range guest.Security.Devices {
		if device.Path != "/dev/net/tun" || device.Type != "c" || device.Major != 10 || device.Minor != 200 || device.Access != "rwm" {
			return fmt.Errorf("HOLD: guest %s has unsupported device contract for %s", guest.Name, device.Path)
		}
	}
	return nil
}

func validateLXCPrivilegedDeviceAuthority(plan Plan, guest GuestPlan) error {
	if len(guest.Security.Devices) == 0 {
		return nil
	}
	if plan.PrivilegedRunner == nil || net.ParseIP(plan.PrivilegedAddress) == nil || plan.PrivilegedUser != "root" {
		return fmt.Errorf("HOLD: guest %s requires the authorized root bootstrap path to configure its exact device contract", guest.Name)
	}
	return nil
}

// configureLXCDevices applies the narrow device contract through the host's
// root bootstrap path. The scoped Proxmox API identity cannot pass device
// passthrough parameters to /lxc; using pct here preserves that provider
// boundary without granting the API token root-equivalent permissions.
func configureLXCDevices(ctx context.Context, plan Plan, guest GuestPlan) error {
	if err := validateLXCPrivilegedDeviceAuthority(plan, guest); err != nil {
		return err
	}
	for index, device := range guest.Security.Devices {
		args := []string{"/usr/sbin/pct", "set", strconv.Itoa(guest.VMID), fmt.Sprintf("--dev%d", index), lxcDeviceParam(device)}
		if _, err := plan.PrivilegedRunner.RunArgs(ctx, plan.PrivilegedAddress, plan.PrivilegedUser, args); err != nil {
			return fmt.Errorf("apply exact device %s through Proxmox host: %w", device.Path, err)
		}
	}
	return nil
}

// lxcDeviceParam is the only Core-owned translation of the bounded TUN
// contract into a Proxmox LXC device setting. No broad device wildcard or
// Linux capability is requested.
func lxcDeviceParam(device model.DeviceRequirement) string {
	return fmt.Sprintf("path=%s,mode=0666", device.Path)
}

// releaseLegacyLXCLoopMapping detaches the one inactive loop device that
// Proxmox retains for a proven legacy local raw LXC volume. Proxmox's LXC
// copy worker mounts its source read-only in a private namespace; a retained
// writable loop mapping causes that mount to fail. The guest is already
// stopped by the caller. Every identity is re-proven through pvesm and
// losetup immediately before the bounded detach, which also fails when the
// device is still busy.
func releaseLegacyLXCLoopMapping(ctx context.Context, plan Plan, guest GuestPlan, observed string) error {
	if plan.PrivilegedRunner == nil || net.ParseIP(plan.PrivilegedAddress) == nil || plan.PrivilegedUser != "root" || guest.VMID <= 0 {
		return fmt.Errorf("HOLD: guest %s requires the authorized root bootstrap path to release a legacy LXC loop mapping", guest.Name)
	}
	volumeID, err := legacyLXCLocalRawVolumeID(observed, guest.VMID)
	if err != nil {
		return fmt.Errorf("HOLD: %w", err)
	}
	volumePathOutput, err := plan.PrivilegedRunner.RunArgs(ctx, plan.PrivilegedAddress, plan.PrivilegedUser, []string{"/usr/sbin/pvesm", "path", volumeID})
	if err != nil {
		return fmt.Errorf("resolve legacy persistent volume %s for %s: %w", volumeID, guest.Name, err)
	}
	volumePath := strings.TrimSpace(string(volumePathOutput))
	if !strings.HasPrefix(volumePath, "/") || strings.ContainsAny(volumePath, "\r\n") {
		return fmt.Errorf("HOLD: Proxmox returned an unsafe path for legacy persistent volume %s", volumeID)
	}
	loopOutput, err := plan.PrivilegedRunner.RunArgs(ctx, plan.PrivilegedAddress, plan.PrivilegedUser, []string{"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", volumePath})
	if err != nil {
		return fmt.Errorf("inspect legacy loop mapping for %s: %w", volumeID, err)
	}
	loops := strings.Fields(string(loopOutput))
	if len(loops) == 0 {
		return nil
	}
	if len(loops) != 1 || !isLoopDevice(loops[0]) {
		return fmt.Errorf("HOLD: legacy persistent volume %s has ambiguous loop mappings %q", volumeID, strings.TrimSpace(string(loopOutput)))
	}
	backingOutput, err := plan.PrivilegedRunner.RunArgs(ctx, plan.PrivilegedAddress, plan.PrivilegedUser, []string{"/usr/sbin/losetup", "--noheadings", "--output", "BACK-FILE", loops[0]})
	if err != nil {
		return fmt.Errorf("re-verify legacy loop mapping %s for %s: %w", loops[0], volumeID, err)
	}
	if strings.TrimSpace(string(backingOutput)) != volumePath {
		return fmt.Errorf("HOLD: legacy loop mapping %s no longer belongs to persistent volume %s", loops[0], volumeID)
	}
	if _, err := plan.PrivilegedRunner.RunArgs(ctx, plan.PrivilegedAddress, plan.PrivilegedUser, []string{"/usr/sbin/losetup", "--detach", loops[0]}); err != nil {
		return fmt.Errorf("HOLD: detach inactive legacy loop mapping %s for persistent volume %s: %w", loops[0], volumeID, err)
	}
	return waitForLegacyLXCLoopRelease(ctx, plan, volumeID, volumePath, loops[0], 30, time.Second)
}

// waitForLegacyLXCLoopRelease accounts for losetup's deferred autoclear
// behavior. A successful detach can remain visible until the stopped LXC's
// old mount namespace drains; handing it to Proxmox before then recreates the
// read-only mount conflict. A changed or still-attached mapping is blocking.
func waitForLegacyLXCLoopRelease(ctx context.Context, plan Plan, volumeID, volumePath, expectedLoop string, attempts int, interval time.Duration) error {
	if attempts < 1 || interval < 0 {
		return errors.New("legacy LXC loop-release wait is invalid")
	}
	for attempt := 0; attempt < attempts; attempt++ {
		loopOutput, err := plan.PrivilegedRunner.RunArgs(ctx, plan.PrivilegedAddress, plan.PrivilegedUser, []string{"/usr/sbin/losetup", "--noheadings", "--output", "NAME", "--associated", volumePath})
		if err != nil {
			return fmt.Errorf("re-check legacy loop mapping for %s: %w", volumeID, err)
		}
		loops := strings.Fields(string(loopOutput))
		if len(loops) == 0 {
			return nil
		}
		if len(loops) != 1 || !isLoopDevice(loops[0]) || loops[0] != expectedLoop {
			return fmt.Errorf("HOLD: legacy persistent volume %s has changed loop mappings %q after detach", volumeID, strings.TrimSpace(string(loopOutput)))
		}
		if attempt+1 == attempts {
			break
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for legacy loop mapping %s to release: %w", expectedLoop, ctx.Err())
		case <-timer.C:
		}
	}
	return fmt.Errorf("HOLD: legacy loop mapping %s for persistent volume %s remained attached after detach", expectedLoop, volumeID)
}

func legacyLXCLocalRawVolumeID(observed string, vmid int) (string, error) {
	first, _, _ := strings.Cut(observed, ",")
	storageID, volume, ok := strings.Cut(first, ":")
	if !ok || storageID != "local" || vmid <= 0 {
		return "", fmt.Errorf("refusing legacy LXC loop release for malformed local volume %q", first)
	}
	prefix := fmt.Sprintf("%d/vm-%d-disk-", vmid, vmid)
	if !strings.HasPrefix(volume, prefix) || !strings.HasSuffix(volume, ".raw") {
		return "", fmt.Errorf("refusing legacy LXC loop release for non-canonical local volume %q", first)
	}
	diskNumber := strings.TrimSuffix(strings.TrimPrefix(volume, prefix), ".raw")
	diskIndex, err := strconv.Atoi(diskNumber)
	if err != nil || diskNumber == "" || diskIndex < 0 {
		return "", fmt.Errorf("refusing legacy LXC loop release for non-canonical local volume %q", first)
	}
	return first, nil
}

func isLoopDevice(value string) bool {
	if !strings.HasPrefix(value, "/dev/loop") {
		return false
	}
	index := strings.TrimPrefix(value, "/dev/loop")
	parsed, err := strconv.Atoi(index)
	return err == nil && index != "" && parsed >= 0
}

// replaceLXC detaches only proven persistent mount-point volumes, retains
// their exact volume references, and removes the disposable rootfs. The caller
// must pass those references back to creation; size-only parameters would
// allocate fresh volumes and silently discard retained state.
func replaceLXC(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) (retained map[string]string, err error) {
	kind, refreshed, err := client.GuestConfig(ctx, plan.Node, guest.VMID)
	if err != nil {
		return nil, fmt.Errorf("reinspect %s before appliance replacement: %w", guest.Name, err)
	}
	if kind != KindLXC {
		return nil, fmt.Errorf("HOLD: refusing to replace %s at VMID %d because the occupant is %s, expected LXC", guest.Name, guest.VMID, kind)
	}
	if err := validateExistingGuestDestructiveIdentity(refreshed, guest); err != nil {
		return nil, fmt.Errorf("HOLD: refusing to replace unowned container %s: %w", guest.Name, err)
	}
	if err := validateNoUndeclaredLXCVolumes(refreshed, guest); err != nil {
		return nil, err
	}
	current = refreshed
	retained, err = retainedLXCPersistentVolumeAttachments(current, guest)
	if err != nil {
		return nil, err
	}
	status, err := client.LXCStatus(ctx, plan.Node, guest.VMID)
	if err != nil {
		return nil, fmt.Errorf("inspect %s status before appliance replacement: %w", guest.Name, err)
	}
	if status != "running" && status != "stopped" {
		return nil, fmt.Errorf("HOLD: guest %s is %q; refusing appliance replacement outside a running or stopped state", guest.Name, status)
	}
	if status == "running" {
		if err := client.StopLXC(ctx, plan.Node, guest.VMID); err != nil {
			return nil, fmt.Errorf("stop %s before appliance replacement: %w", guest.Name, err)
		}
		defer func() {
			if err == nil {
				return
			}
			if startErr := client.StartLXC(ctx, plan.Node, guest.VMID); startErr != nil {
				err = fmt.Errorf("%w; additionally failed to restore %s after appliance replacement failure: %v", err, guest.Name, startErr)
			}
		}()
	}
	detach := url.Values{}
	for index := range guest.Volumes {
		detach.Add("delete", fmt.Sprintf("mp%d", index))
	}
	if len(detach) > 0 {
		if err := client.SetLXCConfig(ctx, plan.Node, guest.VMID, detach); err != nil {
			return nil, fmt.Errorf("detach persistent volumes from %s before appliance replacement: %w", guest.Name, err)
		}
	}
	if err := client.destroyLXCForReplacement(ctx, plan.Node, guest.VMID); err != nil {
		return nil, fmt.Errorf("destroy %s rootfs for appliance replacement: %w", guest.Name, err)
	}
	if client.RestoreReplacementACL != nil {
		if err := client.RestoreReplacementACL(ctx, guest.VMID); err != nil {
			return nil, fmt.Errorf("restore %s replacement ACL: %w", guest.Name, err)
		}
	}
	return retained, nil
}

// lxcBootstrapKeyParams is the durable operator bootstrap input accepted by
// appliance creation. Proxmox writes this key into the container's root
// bootstrap identity; the image first-boot service copies it to labadmin and
// removes the root bootstrap copy. Temporary Apply authority is installed
// separately after the immutable plan is accepted.
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
	identity, err := persistentVolumeIdentity(volume)
	if err != nil {
		return "", err
	}
	if len(identity) <= 36 {
		return identity, nil
	}
	digest := sha256.Sum256([]byte(identity))
	return "boetticher-" + hex.EncodeToString(digest[:])[:25], nil
}

func persistentVolumeIdentity(volume model.PersistentVolumeDeclaration) (string, error) {
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

func migrateLegacyQEMUPersistentVolumeSerials(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) error {
	params := url.Values{}
	for index, volume := range guest.Volumes {
		serial, err := persistentVolumeSerial(volume)
		if err != nil {
			return err
		}
		legacySerial, err := persistentVolumeIdentity(volume)
		if err != nil || serial == legacySerial {
			continue
		}
		expected, err := qemuPersistentVolumeParam(plan, volume)
		if err != nil {
			return err
		}
		if observed, _ := current[fmt.Sprintf("scsi%d", index+1)].(string); qemuVolumeMatchesSerial(observed, expected, legacySerial) {
			params.Set(fmt.Sprintf("scsi%d", index+1), expected)
		}
	}
	if len(params) == 0 {
		return nil
	}
	if err := client.SetVMConfig(ctx, plan.Node, guest.VMID, params); err != nil {
		return fmt.Errorf("migrate legacy persistent volume serials for %s: %w", guest.Name, err)
	}
	for key, value := range params {
		current[key] = value[0]
	}
	return nil
}

// migrateQEMUPersistentVolumes reconciles a prior supported storage profile
// with the currently declared one. It moves only disks whose attached slot,
// stable serial, backup setting, and exact size prove that the volume belongs
// to this declared guest. An active gateway is stopped for the short move and
// restored even if a later move fails.
func migrateQEMUPersistentVolumes(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) (err error) {
	type migration struct {
		disk    string
		storage string
		volume  model.PersistentVolumeDeclaration
	}
	migrations := make([]migration, 0, len(guest.Volumes))
	for index, volume := range guest.Volumes {
		expected, expectedErr := qemuPersistentVolumeParam(plan, volume)
		if expectedErr != nil {
			return expectedErr
		}
		disk := fmt.Sprintf("scsi%d", index+1)
		observed, _ := current[disk].(string)
		observedStorage := qemuVolumeStorageID(observed)
		expectedStorage := qemuVolumeStorageID(expected)
		if observedStorage == "" || expectedStorage == "" {
			return fmt.Errorf("HOLD: refusing to migrate guest %s persistent volume %s with malformed storage identity", guest.Name, disk)
		}
		if observedStorage == expectedStorage {
			continue
		}
		if !qemuVolumeMatchesPersistentIdentity(observed, expected) {
			return fmt.Errorf("HOLD: refusing to migrate guest %s persistent volume %s=%q; its serial, backup setting, or size does not prove the declared contract %q", guest.Name, disk, observed, expected)
		}
		migrations = append(migrations, migration{disk: disk, storage: expectedStorage, volume: volume})
	}
	if len(migrations) == 0 {
		return nil
	}

	status, err := client.QEMUStatus(ctx, plan.Node, guest.VMID)
	if err != nil {
		return fmt.Errorf("inspect %s status before persistent-volume migration: %w", guest.Name, err)
	}
	if status != "running" && status != "stopped" {
		return fmt.Errorf("HOLD: guest %s is %q; refusing persistent-volume migration outside a running or stopped state", guest.Name, status)
	}
	wasRunning := status == "running"
	if wasRunning {
		if err := client.StopVM(ctx, plan.Node, guest.VMID); err != nil {
			return fmt.Errorf("stop %s before persistent-volume migration: %w", guest.Name, err)
		}
		defer func() {
			if startErr := client.StartVM(ctx, plan.Node, guest.VMID); startErr != nil {
				if err == nil {
					err = fmt.Errorf("restore %s after persistent-volume migration: %w", guest.Name, startErr)
				} else {
					err = fmt.Errorf("%w; additionally failed to restore %s after persistent-volume migration: %v", err, guest.Name, startErr)
				}
			}
		}()
	}

	for _, migration := range migrations {
		refreshed := map[string]any{}
		if err := client.QEMUConfig(ctx, plan.Node, guest.VMID, &refreshed); err != nil {
			return fmt.Errorf("inspect %s before moving persistent volume %s: %w", guest.Name, migration.disk, err)
		}
		expected, expectedErr := qemuPersistentVolumeParam(plan, migration.volume)
		if expectedErr != nil {
			return expectedErr
		}
		observed, _ := refreshed[migration.disk].(string)
		if qemuVolumeStorageID(observed) == migration.storage {
			continue
		}
		if !qemuVolumeMatchesPersistentIdentity(observed, expected) {
			return fmt.Errorf("HOLD: guest %s persistent volume %s changed before migration", guest.Name, migration.disk)
		}
		digest, _ := refreshed["digest"].(string)
		if err := client.MoveQEMUPersistentDisk(ctx, plan.Node, guest.VMID, migration.disk, migration.storage, digest); err != nil {
			return fmt.Errorf("migrate persistent volume %s for %s: %w", migration.disk, guest.Name, err)
		}
	}

	refreshed := map[string]any{}
	if err := client.QEMUConfig(ctx, plan.Node, guest.VMID, &refreshed); err != nil {
		return fmt.Errorf("verify %s persistent-volume migration: %w", guest.Name, err)
	}
	replaceQEMUConfig(current, refreshed)
	return nil
}

func qemuVolumeStorageID(value string) string {
	first, _, _ := strings.Cut(value, ",")
	storage, volume, ok := strings.Cut(first, ":")
	if !ok || storage == "" || volume == "" {
		return ""
	}
	return storage
}

func qemuVolumeMatchesPersistentIdentity(observed, expected string) bool {
	observedParts := strings.Split(observed, ",")
	expectedParts := strings.Split(expected, ",")
	if len(observedParts) == 0 || len(expectedParts) == 0 {
		return false
	}
	_, expectedSize, expectedOK := strings.Cut(expectedParts[0], ":")
	if !expectedOK || expectedSize == "" || qemuVolumeStorageID(observed) == "" {
		return false
	}
	observedOptions := qemuVolumeOptions(observedParts[1:])
	expectedOptions := qemuVolumeOptions(expectedParts[1:])
	return observedOptions["backup"] == expectedOptions["backup"] &&
		observedOptions["serial"] == expectedOptions["serial"] &&
		observedOptions["size"] == expectedSize+"G"
}

func qemuVolumeOptions(parts []string) map[string]string {
	options := make(map[string]string, len(parts))
	for _, option := range parts {
		name, value, ok := strings.Cut(option, "=")
		if ok {
			options[name] = value
		}
	}
	return options
}

func qemuVolumeMatchesSerial(observed, expected, serial string) bool {
	observedParts := strings.Split(observed, ",")
	expectedParts := strings.Split(expected, ",")
	if len(observedParts) == 0 || len(expectedParts) == 0 {
		return false
	}
	expectedStorage, expectedSize, expectedOK := strings.Cut(expectedParts[0], ":")
	observedStorage, _, observedOK := strings.Cut(observedParts[0], ":")
	if !expectedOK || !observedOK || observedStorage != expectedStorage {
		return false
	}
	options := make(map[string]string, len(observedParts)-1)
	for _, option := range observedParts[1:] {
		name, value, ok := strings.Cut(option, "=")
		if ok {
			options[name] = value
		}
	}
	expectedOptions := make(map[string]string, len(expectedParts)-1)
	for _, option := range expectedParts[1:] {
		name, value, ok := strings.Cut(option, "=")
		if ok {
			expectedOptions[name] = value
		}
	}
	return options["backup"] == expectedOptions["backup"] && options["serial"] == serial &&
		(options["size"] == "" || options["size"] == expectedSize+"G")
}

// migrateLXCPersistentVolumes reconciles a prior supported storage profile
// with the storage now declared for an LXC. A mount point has no QEMU-style
// serial, so its fixed slot, storage identity, mount path, backup policy, and
// exact size together establish ownership before Core asks Proxmox to delete
// the source after a successful copy.
func migrateLXCPersistentVolumes(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) (err error) {
	type migration struct {
		mountpoint string
		storage    string
		volume     model.PersistentVolumeDeclaration
		observed   string
		disk       int
	}
	migrations := make([]migration, 0, len(guest.Volumes))
	for index, volume := range guest.Volumes {
		expected, expectedErr := persistentVolumeParam(volume)
		if expectedErr != nil {
			return expectedErr
		}
		mountpoint := fmt.Sprintf("mp%d", index)
		observed, _ := current[mountpoint].(string)
		observedStorage := lxcVolumeStorageID(observed)
		expectedStorage := lxcVolumeStorageID(expected)
		if observedStorage == "" || expectedStorage == "" {
			return fmt.Errorf("HOLD: refusing to migrate guest %s persistent volume %s with malformed storage identity", guest.Name, mountpoint)
		}
		if observedStorage == expectedStorage {
			continue
		}
		if !lxcVolumeMatchesPersistentIdentity(observed, expected, guest.VMID, index+1) {
			return fmt.Errorf("HOLD: refusing to migrate guest %s persistent volume %s=%q; its canonical volume identity, mount path, backup setting, or size does not prove the declared contract %q", guest.Name, mountpoint, observed, expected)
		}
		migrations = append(migrations, migration{mountpoint: mountpoint, storage: expectedStorage, volume: volume, observed: observed, disk: index + 1})
	}
	if len(migrations) == 0 {
		return nil
	}
	if err := validateExistingGuestDestructiveIdentity(current, guest); err != nil {
		return fmt.Errorf("HOLD: refusing to migrate unowned container %s: %w", guest.Name, err)
	}

	status, err := client.LXCStatus(ctx, plan.Node, guest.VMID)
	if err != nil {
		return fmt.Errorf("inspect %s status before persistent-volume migration: %w", guest.Name, err)
	}
	if status != "running" && status != "stopped" {
		return fmt.Errorf("HOLD: guest %s is %q; refusing persistent-volume migration outside a running or stopped state", guest.Name, status)
	}
	wasRunning := status == "running"
	if wasRunning {
		if err := client.StopLXC(ctx, plan.Node, guest.VMID); err != nil {
			return fmt.Errorf("stop %s before persistent-volume migration: %w", guest.Name, err)
		}
		defer func() {
			if startErr := client.StartLXC(ctx, plan.Node, guest.VMID); startErr != nil {
				if err == nil {
					err = fmt.Errorf("restore %s after persistent-volume migration: %w", guest.Name, startErr)
				} else {
					err = fmt.Errorf("%w; additionally failed to restore %s after persistent-volume migration: %v", err, guest.Name, startErr)
				}
			}
		}()
	}
	for _, migration := range migrations {
		if lxcVolumeStorageID(migration.observed) == "local" {
			if err := releaseLegacyLXCLoopMapping(ctx, plan, guest, migration.observed); err != nil {
				return err
			}
		}
	}

	for _, migration := range migrations {
		refreshed := map[string]any{}
		if err := client.LXCConfig(ctx, plan.Node, guest.VMID, &refreshed); err != nil {
			return fmt.Errorf("inspect %s before moving persistent volume %s: %w", guest.Name, migration.mountpoint, err)
		}
		expected, expectedErr := persistentVolumeParam(migration.volume)
		if expectedErr != nil {
			return expectedErr
		}
		observed, _ := refreshed[migration.mountpoint].(string)
		if lxcVolumeStorageID(observed) == migration.storage {
			continue
		}
		if !lxcVolumeMatchesPersistentIdentity(observed, expected, guest.VMID, migration.disk) {
			return fmt.Errorf("HOLD: guest %s persistent volume %s changed before migration", guest.Name, migration.mountpoint)
		}
		digest, _ := refreshed["digest"].(string)
		if err := client.MoveLXCPersistentVolume(ctx, plan.Node, guest.VMID, migration.mountpoint, migration.storage, digest); err != nil {
			return fmt.Errorf("migrate persistent volume %s for %s: %w", migration.mountpoint, guest.Name, err)
		}
	}

	refreshed := map[string]any{}
	if err := client.LXCConfig(ctx, plan.Node, guest.VMID, &refreshed); err != nil {
		return fmt.Errorf("verify %s persistent-volume migration: %w", guest.Name, err)
	}
	replaceLXCConfig(current, refreshed)
	return nil
}

func lxcVolumeStorageID(value string) string {
	first, _, _ := strings.Cut(value, ",")
	storage, volume, ok := strings.Cut(first, ":")
	if !ok || storage == "" || volume == "" {
		return ""
	}
	return storage
}

func lxcVolumeMatchesPersistentIdentity(observed, expected string, vmid, disk int) bool {
	observedParts := strings.Split(observed, ",")
	expectedParts := strings.Split(expected, ",")
	if len(observedParts) == 0 || len(expectedParts) == 0 || vmid <= 0 || disk <= 0 {
		return false
	}
	expectedStorage, expectedSize, expectedOK := strings.Cut(expectedParts[0], ":")
	if !expectedOK || expectedStorage == "" || expectedSize == "" || lxcVolumeStorageID(observed) == "" || !lxcCanonicalVolumeIdentity(observed, vmid, disk) {
		return false
	}
	observedOptions := qemuVolumeOptions(observedParts[1:])
	expectedOptions := qemuVolumeOptions(expectedParts[1:])
	return observedOptions["mp"] == expectedOptions["mp"] &&
		observedOptions["backup"] == expectedOptions["backup"] &&
		observedOptions["size"] == expectedSize+"G"
}

func lxcCanonicalVolumeIdentity(observed string, vmid, disk int) bool {
	first, _, _ := strings.Cut(observed, ",")
	_, volumeID, ok := strings.Cut(first, ":")
	if !ok {
		return false
	}
	canonical := fmt.Sprintf("vm-%d-disk-%d", vmid, disk)
	return volumeID == canonical || volumeID == fmt.Sprintf("%d/%s.raw", vmid, canonical)
}

func retainedLXCPersistentVolumeAttachments(current map[string]any, guest GuestPlan) (map[string]string, error) {
	retained := make(map[string]string, len(guest.Volumes))
	for index, volume := range guest.Volumes {
		expected, err := persistentVolumeParam(volume)
		if err != nil {
			return nil, err
		}
		mountpoint := fmt.Sprintf("mp%d", index)
		observed, _ := current[mountpoint].(string)
		if !lxcPersistentVolumeMatches(observed, expected, guest.VMID, index+1) {
			return nil, fmt.Errorf("HOLD: refusing to retain guest %s persistent volume %s because its storage, canonical volume identity, mount path, backup setting, or size no longer proves the declared contract", guest.Name, mountpoint)
		}
		retained[mountpoint] = observed
	}
	return retained, nil
}

func validateExistingGuestVolumes(current map[string]any, expected GuestPlan) error {
	for index, volume := range expected.Volumes {
		wanted, err := persistentVolumeParam(volume)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("mp%d", index)
		observed, _ := current[key].(string)
		if !lxcPersistentVolumeMatches(observed, wanted, expected.VMID, index+1) {
			return fmt.Errorf("HOLD: guest %s has persistent volume %s=%q, expected %q", expected.Name, key, observed, wanted)
		}
	}
	return validateNoUndeclaredLXCVolumes(current, expected)
}

func validateNoUndeclaredLXCVolumes(current map[string]any, expected GuestPlan) error {
	for key := range current {
		if !strings.HasPrefix(key, "mp") {
			continue
		}
		if !safePersistentLXCMountpointKey(key) {
			return fmt.Errorf("HOLD: guest %s has malformed persistent volume key %s", expected.Name, key)
		}
		index, _ := strconv.Atoi(strings.TrimPrefix(key, "mp"))
		if index >= len(expected.Volumes) {
			return fmt.Errorf("HOLD: guest %s has an undeclared persistent volume %s", expected.Name, key)
		}
	}
	return nil
}

// ValidateNoUndeclaredLXCPersistentVolumes is the narrow public check used by
// cleanup paths that intentionally expect a rootfs-only LXC. It prevents the
// Proxmox purge flag from deleting an attached volume that was never part of
// the cleanup operation's ownership proof.
func ValidateNoUndeclaredLXCPersistentVolumes(current map[string]any, guestName string) error {
	return validateNoUndeclaredLXCVolumes(current, GuestPlan{Name: guestName})
}

func lxcPersistentVolumeMatches(observed, wanted string, vmid, disk int) bool {
	return lxcVolumeStorageID(observed) != "" &&
		lxcVolumeStorageID(observed) == lxcVolumeStorageID(wanted) &&
		lxcVolumeMatchesPersistentIdentity(observed, wanted, vmid, disk)
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
		if (content != "import" && content != "vztmpl") || !strings.HasSuffix(err.Error(), "has no checksum evidence") {
			return err
		}
		// Some Proxmox content listings omit checksums. Re-upload the qualified
		// local bytes so the upload task can verify the exact content before use.
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
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("inspect qualified artifact %s: %w", source, err)
	}
	transferStarted := time.Now()
	uploadErr := client.UploadStorageFile(ctx, node, storage, content, source, filename, checksum)
	telemetry.Record(ctx, telemetry.Event{
		Category: "artifact_transfer", Operation: "controller_to_proxmox", Target: content,
		Bytes: info.Size(), Duration: time.Since(transferStarted), Success: uploadErr == nil, Changed: true,
	})
	if uploadErr != nil {
		return fmt.Errorf("upload %s: %w", filename, uploadErr)
	}
	entries, err = client.StorageContent(ctx, node, storage, content)
	if err != nil {
		return fmt.Errorf("verify uploaded %s artifact storage: %w", filename, err)
	}
	found, err := verifyStoredArtifact(entries, filename, checksum, content == "import" || content == "vztmpl")
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

// validateExistingGuestDestructiveIdentity proves the immutable ownership
// fields immediately before a move, detach, or destroy. It deliberately does
// not compare the artifact description because callers use it while replacing
// an otherwise correctly owned root filesystem.
func validateExistingGuestDestructiveIdentity(current map[string]any, expected GuestPlan) error {
	if err := validateExistingGuestIdentityFields(current, expected); err != nil {
		return err
	}
	got, _ := current["tags"].(string)
	if canonicalTags(got) != canonicalTags(strings.Join(expected.Tags, ";")) {
		return fmt.Errorf("guest %s has unexpected tags %q, expected %q", expected.Name, got, strings.Join(expected.Tags, ";"))
	}
	return nil
}

func validateExistingGuestIdentity(current map[string]any, expected GuestPlan) error {
	if err := validateExistingGuestIdentityFields(current, expected); err != nil {
		return err
	}
	if guestArtifactNeedsReplacement(current, expected) {
		observed, _ := current["description"].(string)
		return fmt.Errorf("HOLD: guest %s has artifact identity %q, expected %q; appliance replacement is required", expected.Name, observed, artifactDescription(expected.Artifact))
	}
	return nil
}

func validateExistingGuestIdentityFields(current map[string]any, expected GuestPlan) error {
	for key, want := range map[string]string{"name": expected.Name, "hostname": expected.Hostname} {
		if got, ok := current[key].(string); ok && got != "" && got != want {
			return fmt.Errorf("guest %s has unexpected %s %q, expected %q", expected.Name, key, got, want)
		}
	}
	if expected.Security.Unprivileged {
		if !observedTruthy(current["unprivileged"]) {
			return fmt.Errorf("HOLD: guest %s is not unprivileged", expected.Name)
		}
		for index, device := range expected.Security.Devices {
			key := fmt.Sprintf("dev%d", index)
			observed, _ := current[key].(string)
			if observed != lxcDeviceParam(device) {
				return fmt.Errorf("HOLD: guest %s has %s=%q, expected exact TUN contract %q", expected.Name, key, observed, lxcDeviceParam(device))
			}
		}
		for key := range current {
			if strings.HasPrefix(key, "dev") && len(key) > len("dev") && key[3] >= '0' && key[3] <= '9' {
				index := int(key[3] - '0')
				if index >= len(expected.Security.Devices) && !stringIn(expected.ManagedUSBSlots, key) {
					return fmt.Errorf("HOLD: guest %s has an undeclared device allowance %s", expected.Name, key)
				}
				if stringIn(expected.ManagedUSBSlots, key) {
					observed, _ := current[key].(string)
					if !validManagedUSBDeviceValue(observed) {
						return fmt.Errorf("HOLD: guest %s has unsafe managed USB allowance %s=%q", expected.Name, key, observed)
					}
				}
			}
		}
	}
	if expected.Owner != "" {
		module := strings.TrimPrefix(expected.Owner, "boetticher/module/")
		ownerTag := model.ModuleOwnershipTag(module)
		if ownerTag == "" || !hasOwnerTag(currentTags(current), ownerTag) {
			return fmt.Errorf("HOLD: guest %s lacks canonical ownership proof %q", expected.Name, ownerTag)
		}
	}
	return nil
}

func stringIn(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validManagedUSBDeviceValue(value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) != 4 || !validManagedUSBPath(parts[0]) {
		return false
	}
	return parts[1] == "uid=2200" && parts[2] == "gid=2200" && parts[3] == "mode=0660"
}

func validManagedUSBPath(path string) bool {
	if strings.HasPrefix(path, "/dev/bus/usb/") {
		parts := strings.Split(strings.TrimPrefix(path, "/dev/bus/usb/"), "/")
		return len(parts) == 2 && allDecimal(parts[0]) && allDecimal(parts[1])
	}
	for _, prefix := range []string{"/dev/ttyUSB", "/dev/ttyACM"} {
		if strings.HasPrefix(path, prefix) {
			return allDecimal(strings.TrimPrefix(path, prefix))
		}
	}
	return false
}

func allDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func observedTruthy(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case float64:
		return typed == 1
	case int:
		return typed == 1
	case string:
		return typed == "1" || strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func guestArtifactNeedsReplacement(current map[string]any, expected GuestPlan) bool {
	if expected.Artifact.Name == "" {
		return false
	}
	observed, _ := current["description"].(string)
	return !artifactDescriptionMatches(observed, expected.Artifact)
}

// InspectGuestArtifact performs the one live guest-config read needed before
// appliance reconciliation. It returns existence and replacement state
// together so callers do not query the same Proxmox config twice. A kind
// mismatch remains present but not replaceable; the normal ensure path then
// preserves its ownership HOLD.
func InspectGuestArtifact(ctx context.Context, client *Client, node string, guest GuestPlan) (exists, replacement bool, err error) {
	if client == nil {
		return false, false, errors.New("Proxmox client is required")
	}
	kind, current, err := client.GuestConfig(ctx, node, guest.VMID)
	if IsNotFound(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("inspect guest %s artifact identity: %w", guest.Name, err)
	}
	if kind != guest.Kind {
		return true, false, nil
	}
	return true, guestArtifactNeedsReplacement(current, guest), nil
}

func normalizeArtifactDescription(value string) string {
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	return strings.TrimSuffix(value, "\n")
}

func replaceQEMURootDisk(ctx context.Context, client *Client, plan Plan, guest GuestPlan) (err error) {
	status, err := client.QEMUStatus(ctx, plan.Node, guest.VMID)
	if err != nil {
		return fmt.Errorf("inspect gateway status before appliance replacement: %w", err)
	}
	if status != "running" && status != "stopped" {
		return fmt.Errorf("HOLD: guest %s is %q; refusing appliance replacement outside a running or stopped state", guest.Name, status)
	}
	wasRunning := status == "running"
	if wasRunning {
		if err := client.StopVM(ctx, plan.Node, guest.VMID); err != nil {
			return fmt.Errorf("stop gateway before appliance replacement: %w", err)
		}
		defer func() {
			if err == nil {
				return
			}
			if startErr := client.StartVM(ctx, plan.Node, guest.VMID); startErr != nil {
				err = fmt.Errorf("%w; additionally failed to restore %s after appliance replacement: %v", err, guest.Name, startErr)
			}
		}()
	}
	if guest.Name == "lab-fw-01" {
		if err := uploadFirewallCloudInit(ctx, client, plan, guest.VMID); err != nil {
			return err
		}
	}
	filename := fmt.Sprintf("%s-%s-%s.qcow2", guest.Artifact.Name, guest.Artifact.Version, guest.Artifact.Architecture)
	source := plan.ArtifactFiles[artifactKey(guest.Artifact)]
	if err := ensureArtifactInStorage(ctx, client, plan.Node, "local", "import", filename, guest.Artifact.ContentSHA256, source); err != nil {
		return fmt.Errorf("prepare replacement %s artifact: %w", guest.Name, err)
	}
	upid, err := client.ImportDisk(ctx, plan.Node, guest.VMID, "local:import/"+filename, plan.Storage, "qcow2")
	if err != nil {
		return fmt.Errorf("import replacement gateway disk: %w", err)
	}
	if err := client.WaitTask(ctx, plan.Node, upid); err != nil {
		return fmt.Errorf("wait for replacement gateway disk: %w", err)
	}
	if err := client.SetVMConfig(ctx, plan.Node, guest.VMID, url.Values{"description": {artifactDescription(guest.Artifact)}}); err != nil {
		return fmt.Errorf("record replacement gateway artifact identity: %w", err)
	}
	return nil
}

func uploadFirewallCloudInit(ctx context.Context, client *Client, plan Plan, vmid int) error {
	if plan.CloudInitFiles.MetaData == "" || plan.CloudInitFiles.UserData == "" || plan.CloudInitFiles.NetworkConfig == "" {
		return errors.New("firewall cloud-init input is incomplete")
	}
	names := cloudInitSnippetNames(vmid)
	for key, value := range map[string]string{"meta": plan.CloudInitFiles.MetaData, "user": plan.CloudInitFiles.UserData, "network": plan.CloudInitFiles.NetworkConfig} {
		if err := client.UploadStorageText(ctx, plan.Node, "local", "snippets", names[key], value); err != nil {
			return fmt.Errorf("upload firewall cloud-init %s: %w", key, err)
		}
	}
	return nil
}

func artifactDescription(artifact model.Artifact) string {
	return fmt.Sprintf("boetticher-artifact=%s@%s content=%s", artifact.Name, artifact.Version, artifact.ContentSHA256)
}

func artifactDescriptionMatches(observed string, expected model.Artifact) bool {
	observed = normalizeArtifactDescription(observed)
	if observed == artifactDescription(expected) {
		return true
	}
	// Accept the prior description format during a normal upgrade. The content
	// digest is the immutable artifact identity; the old definition field was
	// only build provenance and must not force a root-disk replacement.
	parts := strings.Fields(observed)
	return len(parts) == 3 &&
		parts[0] == fmt.Sprintf("boetticher-artifact=%s@%s", expected.Name, expected.Version) &&
		strings.HasPrefix(parts[1], "definition=") &&
		parts[2] == "content="+expected.ContentSHA256
}

func ensureExistingGuestTags(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) error {
	if guest.Owner != "" {
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

func ensureExistingLXCNameserver(ctx context.Context, client *Client, plan Plan, guest GuestPlan, current map[string]any) error {
	servers := guestNameservers(plan, guest)
	if len(servers) == 0 {
		return nil
	}
	want := strings.Join(servers, " ")
	got, _ := current["nameserver"].(string)
	if strings.Join(strings.Fields(got), " ") == strings.Join(strings.Fields(want), " ") {
		return nil
	}
	if err := client.SetLXCConfig(ctx, plan.Node, guest.VMID, url.Values{"nameserver": {want}}); err != nil {
		return fmt.Errorf("apply platform nameservers to %s: %w", guest.Name, err)
	}
	return nil
}

func guestNameservers(plan Plan, guest GuestPlan) []string {
	if len(guest.Nameservers) > 0 {
		return guest.Nameservers
	}
	return plan.Nameservers
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
	return map[string]string{
		"INFRA": "10.10.10.1", "SERVERS": "10.10.20.1",
		"TRUSTED": "10.10.30.1", "SANDBOX": "10.10.40.1", "MGMT": "10.10.99.1",
		"TRANSIT": model.TransitGateway,
	}[zone]
}
