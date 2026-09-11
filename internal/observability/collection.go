package observability

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	NodeExporterPort      = 9100
	MetricsRetentionDays  = 30
	LogsRetentionDays     = 7
	ScrapeInterval        = "30s"
	NodeExporterBinary    = "/usr/local/bin/node_exporter"
	NodeExporterService   = "boetticher-node-exporter.service"
	CollectionConfigPath  = "/etc/boetticher/observability/collection.yml"
	NodeExporterWebConfig = "/etc/boetticher/observability/node-exporter-web.yml"
)

// CollectionConfig is the complete, bounded collection intent consumed by the
// shared monitoring runtime. Targets are an allowlist of product-owned Linux
// nodes; callers cannot supply an arbitrary scrape address.
type CollectionConfig struct {
	Targets              []Target
	MetricsRetentionDays int
	LogsRetentionDays    int
	MediaDiskGiB         int
}
type Target struct {
	Name, Address, Hostname, Arch string
	Kind                          TargetKind
	VMID                          int
	Port                          int
}
type TargetKind string

const (
	TargetController TargetKind = "controller"
	TargetHost       TargetKind = "host"
	TargetRuntime    TargetKind = "runtime"
	TargetMedia      TargetKind = "media"
)

type ControllerIdentity struct {
	Interface string
	Address   string
	MAC       string
}

func CollectionConfigForLab(config controllerhost.LabConfig, controllerAddress string) (CollectionConfig, error) {
	if _, err := collectionIPv4(controllerAddress); err != nil {
		return CollectionConfig{}, errors.New("controller collection address is invalid")
	}
	if _, err := collectionIPv4(config.Proxmox.Address); err != nil {
		return CollectionConfig{}, errors.New("Proxmox collection address is invalid")
	}
	addresses := clientservices.ObservabilityCollectionBindings{
		Controller:  controllerAddress,
		ProxmoxHost: model.ProxmoxManagementAddress,
		Runtime:     binding.Address,
	}
	if config.Modules.Observability != nil {
		persisted := config.Modules.Observability.Collection
		if persisted.Controller != "" || persisted.ProxmoxHost != "" || persisted.Runtime != "" {
			if persisted != addresses {
				return CollectionConfig{}, errors.New("observability collection bindings do not match verified lab identities")
			}
		}
	}
	result := CollectionConfig{
		Targets: []Target{
			{Name: "controller", Hostname: "controller", Address: addresses.Controller, Kind: TargetController, Arch: "arm64", Port: NodeExporterPort},
			{Name: "proxmox-host", Hostname: "proxmox-host", Address: addresses.ProxmoxHost, Kind: TargetHost, Arch: "amd64", Port: NodeExporterPort},
			{Name: "lab-monitor-01", Hostname: "lab-monitor-01", Address: addresses.Runtime, Kind: TargetRuntime, VMID: model.MonitorVMID, Arch: "amd64", Port: NodeExporterPort},
		},
		MetricsRetentionDays: collectionRetention(config.Modules, true),
		LogsRetentionDays:    collectionRetention(config.Modules, false),
		MediaDiskGiB:         256,
	}
	if config.Modules.Observability != nil && clientservices.Enabled(config.Modules.Observability.Enabled) && config.Modules.Media != nil && config.Modules.Media.Enabled {
		if config.Modules.Media.MediaGiB > 0 {
			result.MediaDiskGiB = config.Modules.Media.MediaGiB
		}
		result.Targets = append(result.Targets, Target{Name: "lab-media-01", Hostname: "lab-media-01", Address: "10.10.20.230", Kind: TargetMedia, VMID: 290, Arch: "amd64", Port: NodeExporterPort})
	}
	if err := result.Validate(); err != nil {
		return CollectionConfig{}, err
	}
	return result, nil
}

func collectionRetention(modules clientservices.Modules, metrics bool) int {
	if modules.Observability == nil {
		if metrics {
			return MetricsRetentionDays
		}
		return LogsRetentionDays
	}
	value := modules.Observability.Logging.RetentionDays
	defaultValue := LogsRetentionDays
	if metrics {
		value, defaultValue = modules.Observability.Monitoring.RetentionDays, MetricsRetentionDays
	}
	if value == 0 {
		return defaultValue
	}
	return value
}

// CollectionConfigFromSite is retained for projection fixtures. Installed
// callers must use CollectionConfigForLab, which receives the current
// authenticated Controller address and enrolled Host configuration.
func CollectionConfigFromSite(site model.Site) CollectionConfig {
	hostAddress := "192.0.2.10"
	controllerAddress := site.Gateway.ControllerAddress
	if controllerAddress == "" {
		controllerAddress = "192.0.2.20"
	}
	config, err := CollectionConfigForLab(controllerhost.LabConfig{Proxmox: controllerhost.ProxmoxConfig{Address: hostAddress}}, controllerAddress)
	if err != nil {
		return CollectionConfig{}
	}
	return config
}

// DefaultCollectionConfig remains only for isolated unit fixtures. Installed
// callers must use CollectionConfigForLab with current Controller and Host
// bindings.
func DefaultCollectionConfig() CollectionConfig {
	config, _ := CollectionConfigForLab(controllerhost.LabConfig{Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10"}}, "192.0.2.20")
	return config
}

func (c CollectionConfig) Validate() error {
	if c.MetricsRetentionDays < 1 || c.MetricsRetentionDays > 3650 || c.LogsRetentionDays < 1 || c.LogsRetentionDays > 3650 {
		return errors.New("collection retention must be between 1 and 3650 days")
	}
	if c.MediaDiskGiB < 0 {
		return errors.New("collection media disk size cannot be negative")
	}
	if len(c.Targets) == 0 {
		return errors.New("collection requires exactly three managed Linux targets")
	}
	seen := make(map[string]struct{}, len(c.Targets))
	seenAddress := make(map[string]struct{}, len(c.Targets))
	for _, target := range c.Targets {
		expectedName, expectedHostname, expectedArch := "", "", ""
		switch target.Kind {
		case TargetController:
			expectedName, expectedHostname, expectedArch = "controller", "controller", "arm64"
		case TargetHost:
			expectedName, expectedHostname, expectedArch = "proxmox-host", "proxmox-host", "amd64"
		case TargetRuntime:
			expectedName, expectedHostname, expectedArch = "lab-monitor-01", "lab-monitor-01", "amd64"
		case TargetMedia:
			if c.MediaDiskGiB < 1 {
				return errors.New("media collection requires a configured media disk size")
			}
			expectedName, expectedHostname, expectedArch = "lab-media-01", "lab-media-01", "amd64"
		default:
			return fmt.Errorf("collection target %s has an unknown kind", target.Name)
		}
		if target.Name != expectedName || target.Hostname != expectedHostname || target.Arch != expectedArch || target.Port != NodeExporterPort {
			return fmt.Errorf("collection target %s has an unexpected identity", target.Name)
		}
		address, err := collectionIPv4(target.Address)
		if err != nil {
			return fmt.Errorf("collection target %s has invalid IPv4 address", target.Name)
		}
		if target.Kind == TargetRuntime && (target.VMID != model.MonitorVMID || target.Address != binding.Address) {
			return fmt.Errorf("collection runtime target has an unexpected VMID or address")
		}
		if target.Kind == TargetMedia && (target.VMID != 290 || target.Address != "10.10.20.230") {
			return fmt.Errorf("collection media target has an unexpected VMID or address")
		}
		if target.Kind != TargetRuntime && target.Kind != TargetMedia && target.VMID != 0 {
			return fmt.Errorf("collection target %s must not carry a VMID", target.Name)
		}
		if _, ok := seen[target.Name]; ok {
			return fmt.Errorf("duplicate collection target %s", target.Name)
		}
		seen[target.Name] = struct{}{}
		canonicalAddress := address.String()
		if _, ok := seenAddress[canonicalAddress]; ok {
			return fmt.Errorf("duplicate collection target address %s", canonicalAddress)
		}
		seenAddress[canonicalAddress] = struct{}{}
	}
	if len(c.Targets) != 3 && len(c.Targets) != 4 {
		return errors.New("collection requires three managed Linux targets, plus media when enabled")
	}
	for _, kind := range []TargetKind{TargetController, TargetHost, TargetRuntime} {
		found := false
		for _, target := range c.Targets {
			if target.Kind == kind {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("collection target kind %s is missing", kind)
		}
	}
	mediaCount := countTargetKind(c.Targets, TargetMedia)
	if mediaCount > 1 || (len(c.Targets) == 4 && mediaCount != 1) || (len(c.Targets) == 3 && mediaCount != 0) {
		return errors.New("duplicate collection media target")
	}
	return nil
}

func countTargetKind(targets []Target, kind TargetKind) int {
	count := 0
	for _, target := range targets {
		if target.Kind == kind {
			count++
		}
	}
	return count
}

func collectionIPv4(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.Is4() || address.IsUnspecified() {
		return netip.Addr{}, errors.New("address is not a usable IPv4 address")
	}
	return address, nil
}

// LocalRouteLookup is injectable so collection planning and tests can provide
// the current Controller address without running a host command.
var LocalRouteLookup = defaultLocalRouteLookup

func ObservedControllerIP() (string, error) {
	for _, envName := range []string{"SSH_CONNECTION", "AUTHENTICATED_SSH_CONNECTION"} {
		fields := strings.Fields(os.Getenv(envName))
		if len(fields) > 0 {
			if address, err := collectionIPv4(fields[0]); err == nil {
				return address.String(), nil
			}
		}
	}
	address, err := LocalRouteLookup()
	if err != nil {
		return "", fmt.Errorf("observe Controller collection address: %w", err)
	}
	parsed, err := collectionIPv4(address)
	if err != nil {
		return "", fmt.Errorf("observe Controller collection address: %w", err)
	}
	return parsed.String(), nil
}

// ControllerCollectionAddress binds the local Controller's active interface
// to the operator's existing DHCP reservation. It never infers identity from
// SSH peer or HOME-side addresses.
func ControllerCollectionAddress(config controllerhost.LabConfig) (string, error) {
	identities, err := LocalControllerIdentityLookup()
	if err != nil {
		return "", err
	}
	if config.Modules.DHCP == nil {
		return "", errors.New("Controller collection identity has no DHCP reservation intent")
	}
	matches := make([]string, 0)
	for _, identity := range identities {
		if _, parseErr := collectionIPv4(identity.Address); parseErr != nil {
			continue
		}
		mac, parseErr := net.ParseMAC(identity.MAC)
		if parseErr != nil || len(mac) != 6 {
			continue
		}
		for _, reservation := range config.Modules.DHCP.Reservations {
			if reservation.Zone != "SERVERS" {
				continue
			}
			reservationMAC, macErr := net.ParseMAC(reservation.MAC)
			if macErr != nil || len(reservationMAC) != 6 || !strings.EqualFold(reservationMAC.String(), mac.String()) {
				continue
			}
			if reservation.Address != identity.Address {
				continue
			}
			matches = append(matches, identity.Interface+"\x00"+identity.Address)
		}
	}
	if len(matches) == 1 {
		return strings.SplitN(matches[0], "\x00", 2)[1], nil
	}
	if len(matches) > 1 {
		return "", errors.New("multiple Controller interfaces match SERVERS DHCP reservations")
	}
	return "", errors.New("Controller interface MAC has no matching SERVERS DHCP reservation")
}

var LocalControllerIdentityLookup = defaultLocalControllerIdentityLookup

func defaultLocalControllerIdentityLookup() ([]ControllerIdentity, error) {
	result, err := (BoundedLocalRunner{}).Run(context.Background(), "set -eu; ip -o -4 addr show up | awk '$3 == \"inet\" { split($4, a, \"/\"); sub(/@.*/, \"\", $2); print $2, a[1] }' | while read -r dev address; do case \"$dev\" in ''|*[!A-Za-z0-9_.-]*) continue ;; esac; mac=$(cat \"/sys/class/net/$dev/address\"); printf '%s %s %s\\n' \"$dev\" \"$address\" \"$mac\"; done")
	if err != nil {
		return nil, fmt.Errorf("observe Controller interfaces: %w", err)
	}
	identities := make([]ControllerIdentity, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(result.Stdout)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			identities = append(identities, ControllerIdentity{Interface: fields[0], Address: fields[1], MAC: fields[2]})
		}
	}
	if len(identities) == 0 {
		return nil, errors.New("observe Controller interfaces returned no IPv4 identities")
	}
	return identities, nil
}

func defaultLocalRouteLookup() (string, error) {
	runner := BoundedLocalRunner{}
	result, err := runner.Run(context.Background(), "ip -4 route get 1.1.1.1")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(result.Stdout))
	for index, field := range fields {
		if field == "src" && index+1 < len(fields) {
			return fields[index+1], nil
		}
	}
	return "", errors.New("local route did not report a source IPv4 address")
}
func (c CollectionConfig) VictoriaMetricsScrapeConfig(publicDomain ...string) (string, error) {
	if len(publicDomain) == 0 {
		return "", errorsCollectionDomain
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	if !clientservices.ValidPublicDomain(publicDomain[0]) {
		return "", errorsCollectionDomain
	}
	targets := append([]Target(nil), c.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
	var b strings.Builder
	fmt.Fprintf(&b, "global:\n  scrape_interval: %s\n  scrape_timeout: 10s\nscrape_configs:\n", ScrapeInterval)
	for _, target := range targets {
		fmt.Fprintf(&b, "  - job_name: %s\n    scheme: https\n    metrics_path: %s\n    basic_auth:\n      username: %s\n      password_file: %s\n    tls_config:\n      ca_file: %s\n      server_name: %s\n      insecure_skip_verify: false\n    static_configs:\n      - targets: [%s]\n        labels:\n          boetticher_host: %s\n", yamlQuote("boetticher-"+target.Name), yamlQuote("/"+target.Name+"/metrics"), yamlQuote("boetticher"), yamlQuote("/run/credentials/victoriametrics.service/node-exporter-read-token"), yamlQuote("/etc/ssl/certs/ca-certificates.crt"), yamlQuote("metrics."+publicDomain[0]), yamlQuote("metrics."+publicDomain[0]+":443"), yamlQuote(target.Name))
	}
	if countTargetKind(targets, TargetMedia) == 1 {
		fmt.Fprintf(&b, "  - job_name: %s\n    metrics_path: '/metrics'\n    static_configs:\n      - targets: ['127.0.0.1:8080']\n        labels:\n          boetticher_host: 'lab-monitor-01'\n          boetticher_source: 'gatus'\n", yamlQuote("boetticher-gatus"))
	}
	return b.String(), nil
}

func yamlQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func (c CollectionConfig) VictoriaMetricsRetentionFlag() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("-retentionPeriod=%dd", c.MetricsRetentionDays), nil
}

func (c CollectionConfig) VictoriaLogsRetentionFlag() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("-retentionPeriod=%dd", c.LogsRetentionDays), nil
}
