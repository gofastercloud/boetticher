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
)

type ControllerIdentity struct {
	Address string
	MAC     string
}

func CollectionConfigForLab(config controllerhost.LabConfig, controllerAddress string) (CollectionConfig, error) {
	if _, err := collectionIPv4(controllerAddress); err != nil {
		return CollectionConfig{}, errors.New("controller collection address is invalid")
	}
	if _, err := collectionIPv4(config.Proxmox.Address); err != nil {
		return CollectionConfig{}, errors.New("Proxmox collection address is invalid")
	}
	result := CollectionConfig{
		Targets: []Target{
			{Name: "controller", Hostname: "controller", Address: controllerAddress, Kind: TargetController, Arch: "arm64", Port: NodeExporterPort},
			{Name: "proxmox-host", Hostname: "proxmox-host", Address: model.ProxmoxManagementAddress, Kind: TargetHost, Arch: "amd64", Port: NodeExporterPort},
			{Name: "lab-monitor-01", Hostname: "lab-monitor-01", Address: "10.10.10.20", Kind: TargetRuntime, VMID: model.MonitorVMID, Arch: "amd64", Port: NodeExporterPort},
		},
		MetricsRetentionDays: collectionRetention(config.Modules, true),
		LogsRetentionDays:    collectionRetention(config.Modules, false),
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
		if target.Kind == TargetRuntime && (target.VMID != model.MonitorVMID || target.Address != "10.10.10.20") {
			return fmt.Errorf("collection runtime target has an unexpected VMID or address")
		}
		if target.Kind != TargetRuntime && target.VMID != 0 {
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
	if len(c.Targets) != 3 {
		return errors.New("collection requires exactly three managed Linux targets")
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
	return nil
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
	identity, err := LocalControllerIdentityLookup()
	if err != nil {
		return "", err
	}
	if _, err := collectionIPv4(identity.Address); err != nil {
		return "", errors.New("Controller collection identity has an invalid IPv4 address")
	}
	mac, err := net.ParseMAC(identity.MAC)
	if err != nil || len(mac) != 6 {
		return "", errors.New("Controller collection identity has an invalid interface MAC")
	}
	if config.Modules.DHCP == nil {
		return "", errors.New("Controller collection identity has no DHCP reservation intent")
	}
	for _, reservation := range config.Modules.DHCP.Reservations {
		reservationMAC, macErr := net.ParseMAC(reservation.MAC)
		if macErr != nil || len(reservationMAC) != 6 {
			continue
		}
		if !strings.EqualFold(reservationMAC.String(), mac.String()) {
			continue
		}
		if reservation.Zone != "SERVERS" || reservation.Address != identity.Address {
			return "", errors.New("Controller interface does not match its SERVERS DHCP reservation")
		}
		return identity.Address, nil
	}
	return "", errors.New("Controller interface MAC has no matching SERVERS DHCP reservation")
}

var LocalControllerIdentityLookup = defaultLocalControllerIdentityLookup

func defaultLocalControllerIdentityLookup() (ControllerIdentity, error) {
	result, err := (BoundedLocalRunner{}).Run(context.Background(), "set -eu; route=$(ip -4 route get 1.1.1.1); dev=$(printf '%s\\n' \"$route\" | awk '{ for (i=1; i<=NF; i++) if ($i == \"dev\") { print $(i+1); exit } }'); address=$(printf '%s\\n' \"$route\" | awk '{ for (i=1; i<=NF; i++) if ($i == \"src\") { print $(i+1); exit } }'); case \"$dev\" in ''|*[!A-Za-z0-9_.-]*) exit 1 ;; esac; mac=$(cat \"/sys/class/net/$dev/address\"); printf '%s %s\\n' \"$address\" \"$mac\"")
	if err != nil {
		return ControllerIdentity{}, fmt.Errorf("observe Controller interface identity: %w", err)
	}
	fields := strings.Fields(string(result.Stdout))
	if len(fields) != 2 {
		return ControllerIdentity{}, errors.New("observe Controller interface identity returned no address and MAC")
	}
	return ControllerIdentity{Address: fields[0], MAC: fields[1]}, nil
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
