package networktest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	ArtifactName = "boetticher-network-probe"
	VMIDMin      = 910
	VMIDMax      = 919
	HarnessTag   = "boetticher-network-probe"
)

var ZoneOrder = []string{"TRANSIT", "INFRA", "SERVERS", "TRUSTED", "SANDBOX", "MGMT"}

type Probe struct {
	VMID        int    `json:"vmid"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	Zone        string `json:"zone"`
	VLAN        int    `json:"vlan"`
	Address     string `json:"address,omitempty"`
	Gateway     string `json:"gateway"`
	MAC         string `json:"mac"`
	AddressMode string `json:"address_mode"`
}

type Case struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Source      string `json:"source,omitempty"`
	Target      string `json:"target,omitempty"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Expected    string `json:"expected,omitempty"`
	Description string `json:"description,omitempty"`
}

type Result struct {
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Source       string            `json:"source,omitempty"`
	Target       string            `json:"target,omitempty"`
	Status       string            `json:"status"`
	Detail       string            `json:"detail,omitempty"`
	Started      string            `json:"started"`
	Finished     string            `json:"finished"`
	Output       string            `json:"output,omitempty"`
	Measurements map[string]string `json:"measurements,omitempty"`
}

type Report struct {
	Version       string   `json:"version"`
	RunID         string   `json:"run_id"`
	ModelRevision string   `json:"model_revision"`
	Mode          string   `json:"mode"`
	Probes        []Probe  `json:"probes"`
	Results       []Result `json:"results"`
	Cleanup       string   `json:"cleanup"`
	Overall       string   `json:"overall"`
	EvidencePath  string   `json:"evidence_path,omitempty"`
}

func SelectZones(s model.Site, requested string) ([]model.Zone, error) {
	wanted := map[string]bool{}
	if strings.TrimSpace(requested) == "" {
		for _, name := range ZoneOrder {
			wanted[name] = true
		}
	} else {
		for _, value := range strings.Split(requested, ",") {
			name := strings.ToUpper(strings.TrimSpace(value))
			if name == "" {
				continue
			}
			wanted[name] = true
		}
	}
	if len(wanted) == 0 {
		return nil, errors.New("at least one network zone is required")
	}
	result := make([]model.Zone, 0, len(wanted))
	for _, name := range ZoneOrder {
		if !wanted[name] {
			continue
		}
		found := false
		for _, zone := range s.Network.Zones {
			if zone.Name == name {
				result = append(result, zone)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("network zone %s is not present in the site model", name)
		}
	}
	if len(result) != len(wanted) {
		return nil, errors.New("network zone selection contains an unknown zone")
	}
	return result, nil
}

func Plans(s model.Site, zones []model.Zone, runID string) ([]Probe, error) {
	if runID == "" {
		return nil, errors.New("network test run ID is required")
	}
	used := map[string]bool{}
	for _, component := range s.PlatformComponents() {
		used[component.Address] = true
	}
	for _, reservation := range s.DHCPReservations {
		used[reservation.Address] = true
	}
	result := make([]Probe, 0, len(zones))
	for index, zone := range zones {
		probe := Probe{
			VMID: VMIDMin + index, Name: fmt.Sprintf("boetticher-netprobe-%s", strings.ToLower(zone.Name)),
			Hostname: fmt.Sprintf("boetticher-netprobe-%s", strings.ToLower(zone.Name)), Zone: zone.Name,
			VLAN: zone.VLAN, Gateway: zone.Gateway, MAC: MAC(s.SecretMetadata.InstallationID, zone.Name), AddressMode: zone.AddressMode,
		}
		if zone.AddressMode == "dynamic" || zone.AddressMode == "dynamic-reservations" {
			result = append(result, probe)
			continue
		}
		_, network, err := net.ParseCIDR(zone.Network)
		if err != nil || network.IP.To4() == nil {
			return nil, fmt.Errorf("network zone %s has an invalid IPv4 network", zone.Name)
		}
		base := network.IP.To4()
		for host := 250; host <= 254; host++ {
			candidateIP := append(net.IP(nil), base...)
			candidateIP[3] = byte(host)
			candidate := candidateIP.String()
			if !used[candidate] {
				probe.Address = candidate
				used[candidate] = true
				break
			}
		}
		if probe.Address == "" {
			return nil, fmt.Errorf("no collision-free static address remains for %s", zone.Name)
		}
		result = append(result, probe)
	}
	return result, nil
}

func MAC(installationID, zone string) string {
	sum := sha256.Sum256([]byte(installationID + "\x00" + zone))
	return fmt.Sprintf("02:00:00:%s:%s:%s", hex.EncodeToString(sum[0:1]), hex.EncodeToString(sum[1:2]), hex.EncodeToString(sum[2:3]))
}

func ValidateProbeAddress(probe Probe) error {
	if net.ParseIP(probe.Gateway) == nil {
		return errors.New("probe gateway or MAC is invalid")
	}
	if _, err := net.ParseMAC(probe.MAC); err != nil {
		return errors.New("probe gateway or MAC is invalid")
	}
	if probe.Address != "" && net.ParseIP(probe.Address) == nil {
		return errors.New("probe address is invalid")
	}
	return nil
}
