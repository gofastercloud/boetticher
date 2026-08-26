package opnsense

import "github.com/gofastercloud/boetticher/internal/model"

// BootstrapPlan is the deterministic contract for the OPNsense transition.
// It deliberately describes the expected installer boundary without inventing
// an unqualified config.xml or console automation format.
type BootstrapPlan struct {
	ModelRevision       string          `json:"model_revision"`
	TestedVersion       string          `json:"tested_version"`
	FirewallVMID        int             `json:"firewall_vmid"`
	WANBridge           string          `json:"wan_bridge"`
	WANInterface        string          `json:"wan_interface"`
	InternalBridge      string          `json:"internal_bridge"`
	InternalInterface   string          `json:"internal_interface"`
	ManagementAddress   string          `json:"management_address"`
	ManagementNetwork   string          `json:"management_network"`
	IPv4Only            bool            `json:"ipv4_only"`
	Status              string          `json:"status"`
	QualificationGate   string          `json:"qualification_gate"`
	RequiredTransitions []string        `json:"required_transitions"`
	VLANs               []BootstrapVLAN `json:"vlans"`
}

type BootstrapVLAN struct {
	Name    string `json:"name"`
	VLAN    int    `json:"vlan"`
	Network string `json:"network"`
	Gateway string `json:"gateway"`
}

// BootstrapPlanFromSite is a projection of the fixed V1 bootstrap contract.
// Status is intentionally HOLD until the exact OPNsense patch has been
// exercised on a clean Proxmox installation.
func BootstrapPlanFromSite(s model.Site) (BootstrapPlan, error) {
	if err := s.Validate(); err != nil {
		return BootstrapPlan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return BootstrapPlan{}, err
	}
	zones := make([]BootstrapVLAN, 0, len(s.Network.Zones))
	for _, zone := range s.Normalize().Network.Zones {
		zones = append(zones, BootstrapVLAN{Name: zone.Name, VLAN: zone.VLAN, Network: zone.Network, Gateway: zone.Gateway})
	}
	return BootstrapPlan{
		ModelRevision:       revision,
		TestedVersion:       s.TestedVersions.Gateway,
		FirewallVMID:        model.ProxmoxVMID,
		WANBridge:           "vmbr0",
		WANInterface:        "vtnet0",
		InternalBridge:      "vmbr1",
		InternalInterface:   "vtnet1",
		ManagementAddress:   "10.10.99.1",
		ManagementNetwork:   "10.10.99.0/24",
		IPv4Only:            true,
		Status:              "HOLD",
		QualificationGate:   "fresh Proxmox -> OPNsense install -> VLAN/address/API convergence -> clean-install repeat",
		RequiredTransitions: []string{"create firewall VM", "unattended OPNsense installation/bootstrap", "assign WAN and vtnet1", "establish MGMT reachability", "create scoped API identity", "capture API credential directly into SOPS", "authenticate through supported API", "converge Kea and firewall policy", "remove temporary bootstrap privilege"},
		VLANs:               zones,
	}, nil
}
