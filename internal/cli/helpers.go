package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/portal"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/zabbix"
)

func writeModelProjection(dir string, s model.Site) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	modelForProjection := s.Normalize()
	modelForProjection.SSHIdentityFile = ""
	document := struct {
		ModelRevision string     `json:"model_revision"`
		Model         model.Site `json:"model"`
	}{ModelRevision: revision, Model: modelForProjection}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writePublic(filepath.Join(dir, "generated", "model.json"), append(data, '\n'))
}

func writeModelProjections(dir string, s model.Site) error {
	if err := writeModelProjection(dir, s); err != nil {
		return err
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	normalized := s.Normalize()
	proxmoxPlan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	firewallPlan, err := firewall.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "inventory.json"), struct {
		ModelRevision string            `json:"model_revision"`
		Components    []model.Component `json:"components"`
	}{revision, normalized.Components}); err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "firewall", "desired-state.json"), firewallPlan); err != nil {
		return err
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ruleset, renderErr := firewall.RenderNFT(firewallPlan)
		if renderErr != nil {
			return renderErr
		}
		if err := writePublic(filepath.Join(dir, "generated", "firewall", "boetticher.nft"), []byte(ruleset)); err != nil {
			return err
		}
	} else {
		contract, contractErr := firewall.RenderExternalContract(s, firewallPlan)
		if contractErr != nil {
			return contractErr
		}
		if err := writePublic(filepath.Join(dir, "generated", "network", "external-firewall-contract.md"), []byte(contract)); err != nil {
			return err
		}
	}
	dnsPlan, err := dns.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "dns", "desired-state.json"), dnsPlan); err != nil {
		return err
	}
	backupPlan, err := backup.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "backup", "desired-policy.json"), backupPlan); err != nil {
		return err
	}
	storagePlan, err := storage.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "storage", "desired-state.json"), storagePlan); err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "proxmox", "desired-state.json"), proxmoxPlan); err != nil {
		return err
	}
	zabbixPlan, err := zabbix.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "zabbix", "provisioning.json"), zabbixPlan); err != nil {
		return err
	}
	if err := writeCurrentStatus(dir, revision); err != nil {
		return err
	}
	inventory, err := ansible.Inventory(s)
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(dir, "generated", "ansible", "inventory.ini"), []byte(inventory)); err != nil {
		return err
	}
	variables, err := ansible.Variables(s)
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(dir, "generated", "ansible", "variables.json"), variables); err != nil {
		return err
	}
	sshContent := "# Managed by boetticher. Do not edit.\n# boetticher-model-revision: " + revision + "\n# Bootstrap endpoint is not configured; run boetticher bootstrap-endpoint set ADDRESS.\n"
	if s.BootstrapAddress != "" {
		sshContent, err = sshconfig.Render(s, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	if err := writePublic(filepath.Join(dir, "generated", "ssh", "boetticher.conf"), []byte(sshContent)); err != nil {
		return err
	}
	if err := writeAccessProjection(dir, s); err != nil {
		return err
	}
	return writePhysicalDiscovery(dir, s, loadPhysicalDiscovery(dir, s))
}

func physicalDiscoveryFromSite(s model.Site) networkmodel.Discovery {
	upstream := networkmodel.Interface{Name: s.PhysicalNetwork.Upstream.Name, PermanentMAC: s.PhysicalNetwork.Upstream.PermanentMAC, PCIAddress: s.PhysicalNetwork.Upstream.PCIAddress, PhysicalEthernet: s.PhysicalNetwork.Upstream.Name != ""}
	var trunk *networkmodel.Interface
	if s.PhysicalNetwork.Trunk.Name != "" {
		value := networkmodel.Interface{Name: s.PhysicalNetwork.Trunk.Name, PermanentMAC: s.PhysicalNetwork.Trunk.PermanentMAC, PCIAddress: s.PhysicalNetwork.Trunk.PCIAddress, PhysicalEthernet: true}
		trunk = &value
	}
	return networkmodel.Discovery{Mode: s.PhysicalNetwork.Mode, BootstrapAddress: s.BootstrapAddress, Upstream: upstream, Trunk: trunk, Status: "MODEL", Explanation: "persisted installation binding; live hardware evidence requires preflight or doctor --live"}
}

func writePhysicalDiscovery(dir string, s model.Site, discovery networkmodel.Discovery) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	return writeProjection(filepath.Join(dir, "generated", "network", "physical.json"), struct {
		ModelRevision string                 `json:"model_revision"`
		GeneratedAt   string                 `json:"generated_at"`
		Discovery     networkmodel.Discovery `json:"discovery"`
	}{revision, time.Now().UTC().Format(time.RFC3339), discovery})
}

func writeAccessProjection(dir string, s model.Site) error {
	policy, err := sshconfig.RenderBastionPolicy(s)
	if err != nil {
		return err
	}
	return writePublic(filepath.Join(dir, "generated", "ssh", "lab-jump.conf"), []byte(policy))
}

func rebuildPortal(dir string, s model.Site) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	return portal.Build(s, filepath.Join(dir, "generated", "portal"), "docs", loadEvidence(dir, revision), loadPhysicalDiscovery(dir, s), time.Now().UTC())
}

func loadPhysicalDiscovery(dir string, s model.Site) networkmodel.Discovery {
	data, err := os.ReadFile(filepath.Join(dir, "generated", "network", "physical.json"))
	if err == nil {
		var document struct {
			ModelRevision string                 `json:"model_revision"`
			Discovery     networkmodel.Discovery `json:"discovery"`
		}
		if json.Unmarshal(data, &document) == nil {
			if revision, revisionErr := s.Revision(); revisionErr == nil && document.ModelRevision == revision {
				return document.Discovery
			}
		}
	}
	return physicalDiscoveryFromSite(s)
}

func writeProjection(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePublic(path, append(data, '\n'))
}

func checkRevisionFile(path, revision string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.Contains(string(data), revision) {
		return fmt.Errorf("model revision is not current")
	}
	return nil
}

func loadEvidence(dir, expectedRevision string) portal.Evidence {
	data, err := os.ReadFile(filepath.Join(dir, "generated", "verification.json"))
	if err != nil {
		return portal.Evidence{}
	}
	var document struct {
		ModelRevision string          `json:"model_revision"`
		Evidence      portal.Evidence `json:"evidence"`
	}
	if json.Unmarshal(data, &document) == nil && document.ModelRevision == expectedRevision {
		return document.Evidence
	}
	return portal.Evidence{}
}

func writeCurrentStatus(dir, revision string) error {
	status := "NOT TESTED"
	data, err := os.ReadFile(filepath.Join(dir, "generated", "status.json"))
	if err == nil {
		var current struct {
			ModelRevision string `json:"model_revision"`
			Status        string `json:"status"`
		}
		if json.Unmarshal(data, &current) == nil && current.ModelRevision == revision && current.Status != "" {
			status = current.Status
		} else if current.Status != "" {
			status = "STALE"
		}
	}
	return writeProjection(filepath.Join(dir, "generated", "status.json"), struct {
		ModelRevision string `json:"model_revision"`
		Status        string `json:"status"`
		GeneratedAt   string `json:"generated_at"`
	}{revision, status, time.Now().UTC().Format(time.RFC3339)})
}

func sortedSSHComponents(s model.Site) []model.Component {
	components := []model.Component{}
	for _, m := range s.Components {
		if m.SSHManaged {
			components = append(components, m)
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	return components
}

func toolVersion(tool string) string {
	if tool == "ssh-keyscan" {
		// ssh-keyscan does not expose a version flag. It is shipped with the
		// OpenSSH client, which is checked separately and provides the
		// authoritative version for this required helper.
		return toolVersion("ssh")
	}
	args := []string{"--version"}
	if tool == "ssh" {
		args = []string{"-V"}
	}
	command := exec.Command(tool, args...)
	if tool == "ansible" || tool == "ansible-playbook" {
		preflightTemp := filepath.Join(os.TempDir(), "boetticher-ansible-preflight")
		_ = os.MkdirAll(preflightTemp, 0700)
		command.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+preflightTemp, "ANSIBLE_REMOTE_TEMP="+preflightTemp)
	}
	data, err := command.CombinedOutput()
	if err != nil {
		if len(data) == 0 {
			return "version unavailable"
		}
	}
	line := strings.TrimSpace(strings.Split(string(data), "\n")[0])
	return line
}

func validateToolVersion(tool, version string) error {
	if version == "" || version == "version unavailable" {
		return fmt.Errorf("version unavailable")
	}
	switch tool {
	case "ssh":
		if !strings.Contains(version, "OpenSSH") {
			return fmt.Errorf("unrecognized OpenSSH version")
		}
	case "ssh-keyscan":
		if !strings.Contains(version, "OpenSSH") {
			return fmt.Errorf("ssh-keyscan is not paired with a recognized OpenSSH version")
		}
	case "age-keygen":
		if !strings.HasPrefix(version, "v") {
			return fmt.Errorf("unrecognized Age version")
		}
	case "sops":
		if !strings.HasPrefix(version, "sops ") {
			return fmt.Errorf("unrecognized SOPS version")
		}
	case "tofu":
		if !strings.HasPrefix(version, "OpenTofu v") {
			return fmt.Errorf("OpenTofu is required")
		}
	case "ansible":
		if !strings.HasPrefix(version, "ansible [core ") {
			return fmt.Errorf("Ansible Core is required")
		}
	}
	return nil
}

func valueOrPlaceholder(value string) string {
	if value == "" {
		return "<required for live run>"
	}
	return value
}

func writePrivate(path string, data []byte) error {
	return writeFile(path, data, 0600)
}

func writePublic(path string, data []byte) error {
	return writeFile(path, data, 0644)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".boetticher-output-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
