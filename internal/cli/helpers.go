package cli

import (
	"encoding/json"
	"fmt"
	"html"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/logging"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/storage"
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

// writeStorageProjection refreshes the storage contract without requiring
// runtime metadata owned by another deployment phase. In particular, a
// selected-source AirVPN policy cannot be rendered until deploy has generated
// and qualified its provider profile, but dedicated storage initialization
// must remain safe to run before that happens.
func writeStorageProjection(dir string, s model.Site) error {
	if err := pathguard.ValidateNoSymlinkComponents(filepath.Join(dir, "generated")); err != nil {
		return fmt.Errorf("refuse generated projection path: %w", err)
	}
	storagePlan, err := storage.PlanFromSite(s)
	if err != nil {
		return err
	}
	return writeProjection(filepath.Join(dir, "generated", "storage", "desired-state.json"), storagePlan)
}

// writeBootstrapProjections preserves the complete projection gate for normal
// sites. An AirVPN selected-source policy is different: its firewall and
// Ansible projections cannot exist until deploy has generated and qualified a
// provider profile. Bootstrap only needs the canonical model and storage
// contract, and must not turn that later deploy-time dependency into an
// expensive post-artifact bootstrap failure.
func writeBootstrapProjections(dir string, s model.Site) error {
	firewallPlan, err := firewall.PlanFromSite(s)
	if err != nil {
		return err
	}
	if len(firewallPlan.PolicyRoutes) == 0 {
		return writeModelProjections(dir, s)
	}
	if err := writeModelProjection(dir, s); err != nil {
		return err
	}
	return writeStorageProjection(dir, s)
}

func writeModelProjections(dir string, s model.Site) error {
	return writeModelProjectionsWithResolver(dir, s, net.LookupIP)
}

func writeModelProjectionsWithResolver(dir string, s model.Site, endpointLookup func(string) ([]net.IP, error)) error {
	return writeModelProjectionsWithResolverAndAirVPN(dir, s, endpointLookup, nil)
}

func writeModelProjectionsWithResolverAndAirVPN(dir string, s model.Site, endpointLookup func(string) ([]net.IP, error), airvpnProfile *firewall.AirVPNProfile) error {
	if err := pathguard.ValidateNoSymlinkComponents(filepath.Join(dir, "generated")); err != nil {
		return fmt.Errorf("refuse generated projection path: %w", err)
	}
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
	var firewallPlan firewall.Plan
	if airvpnProfile == nil {
		firewallPlan, err = firewall.PlanFromSite(s)
	} else {
		firewallPlan, err = firewall.PlanFromSiteWithAirVPN(s, *airvpnProfile)
	}
	if err != nil {
		return err
	}
	if airvpnProfile != nil {
		firewallPlan, err = firewall.BindAirVPNEndpoint(firewallPlan, endpointLookup)
		if err != nil {
			return err
		}
		*airvpnProfile = *firewallPlan.AirVPN
	}
	if err := writeProjection(filepath.Join(dir, "generated", "inventory.json"), struct {
		ModelRevision string            `json:"model_revision"`
		Components    []model.Component `json:"components"`
	}{revision, normalized.Components}); err != nil {
		return err
	}
	moduleRoot := filepath.Join(dir, "generated", "modules")
	if err := pathguard.ValidateNoSymlinkComponents(moduleRoot); err != nil {
		return fmt.Errorf("refuse generated module projection path: %w", err)
	}
	if err := pathguard.RemoveAll(moduleRoot); err != nil {
		return fmt.Errorf("clear generated module projections: %w", err)
	}
	for _, declaration := range normalized.Declarations {
		moduleDir := filepath.Join(moduleRoot, declaration.Module)
		if err := writeProjection(filepath.Join(moduleDir, "declaration.json"), struct {
			ModelRevision string                  `json:"model_revision"`
			Declaration   model.ModuleDeclaration `json:"declaration"`
		}{revision, declaration}); err != nil {
			return err
		}
	}
	if err := writeProjection(filepath.Join(dir, "generated", "firewall", "desired-state.json"), firewallPlan); err != nil {
		return err
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ruleset, renderErr := renderDeploymentNFTWithResolver(firewallPlan, endpointLookup)
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
	if err := writeStorageProjection(dir, s); err != nil {
		return err
	}
	if modules.IsEnabled(s, "logging") {
		loggingPlan, err := logging.PlanFromSite(s)
		if err != nil {
			return err
		}
		if err := writeProjection(filepath.Join(dir, "generated", "logging", "desired-state.json"), loggingPlan); err != nil {
			return err
		}
		if err := writePublic(filepath.Join(dir, "generated", "logging", "journal-remote.conf"), []byte(logging.CollectorConfiguration(loggingPlan))); err != nil {
			return err
		}
		if err := writePublic(filepath.Join(dir, "generated", "logging", "journal-remote.service.d", "boetticher.conf"), []byte(logging.CollectorServiceOverride(loggingPlan))); err != nil {
			return err
		}
		if err := writePublic(filepath.Join(dir, "generated", "logging", "journal-remote.socket.d", "boetticher.conf"), []byte(logging.CollectorSocketOverride(loggingPlan))); err != nil {
			return err
		}
	}
	blockyConfig, renderErr := dns.RenderBlockyConfig(dnsPlan)
	if renderErr != nil {
		return renderErr
	}
	if err := writePublic(filepath.Join(dir, "generated", "dns", "blocky.yml"), blockyConfig); err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "proxmox", "desired-state.json"), proxmoxPlan); err != nil {
		return err
	}
	monitoringPlan, err := pulse.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "monitoring", "desired-state.json"), monitoringPlan); err != nil {
		return err
	}
	if err := writeCurrentStatus(dir, s); err != nil {
		return err
	}
	inventory, err := ansible.Inventory(s)
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(dir, "generated", "ansible", "inventory.ini"), []byte(inventory)); err != nil {
		return err
	}
	var variables []byte
	if airvpnProfile == nil {
		variables, err = ansible.Variables(s)
	} else {
		variables, err = ansible.VariablesWithAirVPN(s, *airvpnProfile)
	}
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(dir, "generated", "ansible", "variables.json"), variables); err != nil {
		return err
	}
	sshContent := "# Managed by boetticher. Do not edit.\n# boetticher-model-revision: " + revision + "\n# Bootstrap endpoint is not configured; pass --bootstrap-address to boetticher enroll.\n"
	if s.BootstrapAddress != "" {
		sshContent, err = sshconfig.RenderWithKnownHosts(s, time.Now().UTC(), filepath.Join(dir, "generated", "ssh", "known_hosts"))
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

func renderDeploymentNFT(plan firewall.Plan) (string, error) {
	return renderDeploymentNFTWithResolver(plan, net.LookupIP)
}

func renderDeploymentNFTWithResolver(plan firewall.Plan, endpointLookup func(string) ([]net.IP, error)) (string, error) {
	if len(plan.Publications) > 0 && plan.Upstream == nil {
		return firewall.RenderSafeNFTWithResolver(plan, endpointLookup)
	}
	return firewall.RenderNFTWithResolver(plan, endpointLookup)
}

func physicalDiscoveryFromSite(s model.Site) networkmodel.Discovery {
	upstream := networkmodel.Interface{Name: s.PhysicalNetwork.Upstream.Name, PermanentMAC: s.PhysicalNetwork.Upstream.PermanentMAC, PCIAddress: s.PhysicalNetwork.Upstream.PCIAddress, PhysicalEthernet: s.PhysicalNetwork.Upstream.Name != ""}
	var trunk *networkmodel.Interface
	if s.PhysicalNetwork.Trunk.Name != "" {
		value := networkmodel.Interface{Name: s.PhysicalNetwork.Trunk.Name, PermanentMAC: s.PhysicalNetwork.Trunk.PermanentMAC, PCIAddress: s.PhysicalNetwork.Trunk.PCIAddress, PhysicalEthernet: true}
		trunk = &value
	}
	return networkmodel.Discovery{Mode: s.PhysicalNetwork.Mode, BootstrapAddress: s.BootstrapAddress, Upstream: upstream, Trunk: trunk, Status: "MODEL", Explanation: "persisted installation binding; live hardware evidence requires plan --live or status --details --live"}
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

// temporarySSHConfig creates a fresh, restrictive projection for a read-only
// operation. Persisted generated files are outputs and must not be treated as
// executable OpenSSH configuration because local users can modify them.
func temporarySSHConfig(s model.Site, siteDir string) (string, func(), error) {
	content, err := sshconfig.RenderWithKnownHosts(s, time.Now().UTC(), deploymentKnownHosts(siteDir))
	if err != nil {
		return "", func() {}, err
	}
	file, err := os.CreateTemp("", ".boetticher-ssh-read-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temporary SSH configuration: %w", err)
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("restrict temporary SSH configuration: %w", err)
	}
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("write temporary SSH configuration: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("sync temporary SSH configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close temporary SSH configuration: %w", err)
	}
	return path, cleanup, nil
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
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		var document struct {
			ModelRevision string `json:"model_revision"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			return fmt.Errorf("read model revision: invalid JSON: %w", err)
		}
		if document.ModelRevision != revision {
			return fmt.Errorf("model revision is not current")
		}
	case ".ini":
		if !hasRevisionLine(text, "# Model revision: "+revision) {
			return fmt.Errorf("model revision is not current")
		}
	case ".conf":
		if !hasRevisionLine(text, "# boetticher-model-revision: "+revision) {
			return fmt.Errorf("model revision is not current")
		}
	case ".html":
		if !strings.Contains(text, "Lab revision: <code>"+html.EscapeString(revision)+"</code>") {
			return fmt.Errorf("model revision is not current")
		}
	default:
		return fmt.Errorf("cannot verify model revision in %s", filepath.Base(path))
	}
	return nil
}

func hasRevisionLine(text, expected string) bool {
	for _, line := range strings.Split(text, "\n") {
		if line == expected {
			return true
		}
	}
	return false
}

func writeCurrentStatus(dir string, s model.Site) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	if existing := loadStatusReport(dir, revision); len(existing.Checks) > 0 {
		return nil
	}
	report := desiredStatusReport(s, revision)
	return writeProjection(filepath.Join(dir, "generated", "status.json"), report)
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
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	return pathguard.WriteFile(path, data, mode)
}
