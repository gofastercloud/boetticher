package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
)

const deploymentPlanFormatVersion = 1

// deploymentPlan is the complete immutable input to APPLY. It deliberately
// contains only typed plans and authenticated release identity; observations
// are included when --live is requested and are never written as desired
// state.
type deploymentPlan struct {
	Version         int           `json:"version"`
	ReleaseVersion  string        `json:"release_version"`
	ReleaseDigest   string        `json:"release_digest"`
	ModelRevision   string        `json:"model_revision"`
	Live            bool          `json:"live"`
	Proxmox         proxmox.Plan  `json:"proxmox"`
	Firewall        firewall.Plan `json:"firewall"`
	Storage         storage.Plan  `json:"storage"`
	Backup          backup.Plan   `json:"backup"`
	ReplaceFirewall bool          `json:"replace_firewall,omitempty"`
	RecreateLegacy  bool          `json:"recreate_legacy_lxcs,omitempty"`
	Digest          string        `json:"digest"`
}

func runPlan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	live := fs.Bool("live", false, "include read-only Proxmox and prerequisite observations")
	jsonOutput := fs.Bool("json", false, "emit the typed plan as JSON")
	replaceFirewall := fs.Bool("replace-firewall", false, "include the explicitly confirmed firewall recovery plan")
	recreateLegacy := fs.Bool("recreate-legacy-lxcs", false, "include the explicitly confirmed legacy LXC recovery plan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher plan [--site DIR] [--live] [--json]")
	}

	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("validate desired state: %w", err)
	}
	manifest, releaseDigest, err := artifacts.ImportedReleaseManifest(*siteDir)
	if err != nil {
		return fmt.Errorf("authenticated release bundle is required: %w", err)
	}
	modelRevision, err := s.Revision()
	if err != nil {
		return fmt.Errorf("calculate model revision: %w", err)
	}
	airvpnProfile, err := prepareAirVPNProfile(context.Background(), *siteDir, s, *ageIdentity, true, false)
	if err != nil {
		return err
	}
	var firewallPlan firewall.Plan
	if airvpnProfile == nil {
		firewallPlan, err = firewall.PlanFromSite(s)
	} else {
		firewallPlan, err = firewall.PlanFromSiteWithAirVPN(s, airvpnProfile.Metadata)
	}
	if err != nil {
		return fmt.Errorf("plan firewall: %w", err)
	}
	proxmoxPlan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("plan Proxmox guests: %w", err)
	}
	proxmoxPlan, err = proxmox.ResolveQualifiedArtifacts(*siteDir, proxmoxPlan, true)
	if err != nil {
		return fmt.Errorf("resolve signed release artifacts: %w", err)
	}
	storagePlan, err := storage.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("plan storage: %w", err)
	}
	backupPlan, err := backup.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("plan backup: %w", err)
	}
	plan := deploymentPlan{
		Version: deploymentPlanFormatVersion, ReleaseVersion: manifest.ReleaseVersion,
		ReleaseDigest: releaseDigest, ModelRevision: modelRevision, Live: *live,
		Proxmox: proxmoxPlan, Firewall: firewallPlan, Storage: storagePlan,
		Backup: backupPlan, ReplaceFirewall: *replaceFirewall, RecreateLegacy: *recreateLegacy,
	}
	if *live {
		if err := addLivePlanObservations(context.Background(), *siteDir, s, *ageIdentity, &plan); err != nil {
			return err
		}
	}
	digest, err := digestDeploymentPlan(plan)
	if err != nil {
		return err
	}
	plan.Digest = digest

	if *jsonOutput {
		data, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}
	fmt.Fprintf(out, "Deployment plan: PASS\n  Digest: %s\n  Release: %s (%s)\n  Model revision: %s\n  Mode: %s\n  Guests: %d\n  Firewall rules: %d\n  Artifacts: %d\n", plan.Digest, manifest.ReleaseVersion, releaseDigest, modelRevision, map[bool]string{true: "live read-only", false: "offline"}[*live], len(plan.Proxmox.Guests), len(plan.Firewall.Rules), len(plan.Proxmox.ArtifactFiles))
	if *live {
		fmt.Fprintln(out, "  Proxmox observations: PASS (read-only)")
	}
	fmt.Fprintln(out, "  Mutations: none (PLAN is read-only)")
	return nil
}

func digestDeploymentPlan(plan deploymentPlan) (string, error) {
	plan.Digest = ""
	data, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("encode deployment plan: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

func addLivePlanObservations(ctx context.Context, siteDir string, s model.Site, ageIdentity string, plan *deploymentPlan) error {
	if plan == nil {
		return errors.New("deployment plan is required")
	}
	client, _, err := loadProxmoxClient(siteDir, s, ageIdentity, "", false)
	if err != nil {
		return fmt.Errorf("load Proxmox read-only client: %w", err)
	}
	node, err := client.SingleNode(ctx)
	if err != nil {
		return fmt.Errorf("observe Proxmox node: %w", err)
	}
	plan.Proxmox.Node = node
	statuses, err := client.NodeStorage(ctx, node)
	if err != nil {
		return fmt.Errorf("observe Proxmox storage: %w", err)
	}
	if _, err := expectedStorageStatus(statuses, plan.Storage); err != nil {
		return fmt.Errorf("required storage is not ready: %w", err)
	}
	if _, err := inspectDeploymentGuestStates(ctx, client, node, deploymentGuestPlans(s, plan.Proxmox)); err != nil {
		return fmt.Errorf("observe planned guest state: %w", err)
	}
	if plan.Firewall.AirVPN != nil {
		resolved, err := firewall.BindAirVPNEndpoint(plan.Firewall, net.LookupIP)
		if err != nil {
			return err
		}
		plan.Firewall = resolved
	}
	if err := validateExternalEndpointReadiness(s, net.LookupIP); err != nil {
		return err
	}
	return nil
}
