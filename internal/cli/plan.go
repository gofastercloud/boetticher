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
	"sort"

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
	Version         int                    `json:"version"`
	ReleaseVersion  string                 `json:"release_version"`
	ReleaseDigest   string                 `json:"release_digest"`
	ModelRevision   string                 `json:"model_revision"`
	Live            bool                   `json:"live"`
	Proxmox         proxmox.Plan           `json:"proxmox"`
	Firewall        firewall.Plan          `json:"firewall"`
	Storage         storage.Plan           `json:"storage"`
	Backup          backup.Plan            `json:"backup"`
	Observations    deploymentObservations `json:"observations,omitempty"`
	ReplaceFirewall bool                   `json:"replace_firewall,omitempty"`
	RecreateLegacy  bool                   `json:"recreate_legacy_lxcs,omitempty"`
	Digest          string                 `json:"digest"`
}

// deploymentObservations are read-only facts captured alongside a live plan.
// They are part of the digest so APPLY cannot silently use a plan made for a
// different set of existing guests. Desired state remains in the typed plans;
// these facts never become configuration.
type deploymentObservations struct {
	Node   string                       `json:"node,omitempty"`
	Guests []deploymentGuestObservation `json:"guests,omitempty"`
}

type deploymentGuestObservation struct {
	VMID        int    `json:"vmid"`
	Name        string `json:"name"`
	Exists      bool   `json:"exists"`
	Replacement bool   `json:"replacement"`
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
	return runPlanRequest(planRequest{
		siteDir: *siteDir, ageIdentity: *ageIdentity, live: *live, json: *jsonOutput,
		replaceFirewall: *replaceFirewall, recreateLegacy: *recreateLegacy,
	}, out)
}

type planRequest struct {
	siteDir         string
	ageIdentity     string
	live            bool
	json            bool
	replaceFirewall bool
	recreateLegacy  bool
}

func runPlanRequest(request planRequest, out io.Writer) error {
	siteDir, ageIdentity := request.siteDir, request.ageIdentity
	if siteDir == "" {
		siteDir = "."
	}
	if ageIdentity == "" {
		ageIdentity = model.DefaultAgeIdentity
	}

	s, err := site.Load(siteDir)
	if err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("validate desired state: %w", err)
	}
	manifest, releaseDigest, err := artifacts.ImportedReleaseManifest(siteDir)
	if err != nil {
		return fmt.Errorf("authenticated release bundle is required: %w", err)
	}
	modelRevision, err := s.Revision()
	if err != nil {
		return fmt.Errorf("calculate model revision: %w", err)
	}
	airvpnProfile, err := prepareAirVPNProfile(context.Background(), siteDir, s, ageIdentity, true, false)
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
	proxmoxPlan, err = proxmox.ResolveQualifiedArtifacts(siteDir, proxmoxPlan, true)
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
		ReleaseDigest: releaseDigest, ModelRevision: modelRevision, Live: request.live,
		Proxmox: proxmoxPlan, Firewall: firewallPlan, Storage: storagePlan,
		Backup: backupPlan, ReplaceFirewall: request.replaceFirewall, RecreateLegacy: request.recreateLegacy,
	}
	if request.live {
		if err := addLivePlanObservations(context.Background(), siteDir, s, ageIdentity, &plan); err != nil {
			return err
		}
	}
	digest, err := digestDeploymentPlan(plan)
	if err != nil {
		return err
	}
	plan.Digest = digest

	if request.json {
		data, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}
	fmt.Fprintf(out, "Deployment plan: PASS\n  Digest: %s\n  Release: %s (%s)\n  Model revision: %s\n  Mode: %s\n  Guests: %d\n  Firewall rules: %d\n  Artifacts: %d\n", plan.Digest, manifest.ReleaseVersion, releaseDigest, modelRevision, map[bool]string{true: "live read-only", false: "offline"}[request.live], len(plan.Proxmox.Guests), len(plan.Firewall.Rules), len(plan.Proxmox.ArtifactFiles))
	if request.live {
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
	endpointLookup := net.LookupIP
	if s.Gateway.Mode == model.GatewayModeManaged {
		rootRunner := proxmoxRootSSHRunner(s, siteDir)
		if err := proxmox.WaitForSSH(ctx, rootRunner, s.BootstrapAddress, "root", 1, 0); err != nil {
			return fmt.Errorf("observe authenticated bootstrap path: %w", err)
		}
		endpointLookup = endpointLookupWithFallback(net.LookupIP, remoteEndpointResolver(ctx, rootRunner, s.BootstrapAddress, "root"))
	}
	guestPlans := deploymentGuestPlans(s, plan.Proxmox)
	guestStates, err := inspectDeploymentGuestStates(ctx, client, node, guestPlans)
	if err != nil {
		return fmt.Errorf("observe planned guest state: %w", err)
	}
	plan.Observations = deploymentObservations{Node: node, Guests: deploymentGuestObservations(guestPlans, guestStates)}
	if plan.Firewall.AirVPN != nil {
		resolved, err := firewall.BindAirVPNEndpoint(plan.Firewall, endpointLookup)
		if err != nil {
			return err
		}
		plan.Firewall = resolved
	}
	if err := validateExternalEndpointReadiness(s, endpointLookup); err != nil {
		return err
	}
	return nil
}

func deploymentGuestObservations(guests []proxmox.GuestPlan, states map[int]deploymentGuestArtifactState) []deploymentGuestObservation {
	observations := make([]deploymentGuestObservation, 0, len(guests))
	for _, guest := range guests {
		state := states[guest.VMID]
		observations = append(observations, deploymentGuestObservation{
			VMID: guest.VMID, Name: guest.Name, Exists: state.exists, Replacement: state.replacement,
		})
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].VMID < observations[j].VMID })
	return observations
}
