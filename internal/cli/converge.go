package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	aiopsmodel "github.com/gofastercloud/boetticher/internal/aiops"
	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/appliance"
	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/telemetry"
	"golang.org/x/crypto/ssh"
)

func runDeploy(args []string, out io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runDeployWithContext(ctx, args, out)
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func guideInteractiveDeploy(siteDir, ageIdentity string, out io.Writer) (string, error) {
	var planOutput bytes.Buffer
	if err := runPlanRequest(planRequest{
		siteDir: siteDir, ageIdentity: ageIdentity, live: true,
	}, &planOutput); err != nil {
		return "", fmt.Errorf("prepare live deployment plan: %w", err)
	}
	digest, err := planDigestFromOutput(planOutput.String())
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, &planOutput); err != nil {
		return "", err
	}
	fmt.Fprintf(out, "Apply this exact live plan (%s)? Type APPLY to continue: ", digest)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read deployment approval: %w", err)
	}
	if strings.TrimSpace(answer) != "APPLY" {
		return "", errors.New("deployment not approved")
	}
	return digest, nil
}

func planDigestFromOutput(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Digest:") {
			continue
		}
		digest := strings.TrimSpace(strings.TrimPrefix(line, "Digest:"))
		if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
			return "", errors.New("live deployment plan returned an invalid digest")
		}
		for _, char := range digest[len("sha256:"):] {
			if !strings.ContainsRune("0123456789abcdef", char) {
				return "", errors.New("live deployment plan returned an invalid digest")
			}
		}
		return digest, nil
	}
	return "", errors.New("live deployment plan did not return a digest")
}

func validateDeployRecoveryOptions(gatewayMode string, replaceFirewall, recreateLegacyLXCs, confirm, dryRun bool) error {
	if replaceFirewall {
		if gatewayMode != model.GatewayModeManaged {
			return errors.New("--replace-firewall is available only in managed gateway mode")
		}
		if !confirm && !dryRun {
			return errors.New("--replace-firewall requires --confirm; use --dry-run to inspect the recovery plan")
		}
	}
	if recreateLegacyLXCs && !confirm && !dryRun {
		return errors.New("--recreate-legacy-lxcs requires --confirm outside --dry-run")
	}
	return nil
}

func runDeployWithContext(ctx context.Context, args []string, out io.Writer) (resultErr error) {
	report := newDeploymentReport(out)
	ctx = telemetry.WithObserver(ctx, report)
	lockSiteDir, dryRun := deploymentLockInputs(args)
	var operationLock *site.OperationLock
	if !dryRun {
		var lockErr error
		operationLock, lockErr = site.AcquireOperationLock(lockSiteDir)
		if lockErr != nil {
			return lockErr
		}
		defer func() {
			if unlockErr := operationLock.Release(); unlockErr != nil {
				resultErr = combineDeploymentErrors(resultErr, unlockErr)
			}
		}()
	}
	var cleanup func(context.Context) error
	var commit func() error
	var markOperationFailure func(error)
	operationErr := runDeployOperation(ctx, args, out, report, func(fn func(context.Context) error) {
		cleanup = fn
	}, func(fn func() error) {
		commit = fn
	}, func(fn func(error)) {
		markOperationFailure = fn
	})
	if cleanup != nil {
		report.setCleanup(true, false, nil)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cleanupErr := report.timed("cleanup", "temporary-authority", "deployment", func() error {
			return cleanup(cleanupCtx)
		})
		cancel()
		if cleanupErr == nil {
			report.setCleanup(true, true, nil)
		} else {
			report.setCleanup(true, false, cleanupErr)
		}
		operationErr = combineDeploymentErrors(operationErr, cleanupErr)
	}
	if operationErr != nil && markOperationFailure != nil {
		markOperationFailure(operationErr)
	}
	if operationErr == nil && commit != nil {
		if commitErr := commit(); commitErr != nil {
			if markOperationFailure != nil {
				markOperationFailure(commitErr)
			}
			operationErr = combineDeploymentErrors(operationErr, commitErr)
		}
	}
	operationErr = report.finalize(operationErr)
	resultErr = deploymentErrorForOperator(operationErr)
	return resultErr
}

func deploymentLockInputs(args []string) (string, bool) {
	siteDir := "."
	dryRun := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--dry-run":
			dryRun = true
		case "--site":
			if index+1 < len(args) {
				index++
				siteDir = args[index]
			}
		default:
			if strings.HasPrefix(args[index], "--site=") {
				siteDir = strings.TrimPrefix(args[index], "--site=")
			}
		}
	}
	if siteDir == "" {
		siteDir = "."
	}
	return siteDir, dryRun
}

func runDeployOperation(ctx context.Context, args []string, out io.Writer, report *deploymentReport, registerCleanup deploymentCleanupRegistrar, registerCommit func(func() error), registerOperationFailure func(func(error))) (err error) {
	var operationState site.OperationState
	operationStarted := false
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	dryRun := fs.Bool("dry-run", false, "render and validate policy without connecting")
	planDigestFlag := fs.String("plan", "", "exact immutable plan digest produced by boetticher plan --live")
	replaceFirewall := fs.Bool("replace-firewall", false, "replace only the managed firewall root disk after proving its persistent volumes")
	recreateLegacyLXCs := fs.Bool("recreate-legacy-lxcs", false, "discard only proven legacy local-raw LXC state and recreate those appliances on planned storage")
	confirm := fs.Bool("confirm", false, "confirm destructive appliance replacement or purge actions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*dryRun && *planDigestFlag == "" {
		if !stdinIsTerminal() {
			return errors.New("deploy requires --plan DIGEST when stdin is not an interactive terminal; run boetticher plan --live first")
		}
		approvedDigest, approveErr := guideInteractiveDeploy(*siteDir, *ageIdentity, out)
		if approveErr != nil {
			return approveErr
		}
		*planDigestFlag = approvedDigest
	}
	report.dryRun = *dryRun
	report.start("validate", "Validate desired state")
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if !*dryRun {
		if err := recoverInterruptedDeployment(ctx, *siteDir, s, out); err != nil {
			return err
		}
	}
	releaseManifest := artifacts.ReleaseManifest{ReleaseVersion: model.ReleaseVersion}
	releaseDigest := ""
	if !*dryRun {
		var releaseErr error
		releaseManifest, releaseDigest, releaseErr = artifacts.ImportedReleaseManifest(*siteDir)
		if releaseErr != nil {
			return fmt.Errorf("authenticated release bundle is required before deployment: %w", releaseErr)
		}
	}
	pendingPurge, hasPendingPurge, err := loadPendingModulePurge(*siteDir, s)
	if err != nil {
		return fmt.Errorf("validate pending module purge: %w", err)
	}
	if hasPendingPurge && !*dryRun && !*confirm {
		return fmt.Errorf("module %s purge is pending; deploy requires --confirm to apply the destructive operation", pendingPurge.intent.Module)
	}
	if err := validateDeployRecoveryOptions(s.Gateway.Mode, *replaceFirewall, *recreateLegacyLXCs, *confirm, *dryRun); err != nil {
		return err
	}
	modelRevision, err := s.Revision()
	if err != nil {
		return fmt.Errorf("calculate model revision: %w", err)
	}
	report.setIdentity(model.PlatformVersion, modelRevision)
	report.setTimingPath(filepath.Join(site.RuntimeDir(s), "deploy", report.runID+".json"))
	if !*dryRun {
		operationState = site.OperationState{
			ID:            report.runID,
			Kind:          "deploy",
			Phase:         site.PhasePlan,
			ModelRevision: modelRevision,
			BundleDigest:  releaseDigest,
		}
		if err := site.SaveOperationState(*siteDir, operationState); err != nil {
			return fmt.Errorf("record deployment PLAN phase: %w", err)
		}
		operationStarted = true
		if registerOperationFailure != nil {
			registerOperationFailure(func(cause error) {
				if !operationStarted {
					return
				}
				if journalErr := saveDeployOperationPhase(*siteDir, &operationState, site.PhaseFailed, cause); journalErr != nil {
					fmt.Fprintf(out, "      FAIL: could not persist deployment failure journal: %s\n", compactError(journalErr))
				}
			})
		}
		if registerCommit != nil {
			registerCommit(func() error {
				if !operationStarted {
					return nil
				}
				if err := saveDeployOperationPhase(*siteDir, &operationState, site.PhaseCommit, nil); err != nil {
					return fmt.Errorf("record deployment commit phase: %w", err)
				}
				if err := site.SaveLastAppliedState(*siteDir, site.LastAppliedState{
					ModelRevision: modelRevision,
					PlanDigest:    operationState.PlanDigest,
					BundleDigest:  releaseDigest,
				}); err != nil {
					return fmt.Errorf("record last-applied deployment state: %w", err)
				}
				if err := site.ClearOperationState(*siteDir); err != nil {
					return fmt.Errorf("clear committed deployment operation: %w", err)
				}
				operationStarted = false
				return nil
			})
		}
	}
	var airvpnProfile *preparedAirVPNProfile
	if err := report.timed("validate", "provider", "airvpn-profile", func() error {
		var profileErr error
		// Deployment only consumes the retained encrypted profile. Provider
		// generation is an explicit operator operation, so PLAN never creates
		// credentials or depends on WAN access.
		airvpnProfile, profileErr = prepareAirVPNProfile(ctx, *siteDir, s, *ageIdentity, true, false)
		return profileErr
	}); err != nil {
		return err
	}
	var firewallPlan firewall.Plan
	if err := report.timed("validate", "local", "firewall-plan", func() error {
		if airvpnProfile == nil {
			firewallPlan, err = firewall.PlanFromSite(s)
		} else {
			firewallPlan, err = firewall.PlanFromSiteWithAirVPN(s, airvpnProfile.Metadata)
		}
		return err
	}); err != nil {
		return err
	}
	if airvpnProfile != nil && airvpnProfile.Created {
		report.recordMutation("Secrets", "airvpn_wireguard_config", "encrypted provider profile stored", true)
	}
	var airvpnMetadata *firewall.AirVPNProfile
	if airvpnProfile != nil {
		airvpnMetadata = &airvpnProfile.Metadata
	}
	report.complete()
	if *dryRun {
		report.start("artifacts", "Resolve qualified artifacts")
		fmt.Fprintf(out, "Deployment plan: PASS model %s\n", firewallPlan.ModelRevision)
		fmt.Fprintf(out, "  Mode: %s\n  Engine: %s\n  DHCP subnets: %d\n  Policy rules: %d\n", firewallPlan.Mode, firewallPlan.Engine, len(firewallPlan.DHCP), len(firewallPlan.Rules))
		if *replaceFirewall {
			fmt.Fprintln(out, "  Firewall root recovery: requested (dry-run; declared persistent volumes remain attached)")
		}
		if *recreateLegacyLXCs {
			fmt.Fprintln(out, "  Legacy LXC recovery: requested (dry-run; no appliance state is discarded)")
		}
		if s.Gateway.Mode == model.GatewayModeManaged {
			ruleset, renderErr := renderDeploymentNFT(firewallPlan)
			if renderErr != nil {
				return renderErr
			}
			if err := firewall.ValidateNFT(ruleset); err != nil {
				return err
			}
			fmt.Fprintln(out, "  nftables: valid generated ruleset")
		} else {
			fmt.Fprintln(out, "  External contract: generated")
		}
		fmt.Fprintln(out, "  Destructive actions: not applied (dry-run)")
		if hasPendingPurge {
			fmt.Fprintf(out, "  Pending purge: PASS %s (%d exact owned guest(s)); deploy --confirm will apply it\n", pendingPurge.intent.Module, len(pendingPurge.intent.Guests))
		}
		var plan proxmox.Plan
		if err := report.timed("artifacts", "local", "proxmox-plan", func() error {
			var planErr error
			plan, planErr = proxmox.PlanFromSite(s)
			return planErr
		}); err != nil {
			return err
		}
		if err := report.timed("artifacts", "qualification", "selected-artifacts", func() error {
			var qualifyErr error
			plan, qualifyErr = proxmox.ResolveQualifiedArtifacts(*siteDir, plan, true)
			return qualifyErr
		}); err != nil {
			fmt.Fprintf(out, "  Artifact qualification: FAIL (%s)\n", compactError(err))
			return err
		}
		fmt.Fprintln(out, "  Artifact qualification: PASS (all selected artifacts qualified)")
		if err := report.timed("artifacts", "local", "static-readiness", func() error {
			return validateStaticDeploymentReadiness(*siteDir, s, *ageIdentity, firewallPlan, plan)
		}); err != nil {
			fmt.Fprintf(out, "  Static deployment checks: FAIL (%s)\n", compactError(err))
			return fmt.Errorf("static preflight failed: %w", err)
		}
		fmt.Fprintln(out, "  Static deployment checks: PASS")
		fmt.Fprintln(out, "  Appliances:")
		for _, guest := range plan.Guests {
			fmt.Fprintf(out, "    %s  %s  %s  definition=%s\n", guest.Name, guest.Artifact.Name, artifactQualificationStatus(guest.Artifact), guest.Artifact.DefinitionSHA256)
			for _, volume := range guest.Volumes {
				fmt.Fprintf(out, "    volume %s -> %s (%s, backup=%t)\n", volume.Name, volume.MountPath, volume.Placement, volume.Backup)
			}
		}
		report.complete()
		return nil
	}
	report.start("artifacts", "Resolve qualified artifacts")
	ansibleRoot, cleanupAnsibleSource, err := ansibleSourceRoot()
	if err != nil {
		return fmt.Errorf("resolve Ansible playbook source: %w", err)
	}
	defer cleanupAnsibleSource()
	ansiblePlaybook := filepath.Join(ansibleRoot, "ansible", "site.yml")
	endpointLookup := net.LookupIP
	recoveryRunner := proxmoxRootSSHRunner(s, *siteDir)
	var backupPlan backup.Plan
	var storagePlan storage.Plan
	var proxmoxPlan proxmox.Plan
	if err := report.timed("artifacts", "local", "proxmox-plan", func() error {
		var planErr error
		proxmoxPlan, planErr = proxmox.PlanFromSite(s)
		return planErr
	}); err != nil {
		return err
	}
	if err := report.timed("artifacts", "qualification", "selected-artifacts", func() error {
		var qualifyErr error
		proxmoxPlan, qualifyErr = proxmox.ResolveQualifiedArtifacts(*siteDir, proxmoxPlan, true)
		return qualifyErr
	}); err != nil {
		return err
	}
	var proxmoxClient *proxmox.Client
	var node string
	var guestStates map[int]deploymentGuestArtifactState
	var rootRunner proxmox.SSHRunner
	if airvpnMetadata != nil {
		if err := report.timed("artifacts", "provider", "airvpn-endpoint", func() error {
			var bindErr error
			firewallPlan, bindErr = firewall.BindAirVPNEndpoint(firewallPlan, endpointLookup)
			return bindErr
		}); err != nil {
			return err
		}
		airvpnMetadata = firewallPlan.AirVPN
	}
	if backupPlan, err = backup.PlanFromSite(s); err != nil {
		return err
	}
	if storagePlan, err = storage.PlanFromSite(s); err != nil {
		return err
	}
	proxmoxClient, _, err = loadProxmoxClientWithSnippetUser(*siteDir, s, *ageIdentity, "", false, model.DefaultAdminSSHUser)
	if err != nil {
		return fmt.Errorf("load Proxmox client for platform deployment: %w", err)
	}
	node, err = proxmoxClient.SingleNode(ctx)
	if err != nil {
		return fmt.Errorf("resolve live Proxmox node: %w", err)
	}
	proxmoxPlan.Node = node
	proxmoxPlan.DestructiveConfirmed = *confirm
	proxmoxPlan.ForceFirewallRootReplacement = *replaceFirewall
	proxmoxPlan.ForceLegacyLXCRecreation = *recreateLegacyLXCs
	if err := validateLiveDeploymentPrerequisitesWithResolver(ctx, proxmoxClient, nil, *siteDir, s, proxmoxPlan, storagePlan, endpointLookup); err != nil {
		return fmt.Errorf("live preflight failed before Proxmox mutation: %w", err)
	}
	guestPlans := deploymentGuestPlans(s, proxmoxPlan)
	guestStates, err = inspectDeploymentGuestStates(ctx, proxmoxClient, node, guestPlans)
	if err != nil {
		return fmt.Errorf("observe planned guest state: %w", err)
	}
	if *recreateLegacyLXCs {
		var legacyLXCTargets []string
		if err := report.timed("artifacts", "preflight", "legacy-lxc-recovery", func() error {
			var validateErr error
			legacyLXCTargets, validateErr = proxmox.ValidateLegacyLXCRecreation(ctx, proxmoxClient, proxmoxPlan)
			return validateErr
		}); err != nil {
			return fmt.Errorf("live preflight failed before legacy LXC recovery: %w", err)
		}
		fmt.Fprintf(out, "Legacy LXC recovery preflight: PASS %d exact legacy appliance(s)\n", len(legacyLXCTargets))
	}
	planDigest, err := digestDeploymentPlan(deploymentPlan{
		Version: deploymentPlanFormatVersion, ReleaseVersion: releaseManifest.ReleaseVersion,
		ReleaseDigest: releaseDigest, ModelRevision: modelRevision, Live: true,
		Proxmox: proxmoxPlan, Firewall: firewallPlan, Storage: storagePlan, Backup: backupPlan,
		Observations:    deploymentObservations{Node: node, Guests: deploymentGuestObservations(guestPlans, guestStates)},
		ReplaceFirewall: *replaceFirewall, RecreateLegacy: *recreateLegacyLXCs,
	})
	if err != nil {
		return fmt.Errorf("digest immutable deployment plan: %w", err)
	}
	operationState.PlanDigest = planDigest
	operationState.BundleDigest = releaseDigest
	operationState.Phase = site.PhaseApply
	if *planDigestFlag != "" && *planDigestFlag != planDigest {
		return fmt.Errorf("stale deployment plan: supplied %s, current live plan is %s", *planDigestFlag, planDigest)
	}
	if registerCleanup == nil {
		return errors.New("deployment cleanup registration is required before Apply authority")
	}
	durableOperatorPublicKey, err := operatorPublicKeyForSite(s)
	if err != nil {
		return fmt.Errorf("resolve durable operator identity before Apply: %w", err)
	}
	temporaryPrivateKey, deploymentPublicKey, err := newTemporaryRootIdentity()
	if err != nil {
		return err
	}
	cleanupGuests, err := operationCleanupGuests(proxmoxPlan)
	if err != nil {
		for index := range temporaryPrivateKey {
			temporaryPrivateKey[index] = 0
		}
		return err
	}
	operationState.TemporaryPublicKey = deploymentPublicKey
	operationState.TemporaryHostAddress = s.BootstrapAddress
	operationState.TemporaryCleanupGuests = cleanupGuests
	if err := site.SaveOperationState(*siteDir, operationState); err != nil {
		for index := range temporaryPrivateKey {
			temporaryPrivateKey[index] = 0
		}
		return fmt.Errorf("journal temporary Apply authority before mutation: %w", err)
	}
	rootCleanup := newTemporaryRootCleanup(s, *siteDir, deploymentPublicKey, temporaryPrivateKey)
	// Mark the host as owned before the first remote authority mutation. If key
	// installation fails after changing authorized_keys, the registered cleanup
	// still attempts to remove this exact key.
	rootCleanup.hostEstablished()
	registerCleanup(func(cleanupCtx context.Context) error {
		journalErr := saveDeployOperationPhase(*siteDir, &operationState, site.PhaseCleanup, nil)
		cleanupErr := rootCleanup.revoke(cleanupCtx)
		return combineDeploymentErrors(journalErr, cleanupErr)
	})
	if err := proxmox.InstallTemporaryRootAccess(ctx, recoveryRunner, s.BootstrapAddress, "root", deploymentPublicKey); err != nil {
		return fmt.Errorf("acquire temporary Apply authority: %w", err)
	}
	rootRunner = recoveryRunner.WithIdentityData(temporaryPrivateKey).FreshConnection()
	// Host operations use the HOME-side address directly. Removing the
	// generated host alias also prevents its durable operator IdentityFile from
	// entering the temporary-root authentication set.
	rootRunner.ConfigFile = ""
	rootRunner.HostAlias = ""
	rootRunner.HostKeyAlias = model.LogicalProxmoxIdentity
	if err := proxmoxClient.SetSnippetRunner(rootRunner, s.BootstrapAddress, "root"); err != nil {
		return fmt.Errorf("bind temporary Apply authority to Proxmox host operations: %w", err)
	}
	if err := validateLiveDeploymentPrerequisitesWithResolver(ctx, proxmoxClient, rootRunner, *siteDir, s, proxmoxPlan, storagePlan, endpointLookup); err != nil {
		return fmt.Errorf("live preflight failed after exact plan acceptance: %w", err)
	}
	report.complete()
	report.start("credentials-pki", "Prepare credentials and PKI")
	if err := report.timed("credentials-pki", "local", "static-readiness", func() error {
		return validateStaticDeploymentReadiness(*siteDir, s, *ageIdentity, firewallPlan, proxmoxPlan)
	}); err != nil {
		return fmt.Errorf("static preflight failed: %w", err)
	}
	retainedGuests, err := retainedGuestPlans(s)
	if err != nil {
		return err
	}
	var variables []byte
	if err := report.timed("credentials-pki", "local", "ansible-variables", func() error {
		if airvpnMetadata == nil {
			variables, err = ansible.VariablesWithOperatorKey(s, durableOperatorPublicKey)
		} else {
			variables, err = ansible.VariablesWithOperatorKeyAndAirVPN(s, durableOperatorPublicKey, *airvpnMetadata)
		}
		return err
	}); err != nil {
		return err
	}
	var runtimeVariables map[string]any
	if err := json.Unmarshal(variables, &runtimeVariables); err != nil {
		return fmt.Errorf("decode Ansible variables: %w", err)
	}
	credentialBindings, err := deploymentCredentialBindings(s)
	if err != nil {
		return err
	}
	runtimeVariables["boetticher_appliance_artifact"] = true
	// Agent installation is enabled only in the post-Pulse bootstrap pass,
	// after the scoped report token and encrypted credential projection exist.
	runtimeVariables["pulse_agent_install_enabled"] = false
	monitoringEnabled := modules.IsEnabled(s, "monitoring")
	aiopsEnabled := modules.IsEnabled(s, "aiops")
	secretValues := map[string]string{}
	platformSecrets, err := site.LoadPlatformSecretCache(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load encrypted platform secrets: %w", err)
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ddnsTSIG, loadErr := platformSecrets.Get("ddns_tsig_secret")
		if loadErr != nil {
			return fmt.Errorf("load encrypted DDNS TSIG material: %w", loadErr)
		}
		secretValues["firewall-ddns-tsig"] = ddnsTSIG
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ruleset, renderErr := renderDeploymentNFTWithResolver(firewallPlan, endpointLookup)
		if renderErr != nil {
			return renderErr
		}
		runtimeVariables["firewall_ruleset"] = ruleset
		runtimeVariables["firewall_ruleset_sha256"] = firewall.RulesetDigest(ruleset)
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load platform CA chain: %w", err)
	}
	revocations, err := site.LoadClientRevocations(*siteDir)
	if err != nil {
		return fmt.Errorf("HOLD: load client revocations: %w", err)
	}
	var clientCRL string
	if err := report.timed("credentials-pki", "local", "client-crl", func() error {
		var crlErr error
		clientCRL, crlErr = generateOrReuseClientCRL(authority, revocations, site.RuntimeDir(s), time.Now().UTC())
		return crlErr
	}); err != nil {
		return fmt.Errorf("HOLD: generate enforceable client revocation list: %w", err)
	}
	runtimeVariables["client_crl_pem"] = clientCRL
	var pulseAdminPassword string
	if monitoringEnabled {
		var loadErr error
		pulseAdminPassword, loadErr = platformSecrets.Get("pulse_admin_password")
		if loadErr != nil {
			return fmt.Errorf("load encrypted Pulse administrative password: %w", loadErr)
		}
		secretValues["pulse_admin_password"] = pulseAdminPassword
		pulseProxyAuthSecret, created, loadErr := loadOrCreateRandomSecret(*siteDir, *ageIdentity, s, "pulse_proxy_auth_secret")
		if loadErr != nil {
			return loadErr
		}
		if created {
			report.recordMutation("Secrets", "pulse_proxy_auth_secret", "credential stored", true)
		}
		secretValues["pulse_proxy_auth_secret"] = pulseProxyAuthSecret
	}
	activeCredentialBindings := make([]deploymentCredential, 0, len(credentialBindings))
	for _, binding := range credentialBindings {
		if binding.Guest == "lab-aiops-01" {
			// Pulse-scoped tokens and the webhook secret are reconciled only
			// after Pulse and AI Router pass their live qualification gates.
			continue
		}
		if _, alreadyLoaded := secretValues[binding.SecretKey]; alreadyLoaded {
			activeCredentialBindings = append(activeCredentialBindings, binding)
			continue
		}
		value, loadErr := platformSecrets.Get(binding.SecretKey)
		if loadErr != nil {
			if binding.SecretKey == "tailscale_auth_key" && errors.Is(loadErr, site.ErrPlatformSecretMissing) {
				// A retained, valid Tailscale state file is the durable node
				// identity. The runtime helper will use it without a fresh key;
				// a missing/invalid state fails closed at service start.
				continue
			}
			return fmt.Errorf("load encrypted %s credential: %w", binding.SecretKey, loadErr)
		}
		activeCredentialBindings = append(activeCredentialBindings, binding)
		secretValues[binding.SecretKey] = value
	}
	credentialBindings = activeCredentialBindings
	runtimeVariables["credential_dropins"], err = credentialDropIns(credentialBindings)
	if err != nil {
		return err
	}
	runtimeVariables["client_ca_pem"] = authority.RootCertPEM + authority.IssuingCertPEM
	runtimeVariables["pulse_server_ca_pem"] = authority.RootCertPEM + authority.IssuingCertPEM
	if proxmoxCredentials, loadErr := site.LoadProxmoxCredentials(*siteDir, s, *ageIdentity); loadErr != nil {
		return fmt.Errorf("load encrypted Proxmox credentials for API trust projection: %w", loadErr)
	} else if proxmoxCredentials.CAPEM != "" {
		runtimeVariables["proxmox_ca_pem"] = proxmoxCredentials.CAPEM
	}
	inventoryPath := filepath.Join(*siteDir, "generated", "ansible", "inventory.ini")
	csrDir := filepath.Join(site.RuntimeDir(s), "pki")
	if err := os.MkdirAll(csrDir, 0700); err != nil {
		return fmt.Errorf("create controller PKI runtime directory: %w", err)
	}
	runtimeVariables["pki_bootstrap_phase"] = true
	runtimeVariables["pki_csr_output_dir"] = csrDir
	if err := report.timed("credentials-pki", "local", "projections", func() error {
		return writeModelProjectionsWithResolverAndAirVPN(*siteDir, s, endpointLookup, airvpnMetadata)
	}); err != nil {
		return err
	}
	report.recordMutation("Generated state", "site projections", "reconciled", true)
	variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	variables = append(variables, '\n')
	report.complete()
	proxmoxPlan.OperatorPublicKey = durableOperatorPublicKey
	if s.Gateway.Mode == model.GatewayModeManaged {
		for _, guest := range proxmoxPlan.Guests {
			if guest.Name != "lab-fw-01" {
				continue
			}
			cloudInit, renderErr := proxmox.RenderFirewallCloudInitWithKey(guest, durableOperatorPublicKey)
			if renderErr != nil {
				return fmt.Errorf("render firewall first-boot cloud-init: %w", renderErr)
			}
			proxmoxPlan.CloudInitFiles = cloudInit
			break
		}
	}
	proxmoxPlan.PrivilegedRunner = rootRunner
	proxmoxPlan.PrivilegedAddress = s.BootstrapAddress
	proxmoxPlan.PrivilegedUser = "root"
	report.start("proxmox", "Reconcile Proxmox platform and storage")
	if s.Gateway.Mode == model.GatewayModeManaged {
		// Host identity reconciliation is an apply action. Keep it behind the
		// durable plan journal so every live mutation has a recoverable owner.
		// Reconcile the live host-side jump policy from the canonical destinations
		// only after the read-only preflight and APPLY journal are complete.
		if err := proxmox.ConfigureBastionPolicy(ctx, rootRunner, s.BootstrapAddress, "root", jumpDestinations(s)); err != nil {
			return fmt.Errorf("reconcile Proxmox bastion policy: %w", err)
		}
	}
	if hasPendingPurge {
		pendingPurge.plan.Node = proxmoxPlan.Node
		if err := report.timed("proxmox", "apply", "module-purge", func() error {
			return proxmox.PurgeModule(ctx, proxmoxClient, pendingPurge.plan, pendingPurge.intent.Module)
		}); err != nil {
			return err
		}
		report.recordMutation("Proxmox", pendingPurge.intent.Module, "owned module guests purged", true)
		declaration, ok := findDeclaration(pendingPurge.purgeSite, pendingPurge.intent.Module)
		if !ok {
			return fmt.Errorf("module %s purge declaration disappeared during deployment", pendingPurge.intent.Module)
		}
		if err := site.PurgeModuleSecrets(*siteDir, pendingPurge.purgeSite, *ageIdentity, pendingPurge.intent.Module, declaration); err != nil {
			return fmt.Errorf("remove module secrets after purge: %w", err)
		}
		if err := site.ClearPurgeIntent(*siteDir); err != nil {
			return fmt.Errorf("commit module purge completion: %w", err)
		}
		report.recordMutation("Generated state", "module purge intent", "cleared after verified purge", true)
	}
	var pulseProxmoxToken string
	if monitoringEnabled {
		pulseProxmoxToken, err = site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_proxmox_token")
		if errors.Is(err, site.ErrPlatformSecretMissing) {
			pulseProxmoxToken, err = proxmox.ReplacePulseMonitoringCredentials(ctx, rootRunner, s.BootstrapAddress, "root")
			if err != nil {
				return err
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_proxmox_token", pulseProxmoxToken); err != nil {
				return fmt.Errorf("store encrypted Pulse Proxmox token: %w", err)
			}
			report.recordMutation("Secrets", "pulse_proxmox_token", "credential stored", true)
		} else if err != nil {
			return fmt.Errorf("load encrypted Pulse Proxmox token: %w", err)
		}
	}
	if backupPlan.StorageTarget == backup.DedicatedStorageID {
		changed, err := proxmoxClient.EnsureLVMThinStorageWithMutation(ctx, storage.GuestStorageID, storage.VolumeGroup, storage.ThinPool)
		if changed {
			report.recordMutation("Proxmox", storage.GuestStorageID, "guest storage registered", true)
		}
		if err != nil {
			return fmt.Errorf("ensure dedicated guest storage: %w", err)
		}
		changed, err = proxmoxClient.EnsureDirectoryStorageContentWithMutation(ctx, backup.DedicatedStorageID, backup.DedicatedStoragePath, []string{"backup"})
		if changed {
			report.recordMutation("Proxmox", backup.DedicatedStorageID, "backup storage registered", true)
		}
		if err != nil {
			return fmt.Errorf("ensure dedicated backup storage: %w", err)
		}
	} else {
		localContent, contentErr := storage.LocalStorageContent(s.StorageProfile)
		if contentErr != nil {
			return contentErr
		}
		changed, err := proxmoxClient.EnsureDirectoryStorageContentWithMutation(ctx, "local", "/var/lib/vz", localContent)
		if changed {
			report.recordMutation("Proxmox", "local", "storage content reconciled", true)
		}
		if err != nil {
			return fmt.Errorf("ensure local Proxmox storage: %w", err)
		}
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		firewallGuest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1"}
		for _, candidate := range proxmoxPlan.Guests {
			if candidate.Kind == proxmox.KindQEMU {
				firewallGuest = candidate
				break
			}
		}
		firewallExisted, firewallReplaced, stateErr := proxmox.InspectGuestArtifact(ctx, proxmoxClient, proxmoxPlan.Node, firewallGuest)
		if stateErr != nil {
			return stateErr
		}
		if *replaceFirewall && firewallExisted {
			firewallReplaced = true
		}
		if err := report.timed("proxmox", "reconcile", firewallGuest.Name, func() error {
			return proxmox.EnsureFirewallVM(ctx, proxmoxClient, proxmoxPlan)
		}); err != nil {
			if !firewallExisted || firewallReplaced {
				report.markMutationUncertain()
			}
			return fmt.Errorf("create managed gateway appliance: %w", err)
		}
		if !firewallExisted {
			report.recordMutation("Proxmox", firewallGuest.Name, "guest created", true)
		}
		if firewallReplaced {
			report.recordMutation("Proxmox", firewallGuest.Name, "guest replaced", true)
		}
		if firewallReplaced {
			if err := retireReplacedHostKey(*siteDir, s, firewallGuest); err != nil {
				return fmt.Errorf("retire replaced gateway host key: %w", err)
			}
		}
		if err := report.timed("proxmox", "reconcile", firewallGuest.Name+"/start", func() error {
			return proxmoxClient.EnsureVMRunning(ctx, proxmoxPlan.Node, model.ProxmoxVMID)
		}); err != nil {
			return fmt.Errorf("start managed gateway appliance: %w", err)
		}
	}
	report.complete()
	report.start("appliances", "Reconcile appliance guests")
	var firewallRunner proxmox.SSHRunner
	if s.Gateway.Mode == model.GatewayModeManaged {
		firewallRunner = applianceSSHRunnerWithIdentity(s, *siteDir, "lab-fw-01", temporaryPrivateKey)
		firewallGuest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1"}
		// Cloud-init may have installed the temporary key before SSH becomes
		// reachable. Register the exact owned guest before the readiness probe
		// so cleanup can fall back through the Proxmox host if boot stalls.
		rootCleanup.guestEstablished(firewallGuest)
		if err := report.timed("appliances", "readiness", firewallGuest.Name, func() error {
			return waitForDeploymentRoot(ctx, rootRunner, s.BootstrapAddress, firewallRunner.FreshConnection(), firewallGuest, deploymentPublicKey, deploymentKnownHosts(*siteDir), firewallGuest.Hostname+"."+s.Network.Domain, func() {
				rootCleanup.guestEstablished(firewallGuest)
			})
		}); err != nil {
			return fmt.Errorf("HOLD: managed gateway is not reachable before dependent appliances: %w", err)
		}
		if err := verifyFirewallBootstrapNetwork(ctx, firewallRunner); err != nil {
			return fmt.Errorf("HOLD: managed gateway bootstrap network is not ready before runtime configuration: %w", err)
		}
		if err := installCredentialsForGuest(ctx, firewallRunner, "lab-fw-01", credentialBindings, secretValues); err != nil {
			return fmt.Errorf("install managed gateway credentials: %w", err)
		}
		if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, variables, "lab-fw-01", report, temporaryPrivateKey); err != nil {
			return fmt.Errorf("HOLD: configure managed gateway before dependent appliances: %w", err)
		}
		if err := report.timed("appliances", "readiness", firewallGuest.Name+"/gateway", func() error {
			return verifyGatewayReadiness(ctx, firewallRunner, "10.10.99.1")
		}); err != nil {
			return fmt.Errorf("HOLD: managed gateway did not pass runtime readiness before dependent appliances: %w", err)
		}
	}
	if err := report.timed("appliances", "preflight", "guest-state", func() error {
		if guestStates == nil {
			return errors.New("live guest observations were not captured before APPLY")
		}
		return nil
	}); err != nil {
		return err
	}
	dnsPlan, err := dns.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("resolve DNS readiness contract: %w", err)
	}
	for _, module := range deploymentModuleNames(s) {
		if !modules.IsEnabled(s, module) {
			continue
		}
		replacedGuests := make([]proxmox.GuestPlan, 0)
		missingGuests := make([]proxmox.GuestPlan, 0)
		for _, candidate := range proxmoxPlan.Guests {
			matches := candidate.Owner == "boetticher/module/"+module
			if !matches || candidate.Kind != proxmox.KindLXC {
				continue
			}
			state, ok := guestStates[candidate.VMID]
			if !ok {
				return fmt.Errorf("inspect %s state: guest was not included in preflight", candidate.Name)
			}
			existed, replacement := state.exists, state.replacement
			if replacement {
				replacedGuests = append(replacedGuests, candidate)
			}
			if !existed {
				missingGuests = append(missingGuests, candidate)
			}
		}
		if err := report.timed("appliances", "proxmox", module, func() error {
			return proxmox.ProvisionModule(ctx, proxmoxClient, proxmoxPlan, module)
		}); err != nil {
			if len(missingGuests) > 0 || len(replacedGuests) > 0 {
				report.markMutationUncertain()
			}
			return fmt.Errorf("deploy %s appliances: %w", module, err)
		}
		for _, guest := range missingGuests {
			report.recordMutation("Proxmox", guest.Name, "guest created", true)
		}
		for _, guest := range replacedGuests {
			report.recordMutation("Proxmox", guest.Name, "guest replaced", true)
		}
		for _, guest := range replacedGuests {
			if err := retireReplacedHostKey(*siteDir, s, guest); err != nil {
				return fmt.Errorf("retire replaced %s host key: %w", guest.Name, err)
			}
		}
		for _, guest := range proxmoxPlan.Guests {
			matches := guest.Owner == "boetticher/module/"+module
			if !matches || guest.Kind != proxmox.KindLXC {
				continue
			}
			guestRunner := applianceSSHRunnerWithIdentity(s, *siteDir, guest.Name, temporaryPrivateKey)
			// Register before waiting for SSH: first boot may already have
			// accepted the temporary key while the guest service is still down.
			rootCleanup.guestEstablished(guest)
			if err := report.timed("appliances", "readiness", guest.Name, func() error {
				return waitForDeploymentRoot(ctx, rootRunner, s.BootstrapAddress, guestRunner.FreshConnection(), guest, deploymentPublicKey, deploymentKnownHosts(*siteDir), guest.Hostname+"."+s.Network.Domain, func() {
					rootCleanup.guestEstablished(guest)
				})
			}); err != nil {
				return fmt.Errorf("HOLD: %s guest %s is not reachable after first boot: %w", module, guest.Name, err)
			}
			if err := installCredentialsForGuest(ctx, guestRunner, guest.Name, credentialBindings, secretValues); err != nil {
				return fmt.Errorf("install %s credentials: %w", guest.Name, err)
			}
			if module == "dns" {
				state := guestStates[guest.VMID]
				if needsInitialDNSConfiguration(state) {
					if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, variables, guest.Name, report, temporaryPrivateKey); err != nil {
						return fmt.Errorf("HOLD: configure DNS guest %s before dependent appliances: %w", guest.Name, err)
					}
				}
				if guest.Name == "lab-dns-01" && s.Gateway.Mode == model.GatewayModeManaged {
					needsRestart, err := installPowerDNSTSIG(ctx, guestRunner, guest.Address, dnsPlan, secretValues["firewall-ddns-tsig"])
					if err != nil {
						return fmt.Errorf("install PowerDNS TSIG state on %s: %w", guest.Name, err)
					}
					if !needsRestart {
						needsRestart, err = powerDNSTSIGSyncMarkerMissing(ctx, guestRunner, guest.Address)
						if err != nil {
							return fmt.Errorf("check PowerDNS TSIG synchronization on %s: %w", guest.Name, err)
						}
					}
					if needsRestart {
						if err := restartPowerDNSAfterTSIG(ctx, guestRunner, guest.Address); err != nil {
							return fmt.Errorf("restart PowerDNS after TSIG state change on %s: %w", guest.Name, err)
						}
					}
				}
				if err := report.timed("appliances", "readiness", guest.Name+"/dns", func() error {
					return verifyDNSReadiness(ctx, guestRunner, guest.Address)
				}); err != nil {
					return fmt.Errorf("HOLD: DNS guest %s did not pass runtime readiness before dependent appliances: %w", guest.Name, err)
				}
			}
		}
		if module == "dns" && s.Gateway.Mode == model.GatewayModeManaged && len(firewallPlan.Publications) > 0 {
			var upstream firewall.UpstreamObservation
			if err := report.timed("network", "ssh", "gateway-upstream", func() error {
				var observeErr error
				upstream, observeErr = observeGatewayUpstream(ctx, firewallRunner, firewallPlan)
				return observeErr
			}); err != nil {
				return fmt.Errorf("HOLD: published services require a safe current upstream DHCP lease: %w", err)
			}
			var finalFirewallPlan firewall.Plan
			var planErr error
			if airvpnMetadata == nil {
				finalFirewallPlan, planErr = firewall.PlanFromSiteWithUpstream(s, upstream)
			} else {
				finalFirewallPlan, planErr = firewall.PlanFromSiteWithUpstreamAndAirVPN(s, upstream, *airvpnMetadata)
			}
			if planErr != nil {
				return fmt.Errorf("HOLD: resolve published service policy from upstream lease: %w", planErr)
			}
			if airvpnMetadata != nil {
				if err := report.timed("network", "provider", "airvpn-endpoint", func() error {
					var bindErr error
					finalFirewallPlan, bindErr = firewall.BindAirVPNEndpoint(finalFirewallPlan, endpointLookup)
					return bindErr
				}); err != nil {
					return fmt.Errorf("HOLD: resolve AirVPN provider endpoint: %w", err)
				}
				airvpnMetadata = finalFirewallPlan.AirVPN
			}
			finalRuleset, renderErr := renderDeploymentNFTWithResolver(finalFirewallPlan, endpointLookup)
			if renderErr != nil {
				return fmt.Errorf("HOLD: render published service policy: %w", renderErr)
			}
			var finalVariables []byte
			var variablesErr error
			if airvpnMetadata == nil {
				finalVariables, variablesErr = ansible.VariablesWithOperatorKeyAndUpstream(s, upstream, durableOperatorPublicKey)
			} else {
				finalVariables, variablesErr = ansible.VariablesWithOperatorKeyAndUpstreamAndAirVPN(s, upstream, durableOperatorPublicKey, *airvpnMetadata)
			}
			if variablesErr != nil {
				return fmt.Errorf("HOLD: render published service Ansible variables: %w", variablesErr)
			}
			var finalVariableDocument map[string]any
			if err := json.Unmarshal(finalVariables, &finalVariableDocument); err != nil {
				return fmt.Errorf("HOLD: decode published service Ansible variables: %w", err)
			}
			runtimeVariables["firewall_plan"] = finalVariableDocument["firewall_plan"]
			runtimeVariables["firewall_interface_config_digests"] = finalVariableDocument["firewall_interface_config_digests"]
			runtimeVariables["firewall_ruleset"] = finalRuleset
			runtimeVariables["firewall_ruleset_sha256"] = firewall.RulesetDigest(finalRuleset)
			variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
			if err != nil {
				return fmt.Errorf("HOLD: encode published service Ansible variables: %w", err)
			}
			variables = append(variables, '\n')
			if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, variables, "lab-fw-01", report, temporaryPrivateKey); err != nil {
				return fmt.Errorf("HOLD: activate published services on managed gateway: %w", err)
			}
			if err := report.timed("network", "readiness", "lab-fw-01/gateway", func() error {
				return verifyGatewayReadiness(ctx, firewallRunner, "10.10.99.1")
			}); err != nil {
				return fmt.Errorf("HOLD: managed gateway did not pass publication readiness: %w", err)
			}
			firewallPlan = finalFirewallPlan
			// The final limited pass has already converged the firewall using the
			// observed upstream lease. Do not immediately run that same role
			// again in the all-host network phase.
			runtimeVariables["boetticher_skip_firewall"] = true
			variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
			if err != nil {
				return fmt.Errorf("HOLD: encode network-phase Ansible variables: %w", err)
			}
			variables = append(variables, '\n')
		}
	}
	for _, guest := range retainedGuests {
		module := strings.TrimPrefix(guest.Owner, "boetticher/module/")
		if err := proxmox.InactivateRetainedModule(ctx, rootRunner, s.BootstrapAddress, "root", guest.Kind, guest.VMID, module); err != nil {
			return fmt.Errorf("HOLD: inactivate retained %s guest %s through Proxmox: %w", module, guest.Name, err)
		}
	}
	report.complete()
	report.start("network", "Reconcile network and DNS")
	// The managed gateway and both DNS guests have passed their runtime
	// readiness checks above before this all-host bootstrap/network pass. That
	// foundation barrier makes independent host progress safe; the later
	// health phase remains the final live gate.
	if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, variables, "", ansible.PhaseBootstrap, report, temporaryPrivateKey); err != nil {
		return err
	}
	report.complete()
	report.start("services", "Configure services and runtime credentials")
	var loggingClientCertificates map[string]string
	var loggingCollectorCertificate string
	if modules.IsEnabled(s, "logging") {
		loggingClientCertificates, loggingCollectorCertificate, err = signLoggingCertificates(authority, s, csrDir)
		if err != nil {
			return fmt.Errorf("sign logging transport certificates: %w", err)
		}
	}
	if err := installModuleRuntimeConfigs(ctx, *siteDir, s, proxmoxPlan, temporaryPrivateKey); err != nil {
		return err
	}
	report.recordMutation("Services", "appliance runtime configuration", "reconciled", true)
	var monitorCertificate pki.ServerCertificate
	var bifrostCertificate pki.ServerCertificate
	var octoprintCertificate pki.ServerCertificate
	var arrCertificate pki.ServerCertificate
	var gatusCertificate pki.ServerCertificate
	var aiopsCertificates map[string]string
	if monitoringEnabled {
		monitorCSR, readErr := os.ReadFile(filepath.Join(csrDir, "monitor.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated monitor CSR: %w", readErr)
		}
		monitorCertificate, err = signOrReuseServerCertificate(authority, string(monitorCSR), csrDir, "monitor", "monitor", s.Network.Domain, []string{"lab-monitor-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign monitor endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "bifrost") {
		bifrostCSR, readErr := os.ReadFile(filepath.Join(csrDir, "bifrost.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated Bifrost CSR: %w", readErr)
		}
		bifrostCertificate, err = signOrReuseServerCertificate(authority, string(bifrostCSR), csrDir, "bifrost", "bifrost", s.Network.Domain, []string{"ai." + s.Network.Domain, "lab-bifrost-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign Bifrost endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "printer") {
		octoprintCSR, readErr := os.ReadFile(filepath.Join(csrDir, "octoprint.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated OctoPrint CSR: %w", readErr)
		}
		octoprintCertificate, err = signOrReuseServerCertificate(authority, string(octoprintCSR), csrDir, "octoprint", "octoprint", s.Network.Domain, []string{"printer." + s.Network.Domain, "lab-printer-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign OctoPrint endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "arr") {
		arrCSR, readErr := os.ReadFile(filepath.Join(csrDir, "arr.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated arr CSR: %w", readErr)
		}
		arrCertificate, err = signOrReuseServerCertificate(authority, string(arrCSR), csrDir, "arr", "sonarr", s.Network.Domain, []string{"radarr." + s.Network.Domain, "lab-arr-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign arr endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "aiops") {
		aiopsCertificates, err = signAIOpsCertificates(authority, s, csrDir)
		if err != nil {
			return fmt.Errorf("sign AIOps endpoint certificates: %w", err)
		}
	}
	if modules.IsEnabled(s, "gatus") {
		csr, readErr := os.ReadFile(filepath.Join(csrDir, "gatus.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated Gatus CSR: %w", readErr)
		}
		gatusCertificate, err = signOrReuseServerCertificate(authority, string(csr), csrDir, "gatus", "gatus", s.Network.Domain, []string{"lab-gatus-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign Gatus endpoint CSR: %w", err)
		}
	}
	runtimeVariables["pki_bootstrap_phase"] = false
	if monitoringEnabled {
		runtimeVariables["monitor_server_cert_pem"] = monitorCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "bifrost") {
		runtimeVariables["bifrost_server_cert_pem"] = bifrostCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "printer") {
		runtimeVariables["octoprint_server_cert_pem"] = octoprintCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "arr") {
		runtimeVariables["arr_server_cert_pem"] = arrCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "gatus") {
		runtimeVariables["gatus_server_cert_pem"] = gatusCertificate.ChainPEM
	}
	for name, certificate := range aiopsCertificates {
		runtimeVariables[name] = certificate
	}
	runtimeVariables["logging_client_certificates"] = loggingClientCertificates
	runtimeVariables["logging_collector_certificate"] = loggingCollectorCertificate
	variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	variables = append(variables, '\n')
	if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, variables, "", ansible.PhaseServices, report, temporaryPrivateKey); err != nil {
		return fmt.Errorf("install endpoint-signed certificates: %w", err)
	}
	report.complete()
	if err := saveDeployOperationPhase(*siteDir, &operationState, site.PhaseVerify, nil); err != nil {
		return fmt.Errorf("record deployment verify phase: %w", err)
	}
	report.start("health", "Run live health gates")
	var pulseForward *proxmox.SSHLocalForward
	var aiRouterForward *proxmox.SSHLocalForward
	defer func() {
		if pulseForward != nil {
			_ = pulseForward.Close()
		}
		if aiRouterForward != nil {
			_ = aiRouterForward.Close()
		}
	}()
	if monitoringEnabled {
		bastionRunner := proxmoxBastionSSHRunner(s, *siteDir)
		pulseRunner := bastionRunner
		pulseForward, err = pulseRunner.StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.10.20", 443)
		if err != nil {
			return fmt.Errorf("open Pulse API tunnel through Proxmox bastion: %w", err)
		}
		pulseBaseURL := "https://" + pulseForward.Address()
		clientCertificate, issueErr := pki.IssueClient(authority, "boetticher-reconciler", s.Network.Domain, time.Now().UTC())
		if issueErr != nil {
			return fmt.Errorf("issue runtime Pulse reconciliation certificate: %w", issueErr)
		}
		pulseAdmin, clientErr := pulse.NewAdminClient(pulse.ClientConfig{
			BaseURL: pulseBaseURL, AdminUser: "admin", AdminPassword: pulseAdminPassword,
			CAPEM: authority.IssuingCertPEM, ClientCertPEM: clientCertificate.CertPEM, ClientKeyPEM: clientCertificate.KeyPEM,
			ServerName: "monitor." + s.Network.Domain,
		})
		if clientErr != nil {
			return clientErr
		}
		if aiopsEnabled {
			aiRouterForward, err = bastionRunner.StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.20.60", 443)
			if err != nil {
				return fmt.Errorf("open AI Router canary tunnel through Proxmox bastion: %w", err)
			}
			if err := qualifyAndConfigureAIOps(ctx, *siteDir, *ageIdentity, s, authority, clientCertificate, pulseAdmin, pulseBaseURL, aiRouterForward.Address(), runtimeVariables, ansiblePlaybook, inventoryPath, report, temporaryPrivateKey); err != nil {
				return fmt.Errorf("HOLD: AIOps qualification failed: %w", err)
			}
		}
		if err := pulseAdmin.ConfigureProxmox(ctx, pulse.PVEConfig{
			Name: model.LogicalProxmoxIdentity, Host: "https://proxmox:8006",
			PreviousHost: "https://proxmox." + s.Network.Domain + ":8006",
			TokenID:      proxmox.PulseMonitoringUser + "!" + proxmox.PulseMonitoringToken, TokenSecret: pulseProxmoxToken,
			VerifySSL: true, MonitorVMs: true, MonitorContainers: true, MonitorStorage: true, MonitorBackups: true,
			MonitorPhysicalDisks: false, MonitorTemperatures: false,
		}); err != nil {
			return err
		}
		readToken, tokenErr := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token")
		if errors.Is(tokenErr, site.ErrPlatformSecretMissing) {
			readToken, tokenErr = pulseAdmin.CreateReadToken(ctx, "boetticher monitoring read")
			if tokenErr != nil {
				return tokenErr
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token", readToken); err != nil {
				return fmt.Errorf("store encrypted Pulse read token: %w", err)
			}
			report.recordMutation("Secrets", "pulse_api_token", "credential stored", true)
		} else if tokenErr != nil {
			return fmt.Errorf("load encrypted Pulse read token: %w", tokenErr)
		}
		pulseRead, clientErr := pulse.NewReadClient(pulse.ClientConfig{
			BaseURL: pulseBaseURL, APIToken: readToken,
			CAPEM:      authority.RootCertPEM,
			ServerName: "monitor." + s.Network.Domain,
		})
		if clientErr != nil {
			return clientErr
		}
		readTokenRefreshed := false
		refreshPulseReadToken := func() error {
			if readTokenRefreshed {
				return errors.New("Pulse read token was already refreshed during this deployment")
			}
			readToken, tokenErr = pulseAdmin.CreateReadToken(ctx, "boetticher monitoring read")
			if tokenErr != nil {
				return tokenErr
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token", readToken); err != nil {
				return fmt.Errorf("store encrypted Pulse read token: %w", err)
			}
			report.recordMutation("Secrets", "pulse_api_token", "credential refreshed", true)
			pulseRead, clientErr = pulse.NewReadClient(pulse.ClientConfig{
				BaseURL: pulseBaseURL, APIToken: readToken,
				CAPEM:      authority.RootCertPEM,
				ServerName: "monitor." + s.Network.Domain,
			})
			if clientErr != nil {
				return clientErr
			}
			readTokenRefreshed = true
			return nil
		}
		var health pulse.HealthStatus
		err = report.timed("health", "health", "pulse", func() error {
			var healthErr error
			health, healthErr = pulseRead.Health(ctx)
			return healthErr
		})
		if err != nil {
			return fmt.Errorf("verify Pulse health: %w", err)
		}
		if !strings.EqualFold(health.Status, "healthy") {
			return fmt.Errorf("verify Pulse health: unexpected status %q", health.Status)
		}
		if _, err := pulseRead.StateSummary(ctx); err != nil {
			if !pulse.IsUnauthorized(err) {
				return fmt.Errorf("verify Pulse state summary: %w", err)
			}
			if refreshErr := refreshPulseReadToken(); refreshErr != nil {
				return fmt.Errorf("refresh Pulse read token after unauthorized response: %w", refreshErr)
			}
			if _, retryErr := pulseRead.StateSummary(ctx); retryErr != nil {
				return fmt.Errorf("verify Pulse state summary after read-token refresh: %w", retryErr)
			}
		}
		if _, err := pulseRead.Resources(ctx); err != nil {
			if !pulse.IsUnauthorized(err) || readTokenRefreshed {
				return fmt.Errorf("verify Pulse resources: %w", err)
			}
			if refreshErr := refreshPulseReadToken(); refreshErr != nil {
				return fmt.Errorf("refresh Pulse read token after unauthorized response: %w", refreshErr)
			}
			if _, retryErr := pulseRead.Resources(ctx); retryErr != nil {
				return fmt.Errorf("verify Pulse resources after read-token refresh: %w", retryErr)
			}
		}

		agentBindings, bindingErr := monitoringAgentCredentialBindings(s)
		if bindingErr != nil {
			return bindingErr
		}
		if len(agentBindings) > 0 {
			agentToken, agentTokenErr := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_agent_token")
			if errors.Is(agentTokenErr, site.ErrPlatformSecretMissing) {
				agentToken, agentTokenErr = pulseAdmin.CreateAgentReportToken(ctx, "boetticher monitoring agent")
				if agentTokenErr != nil {
					return agentTokenErr
				}
				if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_agent_token", agentToken); err != nil {
					return fmt.Errorf("store encrypted Pulse agent token: %w", err)
				}
				report.recordMutation("Secrets", "pulse_agent_token", "credential stored", true)
			} else if agentTokenErr != nil {
				return fmt.Errorf("load encrypted Pulse agent token: %w", agentTokenErr)
			}

			for _, target := range ansible.MonitoringAgentTargets(s) {
				var agentRunner proxmox.CommandRunner
				if target == model.LogicalProxmoxIdentity {
					agentRunner = proxmox.SSHRunner{
						IdentityFile:  operatorIdentityFile(s),
						ConfigFile:    filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"),
						StrictHostKey: "yes", HostKeyAlias: model.LogicalProxmoxIdentity,
					}
				} else {
					agentRunner = applianceSSHRunnerWithIdentity(s, *siteDir, target, temporaryPrivateKey)
				}
				if err := installCredentialsForGuest(ctx, agentRunner, target, agentBindings, map[string]string{"pulse_agent_token": agentToken}); err != nil {
					return fmt.Errorf("install Pulse agent credential on %s: %w", target, err)
				}
			}
			agentDropIns, dropInErr := credentialDropIns(agentBindings)
			if dropInErr != nil {
				return dropInErr
			}
			existingDropIns, ok := runtimeVariables["credential_dropins"].(map[string]map[string]string)
			if !ok {
				existingDropIns = map[string]map[string]string{}
			}
			for guest, dropIns := range agentDropIns {
				if existingDropIns[guest] == nil {
					existingDropIns[guest] = map[string]string{}
				}
				for unit, content := range dropIns {
					existingDropIns[guest][unit] = content
				}
			}
			runtimeVariables["credential_dropins"] = existingDropIns
			runtimeVariables["pulse_agent_install_enabled"] = true
			agentVariables, marshalErr := json.MarshalIndent(runtimeVariables, "", "  ")
			if marshalErr != nil {
				return marshalErr
			}
			agentVariables = append(agentVariables, '\n')
			for _, target := range ansible.MonitoringAgentTargets(s) {
				if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, agentVariables, target, report, temporaryPrivateKey); err != nil {
					return fmt.Errorf("install Pulse agent on %s: %w", target, err)
				}
			}
		}

	}
	if pulseForward != nil {
		if err := pulseForward.Close(); err != nil {
			return fmt.Errorf("close Pulse API tunnel: %w", err)
		}
		pulseForward = nil
	}
	report.complete()
	report.start("persist", "Persist final state")
	backupChanged, err := proxmoxClient.ApplyBackupJobWithMutation(ctx, node, proxmox.BackupJob{
		JobName: backupPlan.JobName, ModelRevision: backupPlan.ModelRevision, StorageTarget: backupPlan.StorageTarget,
		Schedule: backupPlan.Schedule, VMIDList: backupPlan.VMIDList(), Retention: backupPlan.Retention,
	})
	if backupChanged {
		report.recordMutation("Proxmox", backupPlan.JobName, "backup job reconciled", true)
	}
	if err != nil {
		return err
	}
	if len(s.PendingDNSDeletions) > 0 {
		if err := site.SavePendingDNSDeletions(*siteDir, s, nil); err != nil {
			return fmt.Errorf("clear reconciled DNS deletion state: %w", err)
		}
		s.PendingDNSDeletions = nil
	}
	if err := report.timed("persist", "local", "projections", func() error {
		return writeModelProjectionsWithResolverAndAirVPN(*siteDir, s, endpointLookup, airvpnMetadata)
	}); err != nil {
		return err
	}
	report.recordMutation("Generated state", "site projections", "persisted", true)
	report.complete()
	return nil
}

const deploymentRootTimeout = 3 * time.Minute

func waitForDeploymentRoot(ctx context.Context, hostRunner proxmox.CommandRunner, hostAddress string, guestRunner proxmox.CommandRunner, guest proxmox.GuestPlan, publicKey, knownHosts, hostKeyAlias string, onAuthorityEstablished ...func()) error {
	if guest.Hostname == "" || hostKeyAlias == "" {
		return errors.New("guest host-key identity is incomplete")
	}
	markAuthorityEstablished := func() {
		if len(onAuthorityEstablished) > 0 && onAuthorityEstablished[0] != nil {
			onAuthorityEstablished[0]()
		}
	}
	rootCtx, cancel := context.WithTimeout(ctx, deploymentRootTimeout)
	defer cancel()
	var hostKey string
	var pinErr error
	for attempt := 0; attempt < 30; attempt++ {
		hostKey, pinErr = proxmox.ReadGuestHostKey(rootCtx, hostRunner, hostAddress, "root", guest.Kind, guest.VMID)
		if pinErr == nil {
			break
		}
		if attempt+1 < 30 {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-rootCtx.Done():
				timer.Stop()
				return fmt.Errorf("guest host-key pinning cancelled: %w", rootCtx.Err())
			case <-timer.C:
			}
		}
	}
	if pinErr != nil {
		return fmt.Errorf("HOLD: independently read guest host key through Proxmox: %w", pinErr)
	}
	if err := sshconfig.AddHostKey(knownHosts, hostKeyAlias, hostKey); err != nil {
		return fmt.Errorf("HOLD: pin guest host key: %w", err)
	}
	if err := proxmox.WaitForSSH(rootCtx, guestRunner, guest.Address, "root", 1, 0); err == nil {
		markAuthorityEstablished()
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-rootCtx.Done():
				timer.Stop()
				return fmt.Errorf("initial root transport failed and guest re-arm cancelled: %w", rootCtx.Err())
			case <-timer.C:
			}
		}
		if restoreErr := proxmox.RestoreTemporaryRootAccess(rootCtx, hostRunner, hostAddress, "root", guest.Kind, guest.VMID, publicKey); restoreErr != nil {
			lastErr = restoreErr
			continue
		}
		// Restoration itself establishes cleanup responsibility. The guest
		// probe may still fail, but the temporary key must be removed on the
		// outer failure path in that case too.
		markAuthorityEstablished()
		if retryErr := proxmox.WaitForSSH(rootCtx, guestRunner, guest.Address, "root", 30, 2*time.Second); retryErr == nil {
			return nil
		} else {
			lastErr = retryErr
		}
	}
	return fmt.Errorf("initial root transport failed after bounded guest re-arm attempts: %w", lastErr)
}

type interruptedDeploymentCleanup func(context.Context, string, model.Site, []proxmox.GuestPlan, string) error

// recoverInterruptedDeployment removes authority left by a controller crash.
// It runs before a new deploy operation is journaled and uses only the
// independent operator/root transport; no private temporary key is needed for
// this recovery because the host can remove the exact public-key line from
// each bounded guest.
func recoverInterruptedDeployment(ctx context.Context, siteDir string, s model.Site, out io.Writer) error {
	return recoverInterruptedDeploymentWith(ctx, siteDir, s, out, func(cleanupCtx context.Context, cleanupSiteDir string, cleanupSite model.Site, guests []proxmox.GuestPlan, publicKey string) error {
		return revokeTemporaryRootAccessForGuestsWithFallback(cleanupCtx, cleanupSite, cleanupSiteDir, guests, publicKey, true, proxmox.RevokeTemporaryRootAccess, proxmox.RevokeTemporaryRootAccessThroughHost)
	})
}

func recoverInterruptedDeploymentWith(ctx context.Context, siteDir string, s model.Site, out io.Writer, cleanup interruptedDeploymentCleanup) error {
	state, found, err := site.LoadOperationState(siteDir)
	if err != nil {
		return fmt.Errorf("HOLD: load interrupted deployment state: %w", err)
	}
	if !found {
		return nil
	}
	if state.TemporaryPublicKey == "" {
		if state.Phase != site.PhasePlan && state.Phase != site.PhaseFailed {
			return fmt.Errorf("HOLD: interrupted deployment phase %s has no recoverable temporary public key; use independent operator/root recovery before retrying", state.Phase)
		}
		if err := site.ClearOperationState(siteDir); err != nil {
			return fmt.Errorf("HOLD: clear interrupted pre-Apply journal: %w", err)
		}
		if out != nil {
			fmt.Fprintln(out, "Interrupted deployment cleanup: PASS no temporary Apply authority was armed")
		}
		return nil
	}
	if state.TemporaryHostAddress != s.BootstrapAddress {
		return fmt.Errorf("HOLD: interrupted deployment host address changed from %s to %s; use independent operator/root recovery before retrying", state.TemporaryHostAddress, s.BootstrapAddress)
	}
	if cleanup == nil {
		return errors.New("HOLD: interrupted deployment cleanup is not configured")
	}
	guests, err := operationGuestPlans(state.TemporaryCleanupGuests)
	if err != nil {
		return fmt.Errorf("HOLD: decode interrupted deployment cleanup targets: %w", err)
	}
	journalErr := saveDeployOperationPhase(siteDir, &state, site.PhaseCleanup, nil)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cleanupErr := cleanup(cleanupCtx, siteDir, s, guests, state.TemporaryPublicKey)
	cancel()
	if cleanupErr != nil {
		recoveryErr := fmt.Errorf("HOLD: interrupted deployment cleanup failed: %w", cleanupErr)
		if journalErr != nil {
			recoveryErr = errors.Join(recoveryErr, fmt.Errorf("record cleanup phase: %w", journalErr))
		}
		if failureJournalErr := saveDeployOperationPhase(siteDir, &state, site.PhaseFailed, cleanupErr); failureJournalErr != nil {
			recoveryErr = errors.Join(recoveryErr, fmt.Errorf("record cleanup failure: %w", failureJournalErr))
		}
		return recoveryErr
	}
	if journalErr != nil {
		return fmt.Errorf("HOLD: temporary Apply authority was removed but cleanup journal could not be recorded: %w", journalErr)
	}
	if err := site.ClearOperationState(siteDir); err != nil {
		return fmt.Errorf("HOLD: temporary Apply authority was removed but interrupted deployment journal could not be cleared: %w", err)
	}
	if out != nil {
		fmt.Fprintln(out, "Interrupted deployment cleanup: PASS temporary Apply authority removed")
	}
	return nil
}

func operationCleanupGuests(plan proxmox.Plan) ([]site.OperationGuest, error) {
	guests := make([]site.OperationGuest, 0, len(plan.Guests))
	for _, guest := range plan.Guests {
		if guest.Owner == "" {
			continue
		}
		if guest.Name == "" || guest.VMID <= 0 || guest.Address == "" {
			return nil, fmt.Errorf("guest %s has incomplete identity for temporary cleanup", guest.Name)
		}
		kind := string(guest.Kind)
		if kind != string(proxmox.KindQEMU) && kind != string(proxmox.KindLXC) {
			return nil, fmt.Errorf("guest %s has unsupported kind %q for temporary cleanup", guest.Name, kind)
		}
		guests = append(guests, site.OperationGuest{Name: guest.Name, Kind: kind, VMID: guest.VMID, Address: guest.Address})
	}
	return guests, nil
}

func operationGuestPlans(guests []site.OperationGuest) ([]proxmox.GuestPlan, error) {
	plans := make([]proxmox.GuestPlan, 0, len(guests))
	for _, guest := range guests {
		var kind proxmox.GuestKind
		switch guest.Kind {
		case string(proxmox.KindQEMU):
			kind = proxmox.KindQEMU
		case string(proxmox.KindLXC):
			kind = proxmox.KindLXC
		default:
			return nil, fmt.Errorf("unsupported temporary cleanup guest kind %q", guest.Kind)
		}
		plans = append(plans, proxmox.GuestPlan{Name: guest.Name, Kind: kind, VMID: guest.VMID, Address: guest.Address, Owner: "boetticher/recovery"})
	}
	return plans, nil
}

func artifactQualificationStatus(artifact model.Artifact) string {
	if artifact.Name == "" {
		return "no appliance artifact"
	}
	if artifact.ContentSHA256 == "" {
		return "FAIL (qualified content evidence absent)"
	}
	return "QUALIFIED content=" + artifact.ContentSHA256
}

// deploymentModuleNames returns the resolved module graph order carried by
// Site. The managed firewall is handled immediately above because dependent
// guests must not be created until its management leg and forwarding policy
// are ready.
func deploymentModuleNames(s model.Site) []string {
	result := make([]string, 0, len(s.Modules))
	for _, module := range s.Modules {
		if module.Enabled && module.Name != "firewall" {
			result = append(result, module.Name)
		}
	}
	return result
}

type deploymentGuestArtifactState struct {
	exists      bool
	replacement bool
}

// needsInitialDNSConfiguration keeps the dependency barrier for new or
// replaced DNS guests while avoiding a duplicate full role pass for an
// unchanged guest. The authoritative all-host network convergence still runs
// after appliance reconciliation and applies current desired state.
func needsInitialDNSConfiguration(state deploymentGuestArtifactState) bool {
	return !state.exists || state.replacement
}

func deploymentGuestPlans(s model.Site, plan proxmox.Plan) []proxmox.GuestPlan {
	seen := make(map[int]bool)
	guests := make([]proxmox.GuestPlan, 0, len(plan.Guests))
	for _, guest := range plan.Guests {
		if guest.Owner != "boetticher/module/firewall" {
			continue
		}
		seen[guest.VMID] = true
		guests = append(guests, guest)
	}
	for _, module := range deploymentModuleNames(s) {
		for _, guest := range plan.Guests {
			matches := guest.Owner == "boetticher/module/"+module
			if !matches || seen[guest.VMID] {
				continue
			}
			seen[guest.VMID] = true
			guests = append(guests, guest)
		}
	}
	return guests
}

func inspectDeploymentGuestStates(ctx context.Context, client *proxmox.Client, node string, guests []proxmox.GuestPlan) (map[int]deploymentGuestArtifactState, error) {
	if client == nil {
		return nil, errors.New("Proxmox client is required")
	}
	if node == "" {
		return nil, errors.New("Proxmox node is required")
	}
	if len(guests) == 0 {
		return map[int]deploymentGuestArtifactState{}, nil
	}
	type result struct {
		index       int
		exists      bool
		replacement bool
		err         error
	}
	jobs := make(chan int, len(guests))
	results := make(chan result, len(guests))
	for index := range guests {
		jobs <- index
	}
	close(jobs)
	workers := 4
	if len(guests) < workers {
		workers = len(guests)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for index := range jobs {
				exists, replacement, err := proxmox.InspectGuestArtifact(ctx, client, node, guests[index])
				results <- result{index: index, exists: exists, replacement: replacement, err: err}
			}
		}()
	}
	wait.Wait()
	close(results)
	ordered := make([]result, len(guests))
	for item := range results {
		ordered[item.index] = item
	}
	states := make(map[int]deploymentGuestArtifactState, len(guests))
	for _, item := range ordered {
		if item.err != nil {
			return nil, item.err
		}
		if _, duplicate := states[guests[item.index].VMID]; duplicate {
			return nil, fmt.Errorf("duplicate deployment guest VMID %d", guests[item.index].VMID)
		}
		states[guests[item.index].VMID] = deploymentGuestArtifactState{exists: item.exists, replacement: item.replacement}
	}
	return states, nil
}

func newTemporaryRootIdentity() ([]byte, string, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate temporary Apply identity: %w", err)
	}
	privateBlock, err := ssh.MarshalPrivateKey(private, "")
	for index := range private {
		private[index] = 0
	}
	if err != nil {
		return nil, "", fmt.Errorf("encode temporary Apply identity: %w", err)
	}
	privatePEM := pem.EncodeToMemory(privateBlock)
	if len(privatePEM) == 0 {
		return nil, "", errors.New("encode temporary Apply identity produced no private-key data")
	}
	wipePrivatePEM := func() {
		for index := range privatePEM {
			privatePEM[index] = 0
		}
	}
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		wipePrivatePEM()
		return nil, "", fmt.Errorf("encode temporary Apply public identity: %w", err)
	}
	publicLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))) + " boetticher-apply"
	if err := proxmox.ValidatePublicKey(publicLine); err != nil {
		wipePrivatePEM()
		return nil, "", fmt.Errorf("validate temporary Apply public identity: %w", err)
	}
	return privatePEM, publicLine, nil
}

func verifyGatewayReadiness(ctx context.Context, runner proxmox.CommandRunner, address string) error {
	if runner == nil {
		return errors.New("gateway readiness runner is required")
	}
	command := "set -eu; nft -c -f /etc/nftables.conf; test -n \"$(ip -4 -o addr show dev wan0 scope global)\"; ip -4 route show default dev wan0 | grep -Fq default; systemctl is-active nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq chrony; test \"$(sysctl -n net.ipv4.ip_forward)\" = 1"
	if _, err := runner.Run(ctx, address, "root", command); err != nil {
		return fmt.Errorf("gateway policy, DHCP, NTP, and forwarding checks failed: %w", err)
	}
	return nil
}

func observeGatewayUpstream(ctx context.Context, runner proxmox.CommandRunner, plan firewall.Plan) (firewall.UpstreamObservation, error) {
	if runner == nil {
		return firewall.UpstreamObservation{}, errors.New("gateway observation runner is required")
	}
	data, err := runner.Run(ctx, "10.10.99.1", "root", "/usr/lib/boetticher/inspect-firewall status")
	if err != nil {
		return firewall.UpstreamObservation{}, err
	}
	status, err := parseGatewayStatus(string(data))
	if err != nil {
		return firewall.UpstreamObservation{}, err
	}
	if err := firewall.ValidateUpstreamObservation(plan, status.Upstream); err != nil {
		return firewall.UpstreamObservation{}, err
	}
	return status.Upstream, nil
}

func verifyFirewallBootstrapNetwork(ctx context.Context, runner proxmox.CommandRunner) error {
	if runner == nil {
		return errors.New("firewall bootstrap network runner is required")
	}
	command := "set -eu; for interface in wan0 trusted0 servers0 sandbox0 mgmt0 transit0 infra0; do ip link show dev \"$interface\" >/dev/null; done; ip -4 -o addr show dev trusted0 | grep -Fq '10.10.30.1/24'; ip -4 -o addr show dev servers0 | grep -Fq '10.10.20.1/24'; ip -4 -o addr show dev sandbox0 | grep -Fq '10.10.40.1/24'; ip -4 -o addr show dev mgmt0 | grep -Fq '10.10.99.1/24'; ip -4 -o addr show dev transit0 | grep -Fq '10.10.5.1/24'; ip -4 -o addr show dev infra0 | grep -Fq '10.10.10.1/24'"
	if _, err := runner.Run(ctx, "10.10.99.1", "root", command); err != nil {
		return fmt.Errorf("role-named interfaces or static addresses are not ready: %w", err)
	}
	return nil
}

func verifyDNSReadiness(ctx context.Context, runner proxmox.CommandRunner, address string) error {
	if runner == nil {
		return errors.New("DNS readiness runner is required")
	}
	command := "set -eu; systemctl is-active pdns chrony blocky; test -s /etc/powerdns/pdns.conf; test -s /etc/blocky/config.yml; blocky version | grep -Fq '0.34.0'; blocky validate --config /etc/blocky/config.yml"
	if _, err := runner.Run(ctx, address, "root", command); err != nil {
		return fmt.Errorf("authoritative, NTP, and Blocky resolver checks failed: %w", err)
	}
	return nil
}

func signLoggingCertificates(authority pki.Authority, s model.Site, csrDir string) (map[string]string, string, error) {
	clients := map[string]string{}
	for _, component := range s.PlatformComponents() {
		if !component.Logging || component.Name == "lab-log-01" {
			continue
		}
		csr, err := os.ReadFile(filepath.Join(csrDir, "logging-"+component.Name+".csr.pem"))
		if err != nil {
			return nil, "", fmt.Errorf("read %s logging CSR: %w", component.Name, err)
		}
		certificate, err := signOrReuseEndpointClientCertificate(authority, string(csr), csrDir, "logging-"+component.Name, component.Name, s.Network.Domain)
		if err != nil {
			return nil, "", fmt.Errorf("sign %s logging CSR: %w", component.Name, err)
		}
		clients[component.Name] = certificate.ChainPEM
	}
	collectorCSR, err := os.ReadFile(filepath.Join(csrDir, "logging-collector.csr.pem"))
	if err != nil {
		return nil, "", fmt.Errorf("read logging collector CSR: %w", err)
	}
	collector, err := signOrReuseServerCertificate(authority, string(collectorCSR), csrDir, "logging-collector", "logs", s.Network.Domain, []string{"lab-log-01." + s.Network.Domain})
	if err != nil {
		return nil, "", fmt.Errorf("sign logging collector CSR: %w", err)
	}
	return clients, collector.ChainPEM, nil
}

func signAIOpsCertificates(authority pki.Authority, s model.Site, csrDir string) (map[string]string, error) {
	readCSR := func(name string) (string, error) {
		data, err := os.ReadFile(filepath.Join(csrDir, name+".csr.pem"))
		if err != nil {
			return "", fmt.Errorf("read %s CSR: %w", name, err)
		}
		return string(data), nil
	}
	serverRequests := []struct {
		file, identity, variable string
		aliases                  []string
	}{
		{"aiops", "aiops", "aiops_server_cert_pem", []string{"lab-aiops-01." + s.Network.Domain}},
		{"log-query", "log-query", "log_query_server_cert_pem", []string{"logs." + s.Network.Domain, "lab-log-01." + s.Network.Domain}},
	}
	result := make(map[string]string, 6)
	for _, request := range serverRequests {
		csr, err := readCSR(request.file)
		if err != nil {
			return nil, err
		}
		certificate, err := signOrReuseServerCertificate(authority, csr, csrDir, request.file, request.identity, s.Network.Domain, request.aliases)
		if err != nil {
			return nil, fmt.Errorf("sign %s CSR: %w", request.file, err)
		}
		result[request.variable] = certificate.ChainPEM
	}
	clientRequests := []struct{ file, identity, variable string }{
		{"pulse-read", "aiops-pulse-read", "aiops_pulse_read_cert_pem"},
		{"pulse-note", "aiops-pulse-note", "aiops_pulse_note_cert_pem"},
		{"log-query-client", "aiops-log-read", "aiops_log_read_cert_pem"},
		{"ai-router-client", "aiops-router-client", "aiops_router_client_cert_pem"},
	}
	for _, request := range clientRequests {
		csr, err := readCSR(request.file)
		if err != nil {
			return nil, err
		}
		certificate, err := signOrReuseServiceClientCertificate(authority, csr, csrDir, request.file, request.identity)
		if err != nil {
			return nil, fmt.Errorf("sign %s CSR: %w", request.file, err)
		}
		result[request.variable] = certificate.ChainPEM
	}
	return result, nil
}

func qualifyAndConfigureAIOps(ctx context.Context, siteDir, ageIdentity string, s model.Site, authority pki.Authority, controllerCertificate pki.ClientCertificate, pulseAdmin *pulse.Client, pulseBaseURL, routerForwardAddress string, runtimeVariables map[string]any, ansiblePlaybook, inventoryPath string, report *deploymentReport, identityData []byte) error {
	modelConfig, err := selectedAIOpsModel(s)
	if err != nil {
		return err
	}
	runner := applianceSSHRunnerWithIdentity(s, siteDir, "lab-bifrost-01", identityData)
	var metadata []byte
	err = report.timed("health", "health", "bifrost", func() error {
		var metadataErr error
		metadata, metadataErr = runner.RunArgs(ctx, "10.10.20.60", "root", []string{"/usr/local/libexec/boetticher-bifrost-model-capabilities", modelConfig.Alias})
		return metadataErr
	})
	if err != nil {
		return fmt.Errorf("read pinned Bifrost model metadata: %w", err)
	}
	if _, err := aiopsmodel.DecodeModelCapabilities(metadata); err != nil {
		return err
	}
	routerClient, err := controllerMTLSClient(authority, controllerCertificate, routerForwardAddress)
	if err != nil {
		return err
	}
	canaryContext, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := report.timed("health", "health", "aiops", func() error {
		return aiopsmodel.QualifyModelAlias(canaryContext, routerClient, "https://ai."+s.Network.Domain+"/v1/chat/completions", s.ModuleConfig["aiops"].ModelAlias)
	}); err != nil {
		return err
	}

	webhookSecret, created, err := loadOrCreateRandomSecret(siteDir, ageIdentity, s, "aiops_webhook_secret")
	if err != nil {
		return err
	}
	if created {
		report.recordMutation("Secrets", "aiops_webhook_secret", "credential stored", true)
	}
	readToken, created, err := loadOrCreatePulseToken(siteDir, ageIdentity, s, "aiops_pulse_read_token", func() (string, error) {
		return pulseAdmin.CreateReadToken(ctx, "boetticher aiops read")
	})
	if err != nil {
		return err
	}
	pulseRead, err := pulse.NewReadClient(pulse.ClientConfig{
		BaseURL: pulseBaseURL, APIToken: readToken,
		CAPEM:      authority.RootCertPEM,
		ServerName: "monitor." + s.Network.Domain,
	})
	if err != nil {
		return fmt.Errorf("configure AIOps Pulse read client: %w", err)
	}
	if _, err := pulseRead.StateSummary(ctx); err != nil {
		if !pulse.IsUnauthorized(err) {
			return fmt.Errorf("validate AIOps Pulse read token: %w", err)
		}
		readToken, err = pulseAdmin.CreateReadToken(ctx, "boetticher aiops read")
		if err != nil {
			return fmt.Errorf("refresh AIOps Pulse read token: %w", err)
		}
		if err := site.StorePlatformSecret(siteDir, s, ageIdentity, "aiops_pulse_read_token", readToken); err != nil {
			return fmt.Errorf("store refreshed AIOps Pulse read token: %w", err)
		}
		report.recordMutation("Secrets", "aiops_pulse_read_token", "credential refreshed", true)
		pulseRead, err = pulse.NewReadClient(pulse.ClientConfig{
			BaseURL: pulseBaseURL, APIToken: readToken,
			CAPEM:      authority.RootCertPEM,
			ServerName: "monitor." + s.Network.Domain,
		})
		if err != nil {
			return fmt.Errorf("reconfigure AIOps Pulse read client: %w", err)
		}
		if _, err := pulseRead.StateSummary(ctx); err != nil {
			return fmt.Errorf("validate refreshed AIOps Pulse read token: %w", err)
		}
	}
	if created {
		report.recordMutation("Secrets", "aiops_pulse_read_token", "credential stored", true)
	}
	noteToken, created, err := loadOrCreatePulseToken(siteDir, ageIdentity, s, "aiops_pulse_note_token", func() (string, error) {
		return pulseAdmin.CreateIncidentNoteToken(ctx, "boetticher aiops notes")
	})
	if err != nil {
		return err
	}
	if created {
		report.recordMutation("Secrets", "aiops_pulse_note_token", "credential stored", true)
	}
	if err := pulseAdmin.ConfigureAIOpsWebhook(ctx, "https://aiops."+s.Network.Domain+"/v1/pulse/events", webhookSecret, "10.10.20.90/32"); err != nil {
		return err
	}

	allBindings, err := deploymentCredentialBindings(s)
	if err != nil {
		return err
	}
	var bindings []deploymentCredential
	for _, binding := range allBindings {
		if binding.Guest == "lab-aiops-01" {
			bindings = append(bindings, binding)
		}
	}
	values := map[string]string{"aiops_webhook_secret": webhookSecret, "aiops_pulse_read_token": readToken, "aiops_pulse_note_token": noteToken}
	aiopsRunner := applianceSSHRunnerWithIdentity(s, siteDir, "lab-aiops-01", identityData)
	if err := installCredentialsForGuest(ctx, aiopsRunner, "lab-aiops-01", bindings, values); err != nil {
		return err
	}
	dropIns, err := credentialDropIns(bindings)
	if err != nil {
		return err
	}
	existing, _ := runtimeVariables["credential_dropins"].(map[string]map[string]string)
	if existing == nil {
		existing = map[string]map[string]string{}
	}
	existing["lab-aiops-01"] = dropIns["lab-aiops-01"]
	runtimeVariables["credential_dropins"] = existing
	runtimeVariables["aiops_runtime_credentials_ready"] = true
	runtimeVariables["aiops_model_alias_qualified"] = true
	variables, err := json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	return runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, append(variables, '\n'), "lab-aiops-01", ansible.PhaseHealth, report, identityData)
}

func selectedAIOpsModel(s model.Site) (model.BifrostModelConfig, error) {
	alias := s.ModuleConfig["aiops"].ModelAlias
	var selected model.BifrostModelConfig
	for _, candidate := range s.ModuleConfig["bifrost"].Models {
		if candidate.Alias != alias {
			continue
		}
		if selected.Alias != "" {
			return model.BifrostModelConfig{}, errors.New("AIOps model alias is ambiguous")
		}
		selected = candidate
	}
	if selected.Alias == "" {
		return model.BifrostModelConfig{}, errors.New("AIOps model alias is undeclared")
	}
	return selected, nil
}

func controllerMTLSClient(authority pki.Authority, certificate pki.ClientCertificate, forwardAddress string) (*http.Client, error) {
	identity, err := tls.X509KeyPair([]byte(certificate.ChainPEM), []byte(certificate.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load controller AIOps canary identity: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(authority.RootCertPEM + authority.IssuingCertPEM)) {
		return nil, errors.New("platform CA contains no certificates")
	}
	forwardHost, forwardPort, err := net.SplitHostPort(forwardAddress)
	if err != nil || forwardHost != "127.0.0.1" || forwardPort == "" {
		return nil, errors.New("AI Router canary requires a loopback SSH forward")
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(forwardHost, forwardPort))
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}}, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("AI Router redirects are forbidden") }}, nil
}

func loadOrCreateRandomSecret(siteDir, ageIdentity string, s model.Site, key string) (string, bool, error) {
	value, err := site.LoadPlatformSecret(siteDir, s, ageIdentity, key)
	if err == nil {
		return value, false, nil
	}
	if !errors.Is(err, site.ErrPlatformSecretMissing) {
		return "", false, fmt.Errorf("load encrypted %s: %w", key, err)
	}
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", false, fmt.Errorf("generate %s: %w", key, err)
	}
	value = base64.RawURLEncoding.EncodeToString(data[:])
	if err := site.StorePlatformSecret(siteDir, s, ageIdentity, key, value); err != nil {
		return "", false, fmt.Errorf("store encrypted %s: %w", key, err)
	}
	return value, true, nil
}

func loadOrCreatePulseToken(siteDir, ageIdentity string, s model.Site, key string, create func() (string, error)) (string, bool, error) {
	value, err := site.LoadPlatformSecret(siteDir, s, ageIdentity, key)
	if err == nil {
		return value, false, nil
	}
	if !errors.Is(err, site.ErrPlatformSecretMissing) {
		return "", false, fmt.Errorf("load encrypted %s: %w", key, err)
	}
	value, err = create()
	if err != nil {
		return "", false, err
	}
	if err := site.StorePlatformSecret(siteDir, s, ageIdentity, key, value); err != nil {
		return "", false, fmt.Errorf("store encrypted %s: %w", key, err)
	}
	return value, true, nil
}

// installModuleRuntimeConfigs is the deployment boundary for the common
// non-secret appliance contract. Module declarations remain the source of
// guest identity and runtime configuration; the SSH runner is only the Core
// transport used to install the already-validated document.
func installModuleRuntimeConfigs(ctx context.Context, siteDir string, s model.Site, plan proxmox.Plan, identityData []byte) error {
	declarations := make(map[string]model.ModuleDeclaration, len(s.Declarations))
	for _, declaration := range s.Declarations {
		declarations[declaration.Module] = declaration
	}
	resolvedGuests := make(map[string]proxmox.GuestPlan, len(plan.Guests))
	for _, guest := range plan.Guests {
		if guest.Owner != "" {
			resolvedGuests[guest.Name] = guest
		}
	}
	for _, guest := range s.PlatformComponents() {
		if guest.Module == "" {
			continue
		}
		resolvedGuest, ok := resolvedGuests[guest.Name]
		if !ok || resolvedGuest.Artifact.ContentSHA256 == "" {
			return fmt.Errorf("runtime artifact identity for %s: qualified artifact content checksum is missing", guest.Name)
		}
		if guest.Module == "" {
			runner := applianceSSHRunnerWithIdentity(s, siteDir, guest.Name, identityData)
			if err := appliance.InstallArtifactIdentity(ctx, runner, guest.Address, "root", resolvedGuest.Artifact); err != nil {
				return fmt.Errorf("install artifact identity for %s: %w", guest.Name, err)
			}
			continue
		}
		declaration, ok := declarations[guest.Module]
		if !ok {
			return fmt.Errorf("runtime configuration for %s: module declaration is missing", guest.Name)
		}
		resolvedDeclaration, resolveErr := resolvedDeclarationForGuest(declaration, resolvedGuest)
		if resolveErr != nil {
			return fmt.Errorf("runtime configuration for %s: %w", guest.Name, resolveErr)
		}
		config, err := appliance.RenderRuntimeConfig(s, guest, resolvedDeclaration)
		if err != nil {
			return fmt.Errorf("render runtime configuration for %s: %w", guest.Name, err)
		}
		runner := applianceSSHRunnerWithIdentity(s, siteDir, guest.Name, identityData)
		if err := appliance.InstallRuntimeConfig(ctx, runner, guest.Address, "root", config); err != nil {
			return fmt.Errorf("install runtime configuration for %s: %w", guest.Name, err)
		}
		if err := appliance.InstallArtifactIdentity(ctx, runner, guest.Address, "root", resolvedDeclaration.Artifact); err != nil {
			return fmt.Errorf("install artifact identity for %s: %w", guest.Name, err)
		}
	}
	return nil
}

// applianceSSHRunner selects the generated host alias so internal appliance
// connections use the same bastion/host-key policy as Ansible and operator
// SSH. Passing the guest address as the SSH target would bypass ProxyJump
// because the generated configuration is keyed by stable appliance identity.
func applianceSSHRunner(s model.Site, siteDir, hostAlias string) proxmox.SSHRunner {
	return proxmox.SSHRunner{
		IdentityFile:  operatorIdentityFile(s),
		ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     hostAlias,
	}
}

func applianceSSHRunnerWithIdentity(s model.Site, siteDir, hostAlias string, identityData []byte) proxmox.SSHRunner {
	runner := applianceSSHRunner(s, siteDir, hostAlias)
	if len(identityData) > 0 {
		runner = runner.WithIdentityData(identityData).FreshConnection()
	}
	return runner
}

type temporaryRootCleanup struct {
	s                 model.Site
	siteDir           string
	operatorPublicKey string
	identityData      []byte
	host              bool
	guests            []proxmox.GuestPlan
	guestNames        map[string]struct{}
}

func newTemporaryRootCleanup(s model.Site, siteDir, operatorPublicKey string, identityData ...[]byte) *temporaryRootCleanup {
	var keyData []byte
	if len(identityData) > 0 {
		keyData = identityData[0]
	}
	return &temporaryRootCleanup{s: s, siteDir: siteDir, operatorPublicKey: operatorPublicKey, identityData: keyData, guestNames: make(map[string]struct{})}
}

func (c *temporaryRootCleanup) hostEstablished() {
	c.host = true
}

func (c *temporaryRootCleanup) guestEstablished(guest proxmox.GuestPlan) {
	if _, ok := c.guestNames[guest.Name]; ok {
		return
	}
	c.guestNames[guest.Name] = struct{}{}
	c.guests = append(c.guests, guest)
}

func (c *temporaryRootCleanup) revoke(ctx context.Context) error {
	defer c.clearIdentityData()
	if !c.host && len(c.guests) == 0 {
		return nil
	}
	return revokeTemporaryRootAccessForGuestsWithFallback(ctx, c.s, c.siteDir, c.guests, c.operatorPublicKey, c.host, proxmox.RevokeTemporaryRootAccess, proxmox.RevokeTemporaryRootAccessThroughHost, c.identityData)
}

func (c *temporaryRootCleanup) clearIdentityData() {
	if c == nil {
		return
	}
	for index := range c.identityData {
		c.identityData[index] = 0
	}
	c.identityData = nil
}

type temporaryRootRevoker func(context.Context, proxmox.CommandRunner, string, string, string, bool) error
type temporaryRootGuestRevoker func(context.Context, proxmox.CommandRunner, string, string, proxmox.GuestKind, int, string) error

func revokeTemporaryRootAccessForGuestsWith(ctx context.Context, s model.Site, siteDir string, guests []proxmox.GuestPlan, operatorPublicKey string, host bool, revoke temporaryRootRevoker, identityData ...[]byte) error {
	return revokeTemporaryRootAccessForGuestsWithFallback(ctx, s, siteDir, guests, operatorPublicKey, host, revoke, nil, identityData...)
}

func revokeTemporaryRootAccessForGuestsWithFallback(ctx context.Context, s model.Site, siteDir string, guests []proxmox.GuestPlan, operatorPublicKey string, host bool, revoke temporaryRootRevoker, hostRevoke temporaryRootGuestRevoker, identityData ...[]byte) error {
	var guestIdentityData []byte
	if len(identityData) > 0 {
		guestIdentityData = identityData[0]
	}
	type target struct {
		name    string
		address string
		kind    proxmox.GuestKind
		vmid    int
		isHost  bool
		runner  proxmox.CommandRunner
	}
	targets := make([]target, 0, len(guests))
	for _, guest := range guests {
		if guest.Owner == "" || guest.Address == "" {
			continue
		}
		guestRunner := applianceSSHRunner(s, siteDir, guest.Name)
		if len(guestIdentityData) > 0 {
			guestRunner = guestRunner.WithIdentityData(guestIdentityData)
		}
		targets = append(targets, target{name: guest.Name, address: guest.Address, kind: guest.Kind, vmid: guest.VMID, runner: guestRunner})
	}
	if len(targets) == 0 && !host {
		return nil
	}

	// Cleanup is a security boundary, not a best-effort loop. An unreachable
	// guest must not prevent attempts against every other exact target,
	// especially the Proxmox host. Try direct guest cleanup concurrently, then
	// use the independent host recovery path for guests whose SSH is gone. The
	// host is revoked last so it remains available for those fallback attempts.
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for index, item := range targets {
		wg.Add(1)
		go func(index int, item target) {
			defer wg.Done()
			if err := revoke(ctx, item.runner, item.address, "root", operatorPublicKey, item.isHost); err != nil {
				if hostRevoke != nil && host {
					hostRunner := proxmoxRootSSHRunner(s, siteDir)
					if fallbackErr := hostRevoke(ctx, hostRunner, s.BootstrapAddress, "root", item.kind, item.vmid, operatorPublicKey); fallbackErr == nil {
						return
					} else {
						errs[index] = fmt.Errorf("revoke root access on %s: direct: %w; host fallback: %v", item.name, err, fallbackErr)
						return
					}
				}
				errs[index] = fmt.Errorf("revoke root access on %s: %w", item.name, err)
			}
		}(index, item)
	}
	wg.Wait()
	if host {
		if err := revoke(ctx, proxmoxRootSSHRunner(s, siteDir), s.BootstrapAddress, "root", operatorPublicKey, true); err != nil {
			errs = append(errs, fmt.Errorf("revoke root access on %s: %w", model.LogicalProxmoxIdentity, err))
		}
	}
	return errors.Join(errs...)
}

func retainedGuestPlans(s model.Site) ([]proxmox.GuestPlan, error) {
	guests := make([]proxmox.GuestPlan, 0)
	for _, retained := range s.RetainedModules {
		artifact, err := artifacts.ArtifactFor(retained.Module)
		if err != nil {
			return nil, fmt.Errorf("resolve retained %s artifact identity: %w", retained.Module, err)
		}
		var kind proxmox.GuestKind
		switch artifact.Kind {
		case string(proxmox.KindQEMU):
			kind = proxmox.KindQEMU
		case string(proxmox.KindLXC):
			kind = proxmox.KindLXC
		default:
			return nil, fmt.Errorf("retained %s has unsupported artifact kind %q", retained.Module, artifact.Kind)
		}
		for _, component := range retained.Guests {
			guests = append(guests, proxmox.GuestPlan{
				VMID: component.VMID, Name: component.Name, Hostname: component.Hostname, Kind: kind,
				Zone: component.Zone, Address: component.Address, Owner: "boetticher/module/" + retained.Module,
			})
		}
	}
	return guests, nil
}

func resolvedDeclarationForGuest(declaration model.ModuleDeclaration, guest proxmox.GuestPlan) (model.ModuleDeclaration, error) {
	if declaration.Module == "" || declaration.Module != strings.TrimPrefix(guest.Owner, "boetticher/module/") {
		return model.ModuleDeclaration{}, fmt.Errorf("module declaration ownership does not match guest %s", guest.Name)
	}
	if guest.Artifact.Name == "" || guest.Artifact.ContentSHA256 == "" || guest.Artifact.DefinitionSHA256 == "" {
		return model.ModuleDeclaration{}, fmt.Errorf("qualified artifact identity is incomplete")
	}
	declaration.Artifact = guest.Artifact
	return declaration, nil
}

func loadProxmoxClient(siteDir string, s model.Site, ageIdentity, caFile string, insecure bool) (*proxmox.Client, site.ProxmoxCredentials, error) {
	return loadProxmoxClientWithSnippetUser(siteDir, s, ageIdentity, caFile, insecure, model.DefaultAdminSSHUser)
}

func loadProxmoxClientWithSnippetUser(siteDir string, s model.Site, ageIdentity, caFile string, insecure bool, snippetUser string) (*proxmox.Client, site.ProxmoxCredentials, error) {
	if s.BootstrapAddress == "" {
		return nil, site.ProxmoxCredentials{}, errors.New("bootstrap endpoint is not configured")
	}
	if err := sshconfig.ValidateBootstrapAddress(s.BootstrapAddress); err != nil {
		return nil, site.ProxmoxCredentials{}, err
	}
	credentials, err := site.LoadProxmoxCredentials(siteDir, s, ageIdentity)
	if err != nil {
		return nil, site.ProxmoxCredentials{}, fmt.Errorf("load encrypted Proxmox API credentials: %w", err)
	}
	client, err := proxmox.NewClient(proxmox.Config{
		BaseURL: "https://" + s.BootstrapAddress + ":8006/api2/json", User: credentials.APIUser,
		TokenID: credentials.TokenID, TokenSecret: credentials.TokenSecret, CAFile: caFile, CAPEM: credentials.CAPEM, Insecure: insecure,
		SnippetRunner: proxmox.SSHRunner{
			IdentityFile:  operatorIdentityFile(s),
			ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
			KnownHosts:    deploymentKnownHosts(siteDir),
			StrictHostKey: "yes", HostKeyAlias: model.LogicalProxmoxIdentity,
		},
		SnippetAddress: s.BootstrapAddress, SnippetUser: snippetUser,
	})
	if err != nil {
		return nil, site.ProxmoxCredentials{}, err
	}
	return client, credentials, nil
}

func proxmoxRootSSHRunner(s model.Site, siteDir string) proxmox.SSHRunner {
	return proxmox.SSHRunner{
		IdentityFile:  operatorIdentityFile(s),
		ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     model.LogicalProxmoxIdentity,
	}
}

func proxmoxBastionSSHRunner(s model.Site, siteDir string) proxmox.SSHRunner {
	return proxmox.SSHRunner{
		IdentityFile:  operatorIdentityFile(s),
		ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     "lab-bastion",
	}
}

func deploymentKnownHosts(siteDir string) string {
	return filepath.Join(siteDir, "generated", "ssh", "known_hosts")
}

func saveDeployOperationPhase(siteDir string, state *site.OperationState, phase site.OperationPhase, cause error) error {
	if state == nil {
		return errors.New("deployment operation state is nil")
	}
	state.Phase = phase
	state.Error = ""
	if cause != nil {
		state.Error = compactError(cause)
	}
	state.UpdatedAt = ""
	return site.SaveOperationState(siteDir, *state)
}

func retireReplacedHostKey(siteDir string, s model.Site, guest proxmox.GuestPlan) error {
	if guest.Hostname == "" {
		return fmt.Errorf("guest %s has no host-key identity", guest.Name)
	}
	return sshconfig.RemoveHostKey(deploymentKnownHosts(siteDir), guest.Hostname+"."+s.Network.Domain)
}

func operatorIdentityFile(s model.Site) string {
	if identity := model.ExpandUserPath(s.SSHIdentityFile); identity != "" {
		return identity
	}
	publicKey := defaultOperatorPublicKey()
	if !strings.HasSuffix(publicKey, ".pub") {
		return ""
	}
	identity := strings.TrimSuffix(publicKey, ".pub")
	if _, err := os.Stat(identity); err != nil {
		return ""
	}
	return identity
}

func operatorPublicKeyForSite(s model.Site) (string, error) {
	identity := operatorIdentityFile(s)
	if identity == "" {
		return "", errors.New("durable operator SSH identity is not configured")
	}
	publicPath := identity + ".pub"
	publicData, err := os.ReadFile(publicPath)
	if err == nil {
		publicKey := strings.TrimSpace(string(publicData))
		if err := proxmox.ValidatePublicKey(publicKey); err != nil {
			return "", fmt.Errorf("validate durable operator public key: %w", err)
		}
		return publicKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read durable operator public key: %w", err)
	}
	privateData, err := os.ReadFile(identity)
	if err != nil {
		return "", fmt.Errorf("read durable operator identity: %w", err)
	}
	signer, parseErr := ssh.ParsePrivateKey(privateData)
	for index := range privateData {
		privateData[index] = 0
	}
	if parseErr != nil {
		return "", fmt.Errorf("derive durable operator public key: %w (provide %s)", parseErr, publicPath)
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := proxmox.ValidatePublicKey(publicKey); err != nil {
		return "", fmt.Errorf("validate derived durable operator public key: %w", err)
	}
	return publicKey, nil
}

func runTrackedAnsible(ctx context.Context, playbook, inventory string, variables []byte, limit string, report *deploymentReport, identityData []byte) error {
	return runTrackedAnsiblePhase(ctx, playbook, inventory, variables, limit, ansible.PhaseFull, report, identityData)
}

func runTrackedAnsiblePhase(ctx context.Context, playbook, inventory string, variables []byte, limit, phase string, report *deploymentReport, identityData []byte) error {
	started := time.Now()
	var (
		result ansible.RunResult
		err    error
	)
	if limit == "" {
		result, err = ansible.RunWithMutationPhase(ctx, playbook, inventory, variables, phase, identityData)
	} else {
		result, err = ansible.RunLimitedWithMutationPhase(ctx, playbook, inventory, variables, limit, phase, identityData)
	}
	if result.Changed {
		target := limit
		if target == "" {
			target = "all managed targets"
		}
		if report != nil {
			report.recordMutation("Services", target, "configuration reconciled", true)
		}
	}
	if report != nil {
		report.recordAnsibleTaskTimings(phase, result.TaskTimings)
		report.recordAnsibleTaskBatches(phase, result.TaskBatchTimings)
		for _, timing := range result.TaskTimings {
			for _, marker := range timing.Markers {
				fmt.Fprintf(report.out, "      Observation: %s (%s)\n", marker, timing.Host)
			}
		}
		target := limit
		if target == "" {
			target = "all managed targets"
		}
		report.recordTiming(report.activePhaseID(), "ansible", target, started)
	}
	return err
}
