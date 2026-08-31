package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/usbexport"
)

// validateStaticDeploymentReadiness runs only checks whose inputs are local
// desired state, qualified artifacts, or encrypted controller state. It is
// deliberately independent of guests and firewall services created by deploy.
func validateStaticDeploymentReadiness(siteDir string, s model.Site, ageIdentity string, plan firewall.Plan, proxmoxPlan proxmox.Plan) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("desired state: %w", err)
	}
	if err := firewall.ValidateNetworkIntentCoverage(s, plan); err != nil {
		return fmt.Errorf("network contract: %w", err)
	}
	if _, err := usbexport.PlanFromSite(s); err != nil {
		return fmt.Errorf("device contract: %w", err)
	}
	if err := staticCredentialReadiness(siteDir, s, ageIdentity); err != nil {
		return err
	}
	if len(proxmoxPlan.Guests) == 0 {
		return errors.New("qualified Proxmox plan contains no platform guests")
	}
	return nil
}

// validateConfiguredModuleReadiness is the pre-bootstrap subset of static
// readiness. It deliberately does not require qualified artifact files: the
// bootstrap command is the operation that creates those artifacts. Deploy
// performs the stricter artifact-bound check above before any live mutation.
func validateConfiguredModuleReadiness(siteDir string, s model.Site, ageIdentity string) error {
	plan, err := firewall.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("firewall plan: %w", err)
	}
	if err := firewall.ValidateNetworkIntentCoverage(s, plan); err != nil {
		return fmt.Errorf("network contract: %w", err)
	}
	if _, err := usbexport.PlanFromSite(s); err != nil {
		return fmt.Errorf("device contract: %w", err)
	}
	return staticCredentialReadiness(siteDir, s, ageIdentity)
}

func staticCredentialReadiness(siteDir string, s model.Site, ageIdentity string) error {
	keys := make([]string, 0, 4)
	if s.Gateway.Mode == model.GatewayModeManaged {
		keys = append(keys, "ddns_tsig_secret")
	}
	if enabled := modulesEnabled(s, "monitoring"); enabled {
		keys = append(keys, "pulse_admin_password")
	}
	if modulesEnabled(s, "tailnet-router") && !hasRetainedModuleState(s.RetainedModules, "tailnet-router") {
		keys = append(keys, "tailscale_auth_key")
	}
	if modulesEnabled(s, "litellm") {
		for _, upstream := range s.ModuleConfig["litellm"].Upstreams {
			keys = append(keys, upstream.APIKeySecret)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	presence, err := site.PlatformSecretPresence(siteDir, s, ageIdentity, keys)
	if err != nil {
		return fmt.Errorf("inspect encrypted credentials before mutation: %w", err)
	}
	missing := make([]string, 0)
	for _, key := range keys {
		if !presence[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required encrypted credential(s) are missing: %s; provide them with boetticher module secrets before deploy", strings.Join(missing, ", "))
	}
	return nil
}

func modulesEnabled(s model.Site, name string) bool {
	for _, module := range s.Modules {
		if module.Name == name {
			return module.Enabled
		}
	}
	return false
}

// validateLiveDeploymentPrerequisites is deliberately limited to infrastructure
// that exists before this deployment. It must never probe a firewall rule,
// appliance DNS service, or module service that this invocation is about to
// create; those remain post-deployment health gates.
func validateLiveDeploymentPrerequisites(ctx context.Context, client *proxmox.Client, rootRunner proxmox.CommandRunner, siteDir string, s model.Site, plan proxmox.Plan, storagePlan storage.Plan) error {
	return validateLiveDeploymentPrerequisitesWithResolver(ctx, client, rootRunner, siteDir, s, plan, storagePlan, net.LookupIP)
}

func validateLiveDeploymentPrerequisitesWithResolver(ctx context.Context, client *proxmox.Client, rootRunner proxmox.CommandRunner, siteDir string, s model.Site, plan proxmox.Plan, storagePlan storage.Plan, endpointLookup func(string) ([]net.IP, error)) error {
	if client == nil || rootRunner == nil {
		return errors.New("live deployment preflight requires the authenticated Proxmox and bootstrap paths")
	}
	if endpointLookup == nil {
		endpointLookup = net.LookupIP
	}
	statuses, err := client.NodeStorage(ctx, plan.Node)
	if err != nil {
		return fmt.Errorf("inspect existing Proxmox storage: %w", err)
	}
	if _, err := expectedStorageStatus(statuses, storagePlan); err != nil {
		return fmt.Errorf("required existing storage is unavailable: %w", err)
	}

	for _, guest := range plan.Guests {
		for _, device := range guest.Security.Devices {
			if !strings.HasPrefix(device.Path, "/dev/") || strings.ContainsAny(device.Path, "\r\n") {
				return fmt.Errorf("module guest %s declares an unsafe host device path %q", guest.Name, device.Path)
			}
			if _, err := rootRunner.Run(ctx, s.BootstrapAddress, "root", "test -c "+shellQuote(device.Path)); err != nil {
				return fmt.Errorf("required host device %s for %s is unavailable: %w", device.Path, guest.Name, err)
			}
		}
	}
	usbManifests, err := usbexport.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("resolve live USB requirements: %w", err)
	}
	needsUSBObservation := false
	for _, manifest := range usbManifests {
		needsUSBObservation = needsUSBObservation || len(manifest.Exports) > 0
	}
	if needsUSBObservation {
		observed, observeErr := observeUSB(ctx, s, siteDir)
		if observeErr != nil {
			return fmt.Errorf("inspect required USB devices: %w", observeErr)
		}
		devices, parseErr := parseConfigureUSBObservation(observed)
		if parseErr != nil {
			return fmt.Errorf("parse required USB device evidence: %w", parseErr)
		}
		if err := validateLiveUSBBindings(usbManifests, devices); err != nil {
			return err
		}
	}

	return validateExternalEndpointReadiness(s, endpointLookup)
}

func validateExternalEndpointReadiness(s model.Site, endpointLookup func(string) ([]net.IP, error)) error {
	if endpointLookup == nil {
		endpointLookup = net.LookupIP
	}
	for _, declaration := range s.Declarations {
		for _, intent := range declaration.NetworkIntents {
			if intent.Endpoint == "" {
				continue
			}
			parsed, parseErr := url.Parse(intent.Endpoint)
			if parseErr != nil || parsed.Hostname() == "" {
				return fmt.Errorf("module %s external endpoint %q is invalid", declaration.Module, intent.Endpoint)
			}
			if parsed.Hostname() == s.Network.Domain || strings.HasSuffix(parsed.Hostname(), "."+s.Network.Domain) {
				// This service name is owned by this deployment. DNS and
				// reachability remain post-deployment health gates.
				continue
			}
			if _, lookupErr := endpointLookup(parsed.Hostname()); lookupErr != nil {
				return fmt.Errorf("module %s external endpoint DNS lookup failed for %s: %w", declaration.Module, parsed.Hostname(), lookupErr)
			}
		}
	}
	return nil
}

func validateLiveUSBBindings(manifests []usbexport.GuestManifest, observed []configureUSBDevice) error {
	for _, manifest := range manifests {
		for _, export := range manifest.Exports {
			found := false
			for _, device := range observed {
				if device.Port != export.Port {
					continue
				}
				found = true
				if device.VendorID != export.VendorID || device.ProductID != export.ProductID {
					return fmt.Errorf("required USB %s/%s at %s has identity %s:%s, expected %s:%s", export.Module, export.Requirement, export.Port, device.VendorID, device.ProductID, export.VendorID, export.ProductID)
				}
				if export.Serial != "" && device.Serial != export.Serial {
					return fmt.Errorf("required USB %s/%s at %s has a different serial identity", export.Module, export.Requirement, export.Port)
				}
				break
			}
			if !found {
				return fmt.Errorf("required USB %s/%s is unavailable at configured port %s", export.Module, export.Requirement, export.Port)
			}
		}
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
