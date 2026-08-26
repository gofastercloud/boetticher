package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runProvision(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	debianTemplate := fs.String("debian-template", "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", "Proxmox Debian LXC template")
	dryRun := fs.Bool("dry-run", false, "render and validate the provisioning plan without connecting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(out, "Proxmox provisioning plan: PASS model %s (%d guests)\n", plan.ModelRevision, len(plan.Guests))
		firewallAction := "not created (external gateway mode)"
		if s.Gateway.Mode == model.GatewayModeManaged {
			firewallAction = "provisioned by bootstrap"
		}
		fmt.Fprintf(out, "  Storage target: %s\n  Firewall VM: %s\n  Debian template: %s\n", plan.Storage, firewallAction, *debianTemplate)
		return nil
	}
	client, credentials, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
	if err != nil {
		return err
	}
	if err := proxmox.Provision(context.Background(), client, plan, *debianTemplate); err != nil {
		return err
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "Proxmox provisioning: PASS model %s via %s\n", plan.ModelRevision, credentials.APIUser)
	return nil
}
