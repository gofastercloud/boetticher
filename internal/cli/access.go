package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runAccess(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("access", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Bootstrap")
	if s.BootstrapAddress == "" {
		fmt.Fprintln(out, "  Proxmox       bootstrap endpoint not configured")
	} else {
		fmt.Fprintf(out, "  Proxmox       ssh proxmox\n                https://%s:8006\n", s.BootstrapAddress)
	}
	fmt.Fprintln(out, "Supported operator access")
	fmt.Fprintln(out, "  Platform      boetticher CLI and generated portal/status surfaces")
	fmt.Fprintln(out, "  Web           native product UI/API where provided")
	fmt.Fprintln(out, "  Break-glass   Proxmox console/exec for explicit recovery")
	if s.Gateway.Mode == model.GatewayModeManaged {
		fmt.Fprintln(out, "  Core SSH      internal controller transport only")
	} else {
		fmt.Fprintln(out, "  External      operator-managed appliance and recovery")
	}
	fmt.Fprintln(out, "Web")
	for _, m := range s.PlatformComponents() {
		if m.URL != "" {
			fmt.Fprintf(out, "  %-13s %s\n", m.Role, m.URL)
		}
	}
	fmt.Fprintln(out, "Logging\n  boetticher logs")
	fmt.Fprintln(out, "Access boundary")
	fmt.Fprintf(out, "Gateway\n  Mode        %s\n", s.Gateway.Mode)
	if s.Gateway.Mode == model.GatewayModeManaged {
		fmt.Fprintln(out, "  Core         routine SSH and hand mutation are unsupported")
		fmt.Fprintln(out, "  Firewall    managed through boetticher deploy")
		fmt.Fprintln(out, "  Engine      nftables")
	} else {
		fmt.Fprintln(out, "  External     configure and recover through the operator's appliance")
		fmt.Fprintln(out, "  Appliance   operator managed")
		fmt.Fprintln(out, "  Trunk       physical VLAN trunk")
	}
	if s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
		fmt.Fprintln(out, "  Physical lab  virtual-only")
	} else {
		fmt.Fprintf(out, "  Physical lab  %s attached\n", s.PhysicalNetwork.Trunk.Name)
	}
	fmt.Fprintln(out, "  Remote access not configured")
	return nil
}

func preferredAccessAlias(component model.Component) string {
	for _, alias := range component.DNSAliases {
		if strings.IndexFunc(alias, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
			return alias
		}
	}
	if len(component.DNSAliases) > 0 {
		return component.DNSAliases[0]
	}
	return component.Name
}
