package cli

import (
	"sort"
	"strings"
)

// commandSpec is the single source for the public top-level command reference
// printed by the CLI and checked against docs/commands.md.
type commandSpec struct {
	Usage string
}

type helpSpec struct {
	Usage     string
	Purpose   string
	Arguments string
	Options   string
	Safety    string
	Examples  string
	Related   string
}

var commandSpecs = []commandSpec{
	{Usage: "boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]"},
	{Usage: "boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]"},
	{Usage: "boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run]"},
	{Usage: "boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--confirm]"},
	{Usage: "boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]"},
	{Usage: "boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]"},
	{Usage: "boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]"},
	{Usage: "boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]"},
	{Usage: "boetticher access [--site DIR]"},
	{Usage: "boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]"},
	{Usage: "boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]"},
	{Usage: "boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]"},
	{Usage: "boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]"},
	{Usage: "boetticher dhcp status|leases [--site DIR] [--live] [--json]"},
	{Usage: "boetticher storage status|initialize [--site DIR] [--live] [--confirmed]"},
	{Usage: "boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher config validate|show|schema [--site DIR]"},
	{Usage: "boetticher portal build [--site DIR] [--output DIR] [--docs DIR]"},
}

// helpSpecs is keyed by the command path before -h/--help. Keeping nested
// paths explicit makes every help request useful without making command
// dispatch depend on a second parser or on a recursive help hint.
var helpSpecs = map[string]helpSpec{
	"init": {
		Usage: "boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]", Purpose: "Create a concise v3 site repository, SOPS/Age metadata, and recovery state.", Arguments: "No positional arguments.", Options: "--site-dir selects the site directory; --age-identity selects the external Age identity; --external-firewall selects the operator-owned gateway contract.", Safety: "Creates local site and recovery files; it does not mutate Proxmox.", Examples: "boetticher init --site-dir ./my-boetticher", Related: "config validate, preflight, bootstrap",
	},
	"preflight": {
		Usage: "boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]", Purpose: "Validate controller, Proxmox, hardware, configuration, and deployment safety prerequisites.", Arguments: "No positional arguments.", Options: "--live performs bounded target checks; --site selects the private site; bootstrap and SSH options identify the target.", Safety: "Read-only. Preflight performs no platform mutation.", Examples: "boetticher preflight --site ./my-boetticher --live", Related: "bootstrap, deploy --dry-run",
	},
	"bootstrap": {
		Usage: "boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run]", Purpose: "Prepare Proxmox trust, bridges, storage, the temporary Linux builder, and qualified appliance artifacts.", Arguments: "No positional arguments.", Options: "--dry-run renders only; --recovery-confirmed confirms the independent Age recovery copy; --storage-confirmed confirms explicit dedicated-storage initialization.", Safety: "May change Proxmox bootstrap infrastructure and creates a temporary builder. Review the plan and recovery prerequisites before applying.", Examples: "boetticher bootstrap --site ./my-boetticher --recovery-confirmed", Related: "preflight, deploy, verify",
	},
	"deploy": {
		Usage: "boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--confirm]", Purpose: "Make boetticher-owned platform resources match the complete resolved desired model.", Arguments: "No positional arguments.", Options: "--dry-run plans without mutation; --confirm authorizes destructive operations supported by the active providers, including replacement of an owned appliance rootfs when its declared persistent volumes can be retained; connection options select the Proxmox trust path.", Safety: "This is the sole public platform-application operation. Review the plan before applying it; unowned occupants, invalid persistent-volume identities, and unsupported replacement conditions remain HOLD.", Examples: "boetticher deploy --site ./my-boetticher --dry-run; boetticher deploy --site ./my-boetticher --confirm", Related: "preflight, verify, doctor",
	},
	"logs": {
		Usage: "boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]", Purpose: "Read a bounded journal view through the central collector using the normal Proxmox bastion path.", Arguments: "HOST is a known boetticher-managed or retained endpoint; omitted HOST reads the collector-local journal.", Options: "--site selects the private site repository; --unit accepts a bounded systemd unit name such as blocky or blocky.service; --since accepts a positive duration up to 168h; --priority accepts a fixed journal priority; --limit is 1-500 and defaults to 100.", Safety: "Read-only. Output is bounded; there is no follow mode, TUI, arbitrary journal path, or query language. Central logging is asynchronous and not an availability dependency.", Examples: "boetticher logs lab-dns-01 --site ./my-boetticher --unit blocky --since 1h; boetticher logs lab-fw-01 --priority warning --limit 100", Related: "doctor, verify",
	},
	"verify": {
		Usage: "boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]", Purpose: "Verify the resolved model, ownership, artifacts, declarations, and supported live evidence.", Arguments: "No positional arguments.", Options: "--ssh-journey runs a bounded authenticated bastion journey; --ssh-config selects the generated SSH configuration.", Safety: "Static checks are distinct from live evidence. Unsupported live checks remain NOT TESTED.", Examples: "boetticher verify --site ./my-boetticher", Related: "preflight, deploy, doctor",
	},
	"doctor": {
		Usage: "boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]", Purpose: "Diagnose current projections, module state, artifact evidence, ownership, and bounded live readiness.", Arguments: "No positional arguments.", Options: "--live performs bounded Proxmox and endpoint checks; connection options select the target trust path.", Safety: "Diagnostics do not repair infrastructure. Intentionally disabled modules are not reported unhealthy.", Examples: "boetticher doctor --site ./my-boetticher --live", Related: "logs, verify, deploy",
	},
	"upgrade": {
		Usage: "boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]", Purpose: "Run the guarded platform-version lifecycle gate.", Arguments: "No positional arguments.", Options: "--recovery-confirmed confirms an independent recovery copy; --site and --age-identity select local state.", Safety: "Upgrade is a guarded lifecycle operation and is distinct from deploy.", Examples: "boetticher upgrade --site ./my-boetticher --recovery-confirmed", Related: "preflight, deploy, verify",
	},
	"ssh-config": {
		Usage: "boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]", Purpose: "Render or validate the generated bastion-aware SSH configuration.", Arguments: "No positional arguments.", Options: "--check validates an existing file; --output selects a file or -; --force permits replacing the generated file; --install-include installs the user SSH include.", Safety: "Writes only the selected SSH projection; inspect paths before using --force.", Examples: "boetticher ssh-config --site ./my-boetticher --check", Related: "access, logs, verify",
	},
	"access": {
		Usage: "boetticher access [--site DIR]", Purpose: "List operator access paths for enabled platform capabilities.", Arguments: "No positional arguments.", Options: "--site selects the private site repository.", Safety: "Read-only and non-secret. Logging is accessed with boetticher logs; it has no web UI.", Examples: "boetticher access --site ./my-boetticher", Related: "logs, portal, ssh-config",
	},
	"bootstrap-endpoint": {
		Usage: "boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]", Purpose: "Inspect or record the HOME-side Proxmox bootstrap address.", Arguments: "set requires an IPv4 ADDRESS; show has no positional argument.", Options: "--site selects the private site repository.", Safety: "set changes local site configuration only; it does not connect or mutate Proxmox.", Examples: "boetticher bootstrap-endpoint set 192.0.2.73 --site ./my-boetticher", Related: "preflight, bootstrap",
	},
	"network": {
		Usage: "boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]", Purpose: "Inspect or explicitly change the physical trunk binding while preserving the virtual-only contract by default.", Arguments: "INTERFACE is required for attach and detach and must match observed hardware identity.", Options: "--live queries Proxmox; --confirm authorizes a live trunk change; connection options select the target trust path.", Safety: "Physical trunk changes can lock out management. Virtual-only sites do not claim spare NICs automatically.", Examples: "boetticher network trunk status --site ./my-boetticher --live", Related: "preflight, bootstrap, firewall",
	},
	"pki": {
		Usage: "boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]", Purpose: "Manage bounded client certificates from the controller-side PKI authority.", Arguments: "NAME is a validated client identity; trust export has no client NAME.", Options: "--output selects an export path; --age-identity selects the external recovery identity; --site selects local state.", Safety: "Private keys are never written to stdout and certificate actions update local generated state.", Examples: "boetticher pki client create operator --site ./my-boetticher", Related: "access, deploy, verify",
	},
	"firewall": {
		Usage: "boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]", Purpose: "Inspect the generated or live managed gateway policy and bounded evidence.", Arguments: "Subcommands select the read-only view; firewall logs may accept a zone and limit.", Options: "--live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.", Safety: "Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.", Examples: "boetticher firewall diff --site ./my-boetticher --live", Related: "dhcp, network, logs, verify",
	},
	"dhcp": {
		Usage: "boetticher dhcp status|leases [--site DIR] [--live] [--json]", Purpose: "Inspect generated DHCP/DDNS intent or read bounded managed-gateway lease evidence.", Arguments: "status and leases select the view.", Options: "--live queries the managed gateway; --json emits machine-readable output.", Safety: "Read-only. External-gateway DHCP remains outside boetticher management.", Examples: "boetticher dhcp leases --site ./my-boetticher --live", Related: "firewall, verify, logs",
	},
	"storage": {
		Usage: "boetticher storage status|initialize [--site DIR] [--live] [--confirmed]", Purpose: "Inspect the Core-owned storage substrate or perform its explicitly confirmed initialization.", Arguments: "status inspects; initialize prepares the configured dedicated data profile.", Options: "--live reads the Proxmox host; --confirmed authorizes fixed-device initialization.", Safety: "initialize can format the explicitly configured device. Modules cannot select disks or create VGs.", Examples: "boetticher storage status --site ./my-boetticher", Related: "bootstrap, deploy, doctor",
	},
	"module": {
		Usage: "boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]", Purpose: "Inspect or change first-party module intent through the shared deploy engine.", Arguments: "NAME is required for show, plan, enable, disable, and optional for status.", Options: "--dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.", Safety: "DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.", Examples: "boetticher module list --site ./my-boetticher; boetticher module disable monitoring --confirm --site ./my-boetticher", Related: "config validate, deploy, doctor",
	},
	"config": {
		Usage: "boetticher config validate|show|schema [--site DIR]", Purpose: "Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.", Arguments: "validate, show, and schema select the read-only operation.", Options: "--site selects the private site repository; schema does not require a site directory.", Safety: "Read-only. Unknown fields, invalid providers, and mandatory-module disable attempts fail before infrastructure mutation.", Examples: "boetticher config validate --site ./my-boetticher; boetticher config schema", Related: "preflight, module list, deploy --dry-run",
	},
	"portal": {
		Usage: "boetticher portal build [--site DIR] [--output DIR] [--docs DIR]", Purpose: "Build the passive, non-secret generated portal from the resolved model and evidence.", Arguments: "build is the only portal operation.", Options: "--output selects the generated portal directory; --docs selects product documentation.", Safety: "Writes generated static content only; it does not provide executable module content or expose secrets.", Examples: "boetticher portal build --site ./my-boetticher", Related: "access, verify, doctor",
	},
}

var nestedHelpSpecs = map[string]helpSpec{
	"portal build":            helpSpecs["portal"],
	"bootstrap-endpoint show": helpSpecs["bootstrap-endpoint"],
	"bootstrap-endpoint set":  helpSpecs["bootstrap-endpoint"],
	"network trunk status":    helpSpecs["network"],
	"network trunk attach":    helpSpecs["network"],
	"network trunk detach":    helpSpecs["network"],
	"pki client create":       helpSpecs["pki"],
	"pki client export":       helpSpecs["pki"],
	"pki client revoke":       helpSpecs["pki"],
	"pki trust export":        helpSpecs["pki"],
	"firewall status":         helpSpecs["firewall"],
	"firewall show":           helpSpecs["firewall"],
	"firewall diff":           helpSpecs["firewall"],
	"firewall counters":       helpSpecs["firewall"],
	"firewall logs":           helpSpecs["firewall"],
	"firewall verify":         helpSpecs["firewall"],
	"dhcp status":             helpSpecs["dhcp"],
	"dhcp leases":             helpSpecs["dhcp"],
	"storage status":          helpSpecs["storage"],
	"storage initialize":      helpSpecs["storage"],
	"module list":             helpSpecs["module"],
	"module show":             helpSpecs["module"],
	"module plan":             helpSpecs["module"],
	"module enable":           helpSpecs["module"],
	"module disable":          helpSpecs["module"],
	"module status":           helpSpecs["module"],
	"config validate":         helpSpecs["config"],
	"config show":             helpSpecs["config"],
	"config schema":           helpSpecs["config"],
}

// CommandReferenceMarkdown renders the public command reference from the same
// metadata used by CLI help. Keeping the generated document here prevents
// option descriptions and safety notes from drifting between the operator
// interface and the runbook.
func CommandReferenceMarkdown() string {
	var document strings.Builder
	document.WriteString("# Command reference\n\n")
	document.WriteString("This reference is generated from the CLI command metadata. `deploy` is the only public platform-application command; inspection and planning commands are read-oriented unless they explicitly request confirmation.\n\n")
	document.WriteString("## Usage\n\n```text\n")
	for _, spec := range commandSpecs {
		document.WriteString(spec.Usage + "\n")
	}
	document.WriteString("```\n\n")

	document.WriteString("## Command details\n\n")
	for _, spec := range commandSpecs {
		path := commandPath(spec.Usage)
		if detail, ok := helpSpecs[path]; ok {
			writeHelpMarkdown(&document, path, detail)
		}
	}

	paths := make([]string, 0, len(nestedHelpSpecs))
	for path := range nestedHelpSpecs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	document.WriteString("## Nested command details\n\n")
	for _, path := range paths {
		writeHelpMarkdown(&document, path, nestedHelpSpecs[path])
	}
	return strings.TrimRight(document.String(), "\n") + "\n"
}

func commandPath(usage string) string {
	fields := strings.Fields(usage)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

func writeHelpMarkdown(document *strings.Builder, path string, detail helpSpec) {
	document.WriteString("### " + path + "\n\n")
	document.WriteString("Purpose: " + detail.Purpose + "\n\n")
	document.WriteString("Usage: `" + detail.Usage + "`\n\n")
	document.WriteString("Arguments: " + detail.Arguments + "\n\n")
	document.WriteString("Options: " + detail.Options + "\n\n")
	document.WriteString("Safety: " + detail.Safety + "\n\n")
	document.WriteString("Examples: `" + strings.ReplaceAll(detail.Examples, "; ", "`; `") + "`\n\n")
	document.WriteString("Related commands: " + detail.Related + "\n\n")
}
