package cli

import "strings"

// commandSpec is the single source for the public command menu printed by the
// CLI and published on the docs site.
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
	{Usage: "boetticher init [--site-dir DIR] [--age-identity PATH] [--root-age-identity PATH] [--external-firewall] [--storage-profile single-disk|dedicated-data-disk] [--storage-device /dev/disk/by-id/DEVICE]"},
	{Usage: "boetticher enroll [--site DIR] [--bootstrap-address ADDRESS] [--operator-key PATH] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--known-hosts PATH] [--proxmox-ca PATH] [--initial-user USER] [--insecure] [--trunk-interface IFACE] [--replace-scoped-credentials] [--dry-run]"},
	{Usage: "boetticher plan [--site DIR] [--live] [--json]"},
	{Usage: "boetticher deploy [--plan DIGEST] [--site DIR] [--age-identity PATH] [--only-module NAME] [--confirm]"},
	{Usage: "boetticher status [--site DIR] [--live] [--details] [--json]"},
	{Usage: "boetticher module list|configure|enable|disable NAME [--site DIR] [--confirm] [--json]"},
	{Usage: "boetticher network reservation|record add|remove|list [--site DIR]"},
	{Usage: "boetticher update [--bundle PATH] [--site DIR] [--dry-run] [--confirm]"},
	{Usage: "boetticher help --advanced"},
}

var advancedCommandSpecs = []commandSpec{
	{Usage: "boetticher bundle inspect|import PATH [--site DIR] [--json]"},
	{Usage: "boetticher recover storage ..."},
	{Usage: "boetticher companion add|setup|status|migrate ..."},
	{Usage: "boetticher tui [--site DIR] [--offline]"},
	{Usage: "boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]"},
	{Usage: "boetticher aiops status [--site DIR] [--live] [--json]"},
	{Usage: "boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]"},
	{Usage: "boetticher access [--site DIR]"},
	{Usage: "boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher network test [--site DIR] [--zones ZONE,...] [--capture] [--airvpn] [--cleanup-only] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]"},
	{Usage: "boetticher pki trust export [--site DIR] [--output PATH| -] [--format pem|apple] [--age-identity PATH]"},
	{Usage: "boetticher firewall status|show|diff|counters|logs|verify|rule add|list|remove [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N] [--source SOURCE] [--destination DESTINATION] [--vmid VMID] [--protocol PROTOCOL] [--ports PORTS] [--id ID] [--dry-run] [--confirm]"},
	{Usage: "boetticher dhcp status|leases [--site DIR] [--live] [--json]"},
	{Usage: "boetticher dhcp reservation add|list|remove [--site DIR] [--hostname NAME] [--address ADDRESS] [--mac MAC] [--vmid VMID] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]"},
	{Usage: "boetticher storage status|initialize|recover [--site DIR] [--live] [--storage-confirmed] [--reinitialize] [--reboot] [--allow-shared-usb-bridge-quirk] [--initial-user USER] [--known-hosts PATH]"},
	{Usage: "boetticher module list|configure|enable|disable NAME [--site DIR] [--dry-run] [--json] [--confirm] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher module secrets MODULE list|set|remove|rotate [--site DIR] [--age-identity PATH] [--confirm]"},
	{Usage: "boetticher config validate|show|schema [--site DIR]"},
}

// helpSpecs is keyed by the command path before -h/--help. Keeping nested
// paths explicit makes every help request useful without making command
// dispatch depend on a second parser or on a recursive help hint.
var helpSpecs = map[string]helpSpec{
	"tui": {
		Usage: "boetticher tui [--site DIR] [--offline]", Purpose: "Open the experimental interactive dashboard.", Arguments: "No positional arguments.", Options: "--site selects your private site directory; --offline skips live refresh and shows saved settings.", Safety: "The dashboard launches the same commands as the CLI, so changes still ask for their normal confirmation. Secrets are never command arguments. Use the direct CLI when you need zones, packet captures, JSON, or probe cleanup.", Examples: "boetticher tui --site ./my-boetticher", Related: "status --details, deploy, module, firewall, network test",
	},
	"init": {
		Usage: "boetticher init [--site-dir DIR] [--age-identity PATH] [--root-age-identity PATH] [--external-firewall] [--storage-profile single-disk|dedicated-data-disk] [--storage-device /dev/disk/by-id/DEVICE]", Purpose: "Create a site directory and the recovery material Boetticher needs.", Arguments: "No positional arguments.", Options: "--site-dir selects the site directory; --age-identity selects your routine private age identity; --root-age-identity selects a distinct root-recovery identity that must be kept offline; --external-firewall says that you run the gateway yourself; --storage-profile selects the fixed disk layout; --storage-device is required only for dedicated-data-disk and must be one stable by-id path.", Safety: "Creates local files only. It does not contact or change Proxmox or format the selected data disk.", Examples: "boetticher init --site-dir ./my-boetticher --storage-profile dedicated-data-disk --storage-device /dev/disk/by-id/ata-example-data", Related: "storage initialize, config validate, enroll",
	},
	"enroll": {
		Usage: "boetticher enroll [--site DIR] [--bootstrap-address ADDRESS] [--operator-key PATH] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--known-hosts PATH] [--proxmox-ca PATH] [--initial-user USER] [--insecure] [--trunk-interface IFACE] [--replace-scoped-credentials] [--dry-run]", Purpose: "Enroll the controller with the Proxmox host and prepare authenticated scoped access.", Arguments: "No positional arguments.", Options: "--bootstrap-address records the fresh Proxmox HOME-side address on first enrollment; --operator-key selects the public key whose matching private key reaches the fresh host; --known-hosts selects the independently verified address-key file; --proxmox-ca selects the Proxmox API CA; --initial-user, --insecure, --trunk-interface, and --replace-scoped-credentials are advanced enrollment controls; recovery and storage confirmations approve the independent recovery copy and selected data disk; --dry-run performs no remote mutation.", Safety: "This is the bounded setup operation. It does not build appliance images; normal deployment consumes a separately signed release bundle. Enrollment never arms deployment-only root authority.", Examples: "boetticher enroll --site ./my-boetticher --bootstrap-address 192.0.2.10 --operator-key ~/.ssh/id_ed25519.pub --known-hosts ~/.ssh/known_hosts --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem", Related: "init, bundle import, plan",
	},
	"plan": {
		Usage: "boetticher plan [--site DIR] [--live] [--json]", Purpose: "Render the exact desired deployment plan and its digest without applying it.", Arguments: "No positional arguments.", Options: "--live includes read-only observations from the target; --json emits the plan and digest for automation.", Safety: "Read-only. A live plan is the approval input for deploy and becomes stale if the observed target changes.", Examples: "boetticher plan --site ./my-boetticher --live --json", Related: "deploy, status, module configure",
	},
	"bundle": {
		Usage: "boetticher bundle inspect|import PATH [--site DIR] [--json]", Purpose: "Inspect or install a signed, release-built appliance bundle.", Arguments: "PATH is a local release bundle file.", Options: "inspect reads only the unsigned manifest for diagnostics; import verifies the signature, compatibility, every digest, and every declared file before activation.", Safety: "Import is local and atomic. A missing trust root, invalid signature, mismatched controller, or incomplete bundle is rejected before activation.", Examples: "boetticher bundle inspect ./boetticher-0.1.0.tar.gz; boetticher bundle import ./boetticher-0.1.0.tar.gz --site ./my-boetticher", Related: "update, plan, deploy",
	},
	"recover": {
		Usage: "boetticher recover storage ...", Purpose: "Run the explicitly guarded recovery operation for the known Boetticher-owned storage path.", Arguments: "The storage subcommand identifies the bounded recovery operation and its exact configured device.", Options: "Recovery-specific options are shown by the selected storage operation.", Safety: "Advanced and destructive where stated. Recovery proves ownership, requires explicit confirmation, and records cleanup failures.", Examples: "boetticher recover storage --help", Related: "status --details, deploy",
	},
	"companion": {
		Usage: "boetticher companion add|setup|status|migrate ...", Purpose: "Add and manage an external Boetticher Companion after the core lab is established.", Arguments: "add records the physical eth0 MAC; setup and status use its derived SERVERS address; migrate removes an exact legacy StreamDeck guest.", Options: "Companion desired state, platform deployment, and Pi provisioning remain separate operations.", Safety: "The Companion remains outside the Proxmox module and credential boundary. Adding it never deploys; setup reaches only its fixed reservation through the enrolled bastion.", Examples: "boetticher companion add --mac DC:A6:32:E9:DD:82 --confirm --site ./my-boetticher", Related: "deploy, companion setup, companion status",
	},
	"companion add": {
		Usage: "boetticher companion add --mac MAC [--site DIR] [--dry-run] [--confirm]", Purpose: "Record one external Companion and derive its fixed SERVERS reservation and bastion route.", Arguments: "No positional arguments.", Options: "--mac is the physical eth0 MAC; --dry-run previews the derived identity; --confirm saves desired state; --site selects the private site.", Safety: "Changes site.yml only. It never changes DHCP, Proxmox, SSH, or the Pi; attach the guarded physical trunk and run deploy separately before setup.", Examples: "boetticher companion add --mac DC:A6:32:E9:DD:82 --confirm --site ./my-boetticher", Related: "network trunk attach, deploy, companion setup, dhcp status",
	},
	"companion setup": {
		Usage: "boetticher companion setup [--site DIR] [--age-identity PATH] [--user USER] [--identity-file PATH] [--known-hosts PATH] [--host-key KEY] [--port PORT] [--confirm] [--dry-run]", Purpose: "Configure the fixed display, StreamDeck, and optional Pulse-agent capabilities on an added Raspberry Pi.", Arguments: "No positional arguments; the target is the fixed Companion SERVERS reservation.", Options: "--site selects the private site; --age-identity selects the operator-owned Age identity; --user, --identity-file, --known-hosts, --host-key, and --port define the strict SSH route; --dry-run validates without changes; --confirm authorizes remote mutation.", Safety: "Advanced and live. Setup connects through the enrolled Proxmox bastion, pins the Companion host key, and sends no Proxmox credentials to the Pi. The Pi receives only its configured capabilities and scoped credentials.", Examples: "boetticher companion setup --host-key 'ssh-ed25519 VERIFIED_HOST_KEY' --site ./my-boetticher --confirm", Related: "companion add, companion status, deploy",
	},
	"companion status": {
		Usage: "boetticher companion status [--site DIR] [--user USER] [--identity-file PATH] [--known-hosts PATH] [--port PORT] [--json]", Purpose: "Read Companion service status at its configured SERVERS reservation through the enrolled bastion.", Arguments: "No positional arguments.", Options: "--site selects the private site; --user, --identity-file, --known-hosts, and --port define the strict SSH route; --json emits machine-readable service status.", Safety: "Read-only. It requires the added Companion identity and enrolled host key and does not change the Companion, Proxmox, or site state.", Examples: "boetticher companion status --site ./my-boetticher --json", Related: "companion add, companion setup, status --details",
	},
	"companion migrate": {
		Usage: "boetticher companion migrate ADDRESS [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--confirm] [--dry-run]", Purpose: "Move an existing 0.4 StreamDeck installation out of Proxmox and into the companion capability.", Arguments: "ADDRESS is the configured Proxmox IPv4 address.", Options: "--site and --age-identity select local state; --proxmox-ca and --insecure select the authenticated API TLS policy; --dry-run previews local cleanup; --confirm authorizes exact remote removal.", Safety: "Advanced and destructive. It accepts only VMID 220 with the exact lab-streamdeck-01 name, hostname, and Boetticher ownership tags, removes only its USB-export manifest, and verifies the guest is absent. Unknown or mismatched guests stop the migration.", Examples: "boetticher companion migrate 192.0.2.10 --site ./my-boetticher --confirm", Related: "companion setup, bundle import, deploy",
	},
	"deploy": {
		Usage: "boetticher deploy [--plan DIGEST] [--site DIR] [--age-identity PATH] [--dry-run] [--only-module NAME] [--replace-firewall] [--recreate-legacy-lxcs] [--confirm]", Purpose: "Apply the authenticated release bundle to an exact live plan.", Arguments: "DIGEST is the immutable digest printed by boetticher plan --live. Interactive operators may omit it and approve the live plan when prompted; non-interactive runs must provide it.", Options: "--only-module limits appliance replacement and runtime configuration to one enabled optional module while leaving core/network state unchanged; --dry-run validates local state without connecting; --replace-firewall and --recreate-legacy-lxcs are advanced recovery actions and require --confirm.", Safety: "This is the only normal command that changes the platform. It requires a signed compatible release, rechecks live observations before mutation, journals apply/verify/cleanup/commit boundaries, and fails closed on cleanup errors.", Examples: "boetticher deploy --site ./my-boetticher; boetticher deploy --only-module gatus --plan sha256:... --site ./my-boetticher", Related: "bundle import, plan, status",
	},
	"status": {
		Usage: "boetticher status [--site DIR] [--ssh-config PATH] [--ssh-journey] [--live] [--details] [--json]", Purpose: "Show the consolidated read-only operational view.", Arguments: "No positional arguments.", Options: "--live adds read-only gateway, Smallstep CA, and leaf-certificate checks; --ssh-journey tests the configured bastion route; --ssh-config selects generated SSH settings; --details adds reasons and safe next actions; --json is for tools. Exit status is zero only for HEALTHY.", Safety: "Read-only. A broken connection or malformed response returns a non-zero result; it never repairs or changes infrastructure.", Examples: "boetticher status --site ./my-boetticher --details --live; boetticher status --site ./my-boetticher --details --live --json", Related: "deploy, plan, dhcp",
	},
	"update": {
		Usage: "boetticher update [--bundle PATH] [--site DIR] [--dry-run] [--confirm]", Purpose: "Import a signed release bundle or update compatible v3 site settings for platform 0.1.0 without deploying them.", Arguments: "PATH is the local signed release bundle when --bundle is supplied; otherwise there are no positional arguments.", Options: "--bundle imports an authenticated release bundle and cannot be combined with --dry-run or --confirm; --dry-run validates and prints the desired-state update without writing; --confirm saves the updated site and generated config.", Safety: "Update never deploys. Bundle import and desired-state writes are local and atomic; if refreshing generated config fails, the original site.yml stays in place.", Examples: "boetticher update --bundle ./boetticher-0.1.0.tar.gz --site ./my-boetticher; boetticher update --site ./my-boetticher --dry-run; boetticher update --site ./my-boetticher --confirm", Related: "bundle import, deploy, status, config validate",
	},
	"logs": {
		Usage: "boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]", Purpose: "Read a small journal view through the optional central collector and bastion.", Arguments: "HOST is a known Boetticher endpoint; omit it for the collector's own journal.", Options: "--site selects your site directory; --unit accepts a systemd unit such as blocky or blocky.service; --since accepts up to 168h; --priority selects a journal level; --limit is 1-500 and defaults to 100.", Safety: "Read-only. There is no follow mode, arbitrary journal path, or query language. Logs arrive asynchronously, so a service does not wait for logging to stay available.", Examples: "boetticher logs lab-dns-01 --site ./my-boetticher --unit blocky --since 1h; boetticher logs lab-fw-01 --priority warning --limit 100", Related: "status --details, module list",
	},
	"aiops": {
		Usage: "boetticher aiops status [--site DIR] [--live] [--json]", Purpose: "Show AIOps incident activity and usage.", Arguments: "status is the only operation.", Options: "--live reads the adapter through the normal bastion; --json is for tools.", Safety: "Read-only. It will not start an investigation, write a note, acknowledge an alert, restart anything, or remediate a service.", Examples: "boetticher aiops status --site ./my-boetticher --live", Related: "module list, status --details, logs",
	},
	"ssh-config": {
		Usage: "boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]", Purpose: "Create or check an SSH config that knows the bastion route.", Arguments: "No positional arguments.", Options: "--check checks an existing file; --output selects a file or -; --force permits replacing the generated file; --install-include adds the user SSH include.", Safety: "Writes only the file you select. Inspect the path before using --force.", Examples: "boetticher ssh-config --site ./my-boetticher --check", Related: "access, logs, status --details",
	},
	"access": {
		Usage: "boetticher access [--site DIR]", Purpose: "List the URLs and access routes for enabled platform services.", Arguments: "No positional arguments.", Options: "--site selects your site directory.", Safety: "Read-only and non-secret. Use the CLI, Proxmox, and service UIs for normal administration. If you run an external firewall, you manage it yourself. Logging lives behind boetticher logs, not a web UI.", Examples: "boetticher access --site ./my-boetticher", Related: "logs, ssh-config, status --details",
	},
	"network": {
		Usage: "boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]", Purpose: "Inspect or explicitly change the physical VLAN trunk, while staying virtual-only by default.", Arguments: "INTERFACE is required for attach and detach and must match the observed hardware.", Options: "--live queries Proxmox; --confirm approves a live trunk change; connection options select the certificate path.", Safety: "A physical trunk change can cut off management. Virtual-only sites leave spare NICs alone until you choose one.", Examples: "boetticher network trunk status --site ./my-boetticher --live", Related: "enroll, firewall, status --details",
	},
	"hardware": {
		Usage: "boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]", Purpose: "Inspect USB hardware and bind a module to a stable physical port.", Arguments: "status can filter MODULE REQUIREMENT; bind needs MODULE REQUIREMENT PORT; unbind needs MODULE REQUIREMENT.", Options: "--live reads parent USB identities from Proxmox; --confirm saves the binding and invokes deploy; connection options select the certificate path.", Safety: "Bindings use a physical port and known device identity, never a changing device path, VMID, or your workload.", Examples: "boetticher hardware usb bind printer serial 1-2.4 --confirm --site ./my-boetticher", Related: "module, deploy, status --details",
	},
	"pki": {
		Usage: "boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]", Purpose: "Create, export, or revoke browser and device client certificates.", Arguments: "NAME is a short client name; certificate-chain export has no client name.", Options: "--output selects an export path; --age-identity selects the independent recovery identity; --site selects local settings.", Safety: "Private keys are never printed to stdout. Certificate actions update local generated config only.", Examples: "boetticher pki client create operator --site ./my-boetticher", Related: "access, deploy, status --details",
	},
	"pki trust": {
		Usage: "boetticher pki trust export [--site DIR] [--output PATH| -] [--format pem|apple] [--age-identity PATH]", Purpose: "Export the public Boetticher trust chain or an Apple configuration profile.", Arguments: "No positional arguments.", Options: "--format selects PEM (the default) or an Apple trust profile; --output selects a file or - for stdout; --age-identity selects the independent recovery identity; --site selects local settings.", Safety: "Writes public certificates only. The private CA key never leaves the controller.", Examples: "boetticher pki trust export --site ./my-boetticher --format apple --output ./boetticher-trust.mobileconfig", Related: "pki client create, access",
	},
	"firewall": {
		Usage: "boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]", Purpose: "Look at the managed gateway rules, counters, and logs without changing them.", Arguments: "Subcommands select a read-only view; firewall logs can take a zone and limit.", Options: "--live queries the managed firewall; --json is for tools; show accepts --format human|nft; logs accepts --zone and --limit 1-1000.", Safety: "These views do not edit nftables, DHCP, or routes. If you use an external gateway, it stays yours to manage. Use the rule commands to add your workload exceptions.", Examples: "boetticher firewall diff --site ./my-boetticher --live", Related: "dhcp, network, logs, status --details",
	},
	"firewall rule add": {
		Usage: "boetticher firewall rule add [--source SOURCE] [--destination DESTINATION|--vmid VMID] [--protocol PROTOCOL] [--ports PORTS] [--id ID] [--site DIR] [--dry-run] [--confirm] [--json]", Purpose: "Add one precise firewall allowance for your workload.", Arguments: "--source and --protocol are required; choose exactly one of --destination and --vmid.", Options: "--dry-run previews the change; --confirm saves it; --age-identity, --proxmox-ca, and --insecure apply when looking up a VMID.", Safety: "Changes site.yml only; deploy applies it. Core destinations remain unavailable except one reserved SERVERS /32 to Pulse on TCP/443. Review the rule before confirming.", Examples: "boetticher firewall rule add --source TRUSTED --destination 10.10.20.61 --protocol tcp --ports 8080 --confirm --site ./my-boetticher; boetticher firewall rule add --source 10.10.20.50/32 --destination 10.10.10.20/32 --protocol tcp --ports 443 --id ufr-lab-display-pulse --confirm --site ./my-boetticher", Related: "firewall diff, deploy, dhcp reservation",
	},
	"firewall rule list": {
		Usage: "boetticher firewall rule list [--site DIR] [--json]", Purpose: "List user-workload firewall rules recorded in the site.", Arguments: "No positional arguments.", Options: "--json emits machine-readable rules; --site selects local state.", Safety: "Read-only. It does not change firewall policy or deploy anything.", Examples: "boetticher firewall rule list --site ./my-boetticher", Related: "firewall rule add, firewall rule remove",
	},
	"firewall rule remove": {
		Usage: "boetticher firewall rule remove --id ID [--site DIR] [--dry-run] [--confirm] [--json]", Purpose: "Remove a user-workload firewall rule from desired site configuration.", Arguments: "--id is required.", Options: "--dry-run previews the change; --confirm writes it; --json emits machine-readable output.", Safety: "Changes site.yml only and never deploys. Review the rule before confirming; deployment remains boetticher deploy.", Examples: "boetticher firewall rule remove --id ufr-example --confirm --site ./my-boetticher", Related: "firewall rule list, deploy",
	},
	"dhcp": {
		Usage: "boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]", Purpose: "Read DHCP leases or give one of your SERVERS guests a stable address.", Arguments: "status and leases inspect; reservation add, list, and remove manage SERVERS reservations.", Options: "--live queries the managed gateway; --mac and --vmid identify a reservation; --hostname and --address define one; --json is for tools; connection options apply when looking up a VMID.", Safety: "Reservation changes update site.yml only; deploy applies them. Your guests are never adopted or changed. External-firewall DHCP is yours to manage.", Examples: "boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher; boetticher dhcp leases --site ./my-boetticher --live", Related: "firewall, dns, status --details",
	},
	"dns": {
		Usage: "boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]", Purpose: "Manage your own private A and CNAME names.", Arguments: "add needs --name, --type, and --value; remove needs --name and --type; list has no required arguments.", Options: "--value is an IPv4 address for A or a private fully qualified domain name for CNAME; --json is for tools; --site selects saved settings.", Safety: "Changes site.yml only; deploy applies them. Platform, module, and DHCP names stay reserved, and the command is not a general PowerDNS console.", Examples: "boetticher dns record add --name app.lab.home.arpa --type CNAME --value app-01.servers.lab.home.arpa --site ./my-boetticher", Related: "dhcp, config validate, deploy",
	},
	"storage": {
		Usage: "boetticher storage status|initialize|recover [--site DIR] [--live] [--storage-confirmed] [--reinitialize] [--reboot] [--allow-shared-usb-bridge-quirk] [--initial-user USER] [--known-hosts PATH]", Purpose: "Inspect storage, prepare the dedicated data disk, or recover its USB transport.", Arguments: "status inspects; initialize prepares the configured dedicated-data profile; recover writes a Boetticher-owned GRUB UAS fallback for the configured device.", Options: "--live reads the Proxmox host; --storage-confirmed approves fixed-device setup or boot configuration recovery; --reinitialize permits replacement of an old unmounted, non-LVM layout on the exact configured device; --reboot schedules the controlled reboot needed after recover; --allow-shared-usb-bridge-quirk acknowledges a fallback that affects multiple identical USB bridges; --initial-user and --known-hosts select the SSH route.", Safety: "initialize can format the configured device. recover derives the USB bridge from the fixed stable device, writes only its own GRUB drop-in, validates generated GRUB, and refuses shared bridge IDs unless explicitly acknowledged. It never uses a transient disk path or changes storage contents. Modules cannot choose disks or create volume groups.", Examples: "boetticher storage initialize --site ./my-boetticher --storage-confirmed --reinitialize --known-hosts ~/.ssh/known_hosts; boetticher storage recover --site ./my-boetticher --storage-confirmed --reboot", Related: "enroll, deploy, status --details",
	},
	"module": {
		Usage: "boetticher module list|configure|enable|disable [NAME] [--site DIR] [--dry-run] [--json] [--confirm] [--purge] [--age-identity PATH]", Purpose: "List or configure Boetticher's built-in modules.", Arguments: "NAME is needed for configure, enable, and disable; list takes none. Use --purge only with disable.", Options: "--dry-run shows the result; --json emits a secret-free setup plan; --confirm approves configuration or lifecycle changes; configure accepts repeatable --set KEY=VALUE, --usb REQUIREMENT=PORT, and --secret NAME (value from stdin).", Safety: "Configure, enable, and disable update desired site state only; they never deploy. Run plan and deploy explicitly. DNS stays on and logging is optional. Disable keeps a module's guests and data unless you explicitly add --purge.", Examples: "boetticher module configure printer --site ./my-boetticher; boetticher module enable monitoring --confirm --site ./my-boetticher; boetticher plan --site ./my-boetticher --live", Related: "config validate, plan, deploy",
	},
	"module secrets": {
		Usage: "boetticher module secrets MODULE list|set|remove|rotate [--site DIR] [--age-identity PATH] [--confirm]", Purpose: "Manage the secrets a built-in module actually needs.", Arguments: "MODULE is a registered module; list, set, and remove choose the operation, with NAME needed for set and remove. AirVPN rotate needs no name.", Options: "--site selects your private site directory; --age-identity selects your independent age identity; --confirm is needed for removal and AirVPN profile rotation.", Safety: "Values come from a hidden prompt or stdin, never command arguments. They are never displayed, logged, or written to generated files. This updates encrypted site material only; deploy delivers a changed secret to a service.", Examples: "boetticher module secrets bifrost list --site ./my-boetticher; boetticher module secrets bifrost set openrouter_api_key --site ./my-boetticher; boetticher module secrets bifrost remove openrouter_api_key --confirm --site ./my-boetticher; boetticher module secrets airvpn rotate --confirm --site ./my-boetticher", Related: "module configure, deploy, config validate",
	},
	"module list": {
		Usage: "boetticher module list [--site DIR]", Purpose: "List the built-in modules and whether they are on.", Arguments: "No positional arguments.", Options: "--site selects your private site directory.", Safety: "Read-only. It does not change settings or deploy.", Examples: "boetticher module list --site ./my-boetticher", Related: "module configure, status --details",
	},
	"module configure": {
		Usage: "boetticher module configure MODULE [--site DIR] [--dry-run] [--json] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--confirm]", Purpose: "Configure one built-in module.", Arguments: "MODULE is a registered module.", Options: "The interactive workflow asks only for fields the module needs. --set provides repeatable typed values; --usb provides repeatable physical bindings; --secret names a secret read from a hidden prompt or stdin; --age-identity selects your independent age identity; --non-interactive suppresses prompts; --dry-run previews; --confirm saves the settings.", Safety: "Changes local settings only and never deploys. Secret values come from a prompt or stdin and are never command arguments or plan output.", Examples: "boetticher module configure printer --site ./my-boetticher; boetticher module configure aiops --non-interactive --enabled true --set model_alias=operations-investigator --confirm --site ./my-boetticher", Related: "module enable, deploy, module secrets",
	},
	"module enable": {
		Usage: "boetticher module enable NAME [--site DIR] [--dry-run] [--confirm] [--age-identity PATH]", Purpose: "Turn on one optional module in desired site state.", Arguments: "NAME is a registered optional module.", Options: "--dry-run shows the proposed state; --confirm saves the setting.", Safety: "This is local desired-state configuration only. It never deploys; review the plan and run deploy explicitly.", Examples: "boetticher module enable monitoring --confirm --site ./my-boetticher; boetticher plan --site ./my-boetticher --live", Related: "module configure, plan, deploy",
	},
	"module disable": {
		Usage: "boetticher module disable NAME [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH]", Purpose: "Turn off one optional module in desired site state.", Arguments: "NAME is a registered optional module.", Options: "--dry-run shows the proposed state; --confirm saves the setting; --purge records removal of the module's exact resources and requires confirmation at deploy.", Safety: "This is local desired-state configuration only. It never deploys. Disable keeps a module's guests and data by default; purge is exact and separately guarded.", Examples: "boetticher module disable printer --confirm --site ./my-boetticher; boetticher plan --site ./my-boetticher --live", Related: "module configure, plan, deploy",
	},
	"config": {
		Usage: "boetticher config validate|show|schema [--site DIR]", Purpose: "Check, display, or find the site configuration schema.", Arguments: "validate, show, and schema select the read-only operation.", Options: "--site selects your private site directory; schema does not need a site directory.", Safety: "Read-only. Unknown fields, invalid settings, and attempts to disable mandatory modules stop before the lab changes.", Examples: "boetticher config validate --site ./my-boetticher; boetticher config schema", Related: "module list, plan, deploy --dry-run",
	},
}

var nestedHelpSpecs = map[string]helpSpec{
	"aiops status":            helpSpecs["aiops"],
	"companion add":           helpSpecs["companion add"],
	"companion setup":         helpSpecs["companion setup"],
	"companion status":        helpSpecs["companion status"],
	"companion migrate":       helpSpecs["companion migrate"],
	"network trunk status":    helpSpecs["network"],
	"network trunk attach":    helpSpecs["network"],
	"network trunk detach":    helpSpecs["network"],
	"network test":            helpSpec{Usage: "boetticher network test [--site DIR] [--zones ZONE,...] [--capture] [--airvpn] [--cleanup-only] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]", Purpose: "Check routes, DNS, policy, mTLS, and speed from temporary probes in selected zones.", Arguments: "No positional arguments. By default it visits all six modeled zones.", Options: "--zones selects a comma-separated subset; --capture adds a short tcpdump from a probe; --airvpn also checks the declared ARR source through AirVPN; --cleanup-only removes a stale Boetticher probe; --json is for tools; connection options select the Proxmox certificate path.", Safety: "Advanced and live. It creates only recognised unprivileged LXC probes in VMIDs 910-919 and never changes firewall policy. --airvpn requires enabled ARR and AirVPN, stops and restarts only the declared AirVPN LXC to prove ARR has no direct escape, and restores it even after a failed check. It tries cleanup after every run; resolve a cleanup failure before retrying. It leaves your saved settings alone.", Examples: "boetticher network test --site ./my-boetticher; boetticher network test --airvpn --site ./my-boetticher", Related: "network trunk status, firewall diff, dhcp leases, status --details"},
	"hardware usb list":       helpSpecs["hardware"],
	"hardware usb status":     helpSpecs["hardware"],
	"hardware usb bind":       helpSpecs["hardware"],
	"hardware usb unbind":     helpSpecs["hardware"],
	"pki client create":       helpSpecs["pki"],
	"pki client export":       helpSpecs["pki"],
	"pki client revoke":       helpSpecs["pki"],
	"pki trust export":        helpSpecs["pki trust"],
	"firewall status":         helpSpecs["firewall"],
	"firewall show":           helpSpecs["firewall"],
	"firewall diff":           helpSpecs["firewall"],
	"firewall counters":       helpSpecs["firewall"],
	"firewall logs":           helpSpecs["firewall"],
	"firewall verify":         helpSpecs["firewall"],
	"firewall rule add":       helpSpecs["firewall rule add"],
	"firewall rule list":      helpSpecs["firewall rule list"],
	"firewall rule remove":    helpSpecs["firewall rule remove"],
	"dhcp status":             helpSpecs["dhcp"],
	"dhcp leases":             helpSpecs["dhcp"],
	"dhcp reservation add":    helpSpecs["dhcp"],
	"dhcp reservation list":   helpSpecs["dhcp"],
	"dhcp reservation remove": helpSpecs["dhcp"],
	"dns":                     helpSpecs["dns"],
	"dns record add":          helpSpecs["dns"],
	"dns record list":         helpSpecs["dns"],
	"dns record remove":       helpSpecs["dns"],
	"storage status":          helpSpecs["storage"],
	"storage initialize":      helpSpecs["storage"],
	"storage recover":         helpSpecs["storage"],
	"module list":             helpSpecs["module list"],
	"module configure":        helpSpecs["module configure"],
	"module enable":           helpSpecs["module enable"],
	"module disable":          helpSpecs["module disable"],
	"module secrets":          helpSpecs["module secrets"],
	"config validate":         helpSpecs["config"],
	"config show":             helpSpecs["config"],
	"config schema":           helpSpecs["config"],
}

// CommandReferenceMarkdown renders the browseable command menu from the same
// usage data as CLI help. It is a Jekyll page for the docs site and remains
// short enough to be useful instead of becoming another manual.
func CommandReferenceMarkdown() string {
	var document strings.Builder
	document.WriteString("---\nlayout: default\ntitle: Command reference\nsection: commands\ndescription: A generated menu of every public Boetticher command form.\n---\n\n")
	document.WriteString("# Command reference\n\n")
	document.WriteString("This page is generated from the same usage menu as `boetticher help`. Most days you will change the site, deploy the reviewed live plan, and check status. Add `--help` to any command for the friendly, full explanation.\n\n")
	document.WriteString("## The usual loop\n\n```text\nboetticher bundle import ./boetticher-0.1.0.tar.gz --site ./my-boetticher\nboetticher deploy --site ./my-boetticher\nboetticher status --site ./my-boetticher --details --live\n```\n\n")
	document.WriteString("## Normal command menu\n\n```text\n")
	for _, spec := range commandSpecs {
		document.WriteString(spec.Usage + "\n")
	}
	document.WriteString("```\n\n## Advanced command menu\n\n```text\n")
	for _, spec := range advancedCommandSpecs {
		document.WriteString(spec.Usage + "\n")
	}
	document.WriteString("```\n\n")
	document.WriteString("## Need a hand?\n\n")
	document.WriteString("```text\nboetticher help\nboetticher help --advanced\nboetticher deploy --help\nboetticher module configure --help\n```\n")
	return strings.TrimRight(document.String(), "\n") + "\n"
}
