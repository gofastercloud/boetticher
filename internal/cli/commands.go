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
	{Usage: "boetticher controller bootstrap|status|reboot [--operator USER] [--confirm-key-login] [--yes]"},
	{Usage: "boetticher host create-identity|show-public-key|import-host-key|enroll|apply|status|plan-storage|teardown|reboot ..."},
	{Usage: "boetticher module <capability> <action> [flags]"},
}

var advancedCommandSpecs = []commandSpec{
	{Usage: "boetticher host status --details"},
	{Usage: "boetticher host plan-storage"},
	{Usage: "boetticher module <capability> <action> [--yes] [--details] [--verbose]"},
}

// helpSpecs is keyed by the command path before -h/--help. Keeping nested
// paths explicit makes every help request useful without making command
// dispatch depend on a second parser or on a recursive help hint.
var helpSpecs = map[string]helpSpec{
	"controller": {
		Usage: "boetticher controller bootstrap|status|reboot [--operator USER] [--confirm-key-login] [--yes]", Purpose: "Bootstrap, inspect, or explicitly reboot the local Controller.", Arguments: "bootstrap configures locally; status reads local readiness; reboot requires --yes and never contacts Proxmox.", Options: "--operator selects the existing local operator account; bootstrap requires --confirm-key-login; reboot requires --yes.", Safety: "Bootstrap and status are local. Controller reboot is explicit and does not reboot the Host.", Examples: "boetticher controller bootstrap --operator pi --confirm-key-login; boetticher controller status; boetticher controller reboot --yes", Related: "host",
	},
	"controller bootstrap": {
		Usage: "boetticher controller bootstrap [--operator USER] [--confirm-key-login]", Purpose: "Configure the local Controller and run final local readiness checks.", Arguments: "No positional arguments.", Options: "--operator selects the existing local operator account; --confirm-key-login confirms that a fresh public-key SSH session was tested.", Safety: "Local-only and retryable. It does not enroll or deploy the Host. A reboot is never automatic; repeat bootstrap after reconnecting.", Examples: "boetticher controller bootstrap --operator pi --confirm-key-login", Related: "controller status",
	},
	"controller status": {
		Usage: "boetticher controller status [--operator USER]", Purpose: "Read local controller readiness without repairing or contacting Proxmox.", Arguments: "No positional arguments.", Options: "--operator selects the local account whose effective SSH policy is checked.", Safety: "Read-only. It does not install packages, run Ansible, change LEDs, load a site, or contact a remote system.", Examples: "boetticher controller status", Related: "controller bootstrap",
	},
	"controller reboot": {
		Usage: "boetticher controller reboot --yes", Purpose: "Reboot the local Controller for an approved persistence rehearsal.", Arguments: "No positional arguments.", Options: "--yes is required.", Safety: "Reboots only the local Controller; the Host and its guests are not contacted.", Examples: "boetticher controller reboot --yes", Related: "controller status, host status",
	},
	"host": {
		Usage: "boetticher host create-identity|show-public-key|import-host-key|enroll|apply|status|plan-storage|teardown|reboot ...", Purpose: "Bind, configure, inspect, rebuild, or reboot the single supported Proxmox Host.", Arguments: "create-identity and show-public-key manage the persistent Controller identity; import-host-key records the independently verified Host key; enroll binds the Host; apply owns the Host baseline, storage, and virtual network; status is read-only; teardown removes exact Boetticher-owned Host configuration; reboot requires --yes.", Options: "import-host-key takes --address and --key; apply takes --data-disk, --adopt-existing-network, and --yes; status accepts --details.", Safety: "Trust is never accepted automatically. Host apply stops at missing enrollment, destructive storage, or ambiguous network adoption. It never deploys Modules or changes the protected HOME path.", Examples: "boetticher host create-identity; boetticher host show-public-key; boetticher host import-host-key --address 192.0.2.10 --key 'ssh-ed25519 VERIFIED_KEY'; boetticher host enroll root@192.0.2.10; boetticher host apply --data-disk /dev/disk/by-id/DEVICE --yes; boetticher host status --details", Related: "controller status, module",
	},
	"module firewall": {
		Usage: "boetticher module firewall plan|apply|status|teardown|reboot [--yes]", Purpose: "Plan, apply, inspect, reboot, or remove the first-party firewall capability.", Arguments: "The firewall capability reads the installed Host configuration and manages one bounded provider appliance plus six LAB IPv4 gateways.", Options: "--yes approves the initial apply, provider reboot, or destructive teardown.", Safety: "Plan and status are read-only. Apply consumes the Host-owned vmbr1 substrate and is idempotent. Reboot and teardown affect only the exact owned provider. Teardown removes the provider and its Controller-local provider state; it preserves Host trust, storage, vmbr0, vmbr1, and physical networking.", Examples: "boetticher module firewall plan; boetticher module firewall apply --yes; boetticher module firewall status; boetticher module firewall reboot --yes; boetticher module firewall teardown --yes", Related: "host apply, host status, module",
	},
	"host enroll": {
		Usage: "boetticher host enroll root@IPv4", Purpose: "Verify and bind the supported Proxmox Host to the Controller.", Arguments: "The target must be root@IPv4 and must match the imported Host key.", Options: "No options.", Safety: "Read-only remote checks plus one local /etc/boetticher/lab.yml binding. It does not apply Host configuration or deploy Modules.", Examples: "boetticher host enroll root@192.0.2.10", Related: "host status, host apply",
	},
	"host status": {
		Usage: "boetticher host status [--details]", Purpose: "Read the complete enrolled Proxmox Host state.", Arguments: "No positional arguments.", Options: "--details includes guests, storage, stable disks, LVM, mounts, interfaces, bridges, and routes.", Safety: "Read-only. It never repairs or changes the Host.", Examples: "boetticher host status; boetticher host status --details", Related: "host enroll, host apply",
	},
	"host apply": {
		Usage: "boetticher host apply [--data-disk /dev/disk/by-id/DEVICE] [--adopt-existing-network] [--yes]", Purpose: "Inspect and establish the owned Host baseline, storage, and internal virtual network.", Arguments: "No positional arguments.", Options: "--data-disk binds the exact stable disk at the destructive storage boundary; --adopt-existing-network approves a compatible unowned internal bridge; --yes approves ordinary changes.", Safety: "Idempotent and fail-closed. It never accepts Host trust automatically, adopts ambiguous state, deploys Modules, or changes HOME management.", Examples: "boetticher host apply; boetticher host apply --data-disk /dev/disk/by-id/DEVICE --yes; boetticher host apply --adopt-existing-network --yes", Related: "host status, host plan-storage",
	},
	"host plan-storage": {
		Usage: "boetticher host plan-storage", Purpose: "Preview the dedicated Host data-storage candidate without changing it.", Arguments: "No positional arguments.", Options: "No options.", Safety: "Read-only. It shows the protected boot disk, stable identities, and any exact candidate for Host apply.", Examples: "boetticher host plan-storage", Related: "host apply, host teardown",
	},
	"host teardown": {
		Usage: "boetticher host teardown [--plan] [--data-disk /dev/disk/by-id/DEVICE] [--yes]", Purpose: "Remove exact Boetticher-owned Host configuration while preserving trust, recovery, boot storage, and HOME management.", Arguments: "--plan is read-only; --data-disk must match the configured dedicated disk when it will be erased.", Options: "--yes approves ordinary removal; the disk binding is still required for destructive storage removal.", Safety: "Unknown guests, storage, bridges, and configuration stop the operation. Teardown is retryable and preserves the imported Host key trust.", Examples: "boetticher host teardown --plan; boetticher host teardown --data-disk /dev/disk/by-id/DEVICE --yes", Related: "host apply, host status",
	},
	"host reboot": {
		Usage: "boetticher host reboot --yes", Purpose: "Reboot the enrolled Proxmox Host after an explicit approval.", Arguments: "No positional arguments.", Options: "--yes is required.", Safety: "Requires a matching enrolled Host and empty guest inventory; it never reboots the Controller.", Examples: "boetticher host reboot --yes", Related: "host status, controller reboot",
	},
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
		Usage: "boetticher companion add --mac MAC [--display=BOOL] [--streamdeck=BOOL] [--pulse-agent=BOOL] [--streamdeck-serial SERIAL] [--site DIR] [--dry-run] [--confirm]", Purpose: "Record one external Companion and its attached display capabilities.", Arguments: "No positional arguments.", Options: "--mac is the physical Ethernet MAC; display, streamdeck, and pulse-agent default on when first added. Omitted capability flags preserve existing settings. --streamdeck-serial selects one exact supported device. --dry-run previews; --confirm saves desired state.", Safety: "Changes site.yml only. Run deploy to apply the reservation and separate Companion tokens, then companion setup.", Examples: "boetticher companion add --mac DC:A6:32:E9:DD:82 --confirm --site ./my-boetticher", Related: "network trunk attach, deploy, companion setup, dhcp status",
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
		Usage: "boetticher status [--site DIR] [--ssh-config PATH] [--age-identity PATH] [--ssh-journey] [--live] [--details] [--json]", Purpose: "Show the consolidated read-only operational view.", Arguments: "No positional arguments.", Options: "--live adds read-only gateway, Smallstep CA, and leaf-certificate checks; --age-identity selects the routine Age identity needed to inspect retained AirVPN metadata; --ssh-journey tests the configured bastion route; --ssh-config selects generated SSH settings; --details adds reasons and safe next actions; --json is for tools. Exit status is zero only for HEALTHY.", Safety: "Read-only. A broken connection or malformed response returns a non-zero result; it never repairs or changes infrastructure.", Examples: "boetticher status --site ./my-boetticher --details --live; boetticher status --site ./my-boetticher --details --live --json", Related: "deploy, plan, dhcp",
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
		Usage: "boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--age-identity PATH] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]", Purpose: "Look at the managed gateway rules, counters, and logs without changing them.", Arguments: "Subcommands select a read-only view; firewall logs can take a zone and limit.", Options: "--live queries the managed firewall; --age-identity selects the routine Age identity needed to inspect retained AirVPN metadata; --json is for tools; show accepts --format human|nft; logs accepts --zone and --limit 1-1000.", Safety: "These views do not edit nftables, DHCP, or routes. If you use an external gateway, it stays yours to manage. Use the rule commands to add your workload exceptions.", Examples: "boetticher firewall diff --site ./my-boetticher --live", Related: "dhcp, network, logs, status --details",
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
	"module": {
		Usage: "boetticher module <capability> <action> [flags]", Purpose: "Reserve one shallow operator namespace for a Host capability.", Arguments: "The capability is the operator-managed concern, such as firewall, dhcp, dns, ntp, vpn, monitoring, statuspage, or printer. The action is capability-specific.", Options: "Modules may define their own bounded action flags. The normal third-level namespace is the capability; do not expose provider, appliance, daemon, or peripheral names here.", Safety: "Phase 4 network services are delivered capability-first. Provider implementation names do not become public capability namespaces.", Examples: "boetticher module firewall plan; boetticher module firewall apply --yes; boetticher module firewall status; boetticher module firewall reboot --yes; boetticher module firewall teardown --yes", Related: "host apply, host status",
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
	"controller reboot":       helpSpecs["controller reboot"],
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
	document.WriteString("This page is generated from the same usage menu as `boetticher help`. The Controller owns local runtime and trust; the Host owns Proxmox baseline, storage, and virtual networking; Modules provide later operator capabilities. Add `--help` to any command for the full explanation. Reapplying an already-correct Host is a successful no-op and reports `No changes required.`\n\n")
	document.WriteString("## The usual loop\n\n```text\nboetticher controller bootstrap\nboetticher controller status\nboetticher host enroll root@PROXMOX_ADDRESS\nboetticher host apply\nboetticher host status\n```\n\n")
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
	document.WriteString("```text\nboetticher help\nboetticher help --advanced\nboetticher host apply --help\nboetticher host teardown --help\nboetticher module firewall status --help\n```\n")
	return strings.TrimRight(document.String(), "\n") + "\n"
}
