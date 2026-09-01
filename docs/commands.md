# Command reference

This reference is generated from the CLI command metadata. `deploy` is the only public platform-application command; inspection and planning commands are read-oriented unless they explicitly request confirmation.

## Usage

```text
boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]
boetticher tui [--site DIR] [--offline]
boetticher preflight [--site DIR] [--age-identity PATH] [--live] [--record] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]
boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run] [--cleanup]
boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--rotate-airvpn-profile] [--confirm]
boetticher status [--site DIR] [--ssh-config PATH] [--ssh-journey] [--live] [--verbose] [--json]
boetticher update [--site DIR] [--dry-run] [--confirm]
boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]
boetticher aiops status [--site DIR] [--live] [--json]
boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey] [--live]
boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]
boetticher access [--site DIR]
boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]
boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher network test [--site DIR] [--zones ZONE,...] [--capture] [--cleanup-only] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher kiosk setup ADDRESS [--site DIR] [--age-identity PATH] [--user USER] [--identity-file PATH] [--known-hosts PATH] [--host-key KEY] [--port PORT] [--confirm] [--dry-run]
boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]
boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]
boetticher firewall status|show|diff|counters|logs|verify|rule add|list|remove [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N] [--source SOURCE] [--destination DESTINATION] [--vmid VMID] [--protocol PROTOCOL] [--ports PORTS] [--id ID] [--dry-run] [--confirm]
boetticher dhcp status|leases [--site DIR] [--live] [--json]
boetticher dhcp reservation add|list|remove [--site DIR] [--hostname NAME] [--address ADDRESS] [--mac MAC] [--vmid VMID] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]
boetticher storage status|initialize [--site DIR] [--live] [--storage-confirmed] [--initial-user USER] [--known-hosts PATH]
boetticher module list|show|plan|configure|enable|disable|status [NAME] [--site DIR] [--dry-run] [--json] [--confirm] [--purge] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher module secrets MODULE list|set|remove|rotate [--site DIR] [--age-identity PATH] [--confirm]
boetticher modules list|MODULE show|plan|configure|enable|disable|status|secrets|purge [--site DIR] [--dry-run] [--json] [--confirm] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher config validate|show|schema [--site DIR]
boetticher portal build [--site DIR] [--output DIR] [--docs DIR]
```

## Command details

### init

Purpose: Create a site directory with the settings and recovery files Boetticher needs.

Usage: `boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]`

Arguments: No positional arguments.

Options: --site-dir selects the site directory; --age-identity selects the operator-owned private Age identity; --external-firewall selects the operator-owned gateway contract.

Safety: Creates local site and recovery files; it does not mutate Proxmox.

Examples: `boetticher init --site-dir ./my-boetticher`

Related commands: config validate, preflight, bootstrap

### tui

Purpose: Open the experimental interactive operator interface.

Usage: `boetticher tui [--site DIR] [--offline]`

Arguments: No positional arguments.

Options: --site selects the private site repository; --offline skips live refresh and displays local projections.

Safety: Experimental. The TUI uses the existing command safety gates. Mutations still require their explicit confirmation flags; secret values are never accepted as command arguments. The command list includes the live network test; use the direct CLI when you need zones, captures, JSON, or cleanup-only.

Examples: `boetticher tui --site ./my-boetticher`

Related commands: status, doctor, deploy, module, firewall, network test

### preflight

Purpose: Check local and, with --live, already-existing target prerequisites before deployment.

Usage: `boetticher preflight [--site DIR] [--age-identity PATH] [--live] [--record] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]`

Arguments: No positional arguments.

Options: --live performs limited target checks; --record explicitly persists approved physical discovery and requires --live; --site selects the private site; --age-identity selects the operator-owned private Age identity needed to validate encrypted credential reuse; bootstrap and SSH options identify the target.

Safety: Read-only unless --live --record is explicit. A live inspection without --record never mutates site state.

Examples: `boetticher preflight --site ./my-boetticher --live`; `boetticher preflight --site ./my-boetticher --live --record`

Related commands: bootstrap, deploy --dry-run

### bootstrap

Purpose: Prepare Proxmox trust, bridges, storage, the temporary Linux builder, and qualified appliance artifacts.

Usage: `boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run] [--cleanup]`

Arguments: No positional arguments.

Options: --dry-run renders only; --cleanup removes only an exact-owned stale temporary builder and does not rebuild artifacts; --recovery-confirmed confirms the independent Age recovery copy; --storage-confirmed confirms explicit dedicated-storage initialization; --age-identity selects the operator-owned private Age identity; --operator-key selects the initial operator SSH public key; --initial-user selects the initial SSH user; --known-hosts selects an independently enrolled SSH trust file and defaults to the site-scoped trust file; --proxmox-ca selects the Proxmox API CA PEM file; --insecure explicitly allows self-signed Proxmox API TLS; --trunk-interface selects the physical trunk interface.

Safety: May change Proxmox bootstrap infrastructure and creates a temporary builder. Cleanup proves the canonical builder name and owner tag before stopping or removing VMID 190. Verify the first SSH host fingerprint at the explicit ask prompt; subsequent privileged paths require the enrolled key.

Examples: `boetticher bootstrap --site ./my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem`; `boetticher bootstrap --site ./my-boetticher --cleanup --age-identity /path/to/age-identity.txt --proxmox-ca /path/to/pve-root-ca.pem`

Related commands: preflight, deploy, verify

### deploy

Purpose: Make boetticher-owned platform resources match the complete resolved desired model.

Usage: `boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--rotate-airvpn-profile] [--confirm]`

Arguments: No positional arguments.

Options: --dry-run plans without mutation; --rotate-airvpn-profile explicitly regenerates the retained AirVPN WireGuard profile; --confirm authorizes destructive operations supported by the active providers, including replacement of an owned appliance rootfs when its declared persistent volumes can be retained; connection options select the Proxmox trust path. A normal deploy prints nine orchestration phases and one final PASS or FAIL summary with the next action on failure.

Safety: This is the sole public platform-application operation. It requires the temporary root SSH access established by bootstrap, uses the scoped Proxmox API token for lifecycle operations, and removes temporary root access after successful convergence. Review the plan before applying it; unowned occupants, invalid persistent-volume identities, and unsupported replacement conditions fail with recovery guidance. AirVPN profile generation reads only the controller-only key path and never places the key or profile in arguments, logs, or generated public state.

Examples: `boetticher deploy --site ./my-boetticher --dry-run`; `boetticher deploy --site ./my-boetticher`; `boetticher deploy --site ./my-boetticher --rotate-airvpn-profile`

Related commands: preflight, verify, doctor

### status

Purpose: Run the current platform health checks and show whether the platform needs attention.

Usage: `boetticher status [--site DIR] [--ssh-config PATH] [--ssh-journey] [--live] [--verbose] [--json]`

Arguments: No positional arguments.

Options: --live performs bounded read-only managed-gateway checks; --ssh-journey runs a bounded authenticated bastion journey; --ssh-config selects the generated SSH configuration; --verbose includes detailed reasons and next actions; --json emits the versioned status model. Exit status is zero only for HEALTHY; a failed or degraded check returns non-zero. Checks that require separate operator, recovery, or product acceptance evidence are not included.

Safety: Read-only. Status and verify use the same health checks. Live transport and malformed observations fail non-zero and are never reported as PASS.

Examples: `boetticher status --site ./my-boetticher`; `boetticher status --site ./my-boetticher --live --json`

Related commands: deploy, doctor, verify, dhcp

### update

Purpose: Plan or atomically update compatible v3 desired state to platform 0.4.0 without deploying it.

Usage: `boetticher update [--site DIR] [--dry-run] [--confirm]`

Arguments: No positional arguments.

Options: --dry-run validates and prints the update without writing; --confirm authorizes the desired-state and projection update.

Safety: Update never deploys. Failed projection refresh restores the original site.yml.

Examples: `boetticher update --site ./my-boetticher --dry-run`; `boetticher update --site ./my-boetticher --confirm`

Related commands: deploy, status, config validate

### logs

Purpose: Read a bounded journal view through the central collector using the normal Proxmox bastion path.

Usage: `boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]`

Arguments: HOST is a known boetticher-managed or retained endpoint; omitted HOST reads the collector-local journal.

Options: --site selects the private site repository; --unit accepts a bounded systemd unit name such as blocky or blocky.service; --since accepts a positive duration up to 168h; --priority accepts a fixed journal priority; --limit is 1-500 and defaults to 100.

Safety: Read-only. Output is bounded; there is no follow mode, TUI, arbitrary journal path, or query language. Central logging is asynchronous and not an availability dependency.

Examples: `boetticher logs lab-dns-01 --site ./my-boetticher --unit blocky --since 1h`; `boetticher logs lab-fw-01 --priority warning --limit 100`

Related commands: doctor, verify

### aiops

Purpose: Inspect desired or bounded live AIOps incident lifecycle and usage state.

Usage: `boetticher aiops status [--site DIR] [--live] [--json]`

Arguments: status is the only operation.

Options: --live reads the adapter's loopback status through the normal bastion; --json emits machine-readable output.

Safety: Read-only. No investigation, note, acknowledgement, clearing, restart, or remediation is triggered.

Examples: `boetticher aiops status --site ./my-boetticher --live`

Related commands: module status, doctor, logs

### verify

Purpose: Compatibility alias for the status health checks that also refreshes verification and portal artifacts.

Usage: `boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey] [--live]`

Arguments: No positional arguments.

Options: --ssh-journey runs a bounded authenticated bastion journey; --ssh-config selects the generated SSH configuration; --live queries the managed gateway health; verification results are written to the generated evidence and status projections.

Safety: Status and verify use the same checks. Unsupported live or acceptance checks are omitted rather than reported as NOT TESTED.

Examples: `boetticher verify --site ./my-boetticher`; `boetticher verify --site ./my-boetticher --live`

Related commands: status, preflight, deploy, doctor

### doctor

Purpose: Diagnose current projections, module state, artifact evidence, ownership, and bounded live readiness.

Usage: `boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: No positional arguments.

Options: --live performs bounded Proxmox and endpoint checks; connection options select the target trust path.

Safety: Diagnostics do not repair infrastructure. Intentionally disabled modules are not reported unhealthy.

Examples: `boetticher doctor --site ./my-boetticher --live`

Related commands: logs, verify, deploy

### upgrade

Purpose: Run the guarded platform-version compatibility gate.

Usage: `boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]`

Arguments: No positional arguments.

Options: --recovery-confirmed confirms an independent recovery copy; --site and --age-identity select local state.

Safety: This advanced gate is not available for normal upgrades and does not replace deploy or update.

Examples: `boetticher upgrade --site ./my-boetticher --recovery-confirmed`

Related commands: preflight, deploy, verify

### ssh-config

Purpose: Render or validate the generated bastion-aware SSH configuration.

Usage: `boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]`

Arguments: No positional arguments.

Options: --check validates an existing file; --output selects a file or -; --force permits replacing the generated file; --install-include installs the user SSH include.

Safety: Writes only the selected SSH projection; inspect paths before using --force.

Examples: `boetticher ssh-config --site ./my-boetticher --check`

Related commands: access, logs, verify

### access

Purpose: List supported operator interfaces and explicit break-glass access for enabled platform capabilities.

Usage: `boetticher access [--site DIR]`

Arguments: No positional arguments.

Options: --site selects the private site repository.

Safety: Read-only and non-secret. Routine SSH and hand mutation of Core-managed appliances are unsupported; the external firewall remains operator-managed; SSH/Ansible is an internal controller transport. Logging is accessed with boetticher logs; it has no web UI.

Examples: `boetticher access --site ./my-boetticher`

Related commands: logs, portal, ssh-config

### bootstrap-endpoint

Purpose: Inspect or record the HOME-side Proxmox bootstrap address.

Usage: `boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]`

Arguments: set requires an IPv4 ADDRESS; show has no positional argument.

Options: --site selects the private site repository.

Safety: set changes local site configuration only; it does not connect or mutate Proxmox.

Examples: `boetticher bootstrap-endpoint set 192.0.2.73 --site ./my-boetticher`

Related commands: preflight, bootstrap

### network

Purpose: Inspect or explicitly change the physical trunk binding while preserving the virtual-only contract by default.

Usage: `boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: INTERFACE is required for attach and detach and must match observed hardware identity.

Options: --live queries Proxmox; --confirm authorizes a live trunk change; connection options select the target trust path.

Safety: Physical trunk changes can lock out management. Virtual-only sites do not claim spare NICs automatically.

Examples: `boetticher network trunk status --site ./my-boetticher --live`

Related commands: preflight, bootstrap, firewall

### hardware

Purpose: Inspect observed USB hardware and manage stable bindings for compiled-in module requirements.

Usage: `boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: status optionally filters MODULE REQUIREMENT; bind requires MODULE REQUIREMENT PORT; unbind requires MODULE REQUIREMENT.

Options: --live reads parent usb_device identities from Proxmox; --confirm is required to change desired state and invoke deploy; connection options select the target trust path.

Safety: Bindings cannot name device paths, VMIDs, or user workloads. Live identity and the compiled requirement allow-list are verified before mutation.

Examples: `boetticher hardware usb bind printer serial 1-2.4 --confirm --site ./my-boetticher`

Related commands: module, deploy, preflight

### pki

Purpose: Manage bounded client certificates from the controller-side PKI authority.

Usage: `boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]`

Arguments: NAME is a validated client identity; trust export has no client NAME.

Options: --output selects an export path; --age-identity selects the external recovery identity; --site selects local state.

Safety: Private keys are never written to stdout and certificate actions update local generated state.

Examples: `boetticher pki client create operator --site ./my-boetticher`

Related commands: access, deploy, verify

### firewall

Purpose: Inspect the generated or live managed gateway policy and bounded checks.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: These views are read-only and do not edit nftables, DHCP, or routes; an external gateway remains operator-managed. Use the separate rule commands to change user firewall intent.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### dhcp

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output; connection options select the target trust path when resolving a VMID.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dns

Purpose: Manage bounded user-owned A and CNAME records in the private lab namespace.

Usage: `boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]`

Arguments: add requires --name, --type, and --value; remove requires --name and --type; list has no required arguments.

Options: --value is an IPv4 address for A or a private FQDN for CNAME; --json emits machine-readable output; --site selects local desired state.

Safety: Changes are local site.yml intent only and apply through boetticher deploy. Core, module, and DHCP/DDNS-owned names cannot be replaced; arbitrary PowerDNS administration is not exposed.

Examples: `boetticher dns record add --name app.lab.home.arpa --type CNAME --value app-01.servers.lab.home.arpa --site ./my-boetticher`

Related commands: dhcp, config validate, deploy

### storage

Purpose: Inspect the Core-owned storage substrate or perform its explicitly confirmed initialization.

Usage: `boetticher storage status|initialize [--site DIR] [--live] [--storage-confirmed] [--initial-user USER] [--known-hosts PATH]`

Arguments: status inspects; initialize prepares the configured dedicated data profile.

Options: --live reads the Proxmox host; --storage-confirmed authorizes fixed-device initialization; --initial-user and --known-hosts select the SSH path.

Safety: initialize can format the explicitly configured device. Modules cannot select disks or create VGs.

Examples: `boetticher storage status --site ./my-boetticher`

Related commands: bootstrap, deploy, doctor

### module

Purpose: Inspect or change first-party module intent through the shared deploy engine, or configure desired state with the declaration-driven wizard.

Usage: `boetticher module list|show|plan|configure|enable|disable|status [NAME] [--site DIR] [--dry-run] [--json] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, configure, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --json emits a redacted configure plan; --confirm authorizes lifecycle or configure changes; configure accepts repeatable --set KEY=VALUE, --usb REQUIREMENT=PORT, and --secret NAME (value from stdin).

Safety: Configure changes site.yml and existing SOPS secrets only; it never deploys. Confirmed enable and disable changes desired state and immediately invoke deploy; --dry-run does not. DNS and logging are mandatory. Ordinary disable retains owned guests; purge remains destructive.

Examples: `boetticher module configure printer --site ./my-boetticher`; `boetticher module configure aiops --enabled true --set model_alias=operations-investigator --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### modules

Purpose: Inspect or change first-party module intent and manage declared operator secrets through the shared registry and deploy engine.

Usage: `boetticher modules list|MODULE show|plan|configure|enable|disable|status|secrets|purge [--site DIR] [--dry-run] [--json] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: MODULE is a registered first-party module. list retains the generic module inventory; lifecycle, configure, and secret commands use the same generic implementation.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration, destructive lifecycle changes, and secret removal; configure accepts repeatable --set KEY=VALUE, --usb REQUIREMENT=PORT, and --secret NAME (value from stdin).

Safety: tailnet-router, airvpn, bifrost, printer, and streamdeck are default-off. AirVPN profile rotation is explicit and uses the controller-only API key. Configure changes desired state only and never deploys; confirmed enable and disable invoke deploy. Secret values are never displayed or accepted as command arguments.

Examples: `boetticher modules printer configure --site ./my-boetticher`; `boetticher modules aiops configure --set model_alias=operations-investigator --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### config

Purpose: Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.

Usage: `boetticher config validate|show|schema [--site DIR]`

Arguments: validate, show, and schema select the read-only operation.

Options: --site selects the private site repository; schema does not require a site directory.

Safety: Read-only. Unknown fields, invalid configuration, and mandatory-module disable attempts fail before infrastructure mutation.

Examples: `boetticher config validate --site ./my-boetticher`; `boetticher config schema`

Related commands: preflight, module list, deploy --dry-run

### portal

Purpose: Build the passive, non-secret generated portal from the resolved model and evidence.

Usage: `boetticher portal build [--site DIR] [--output DIR] [--docs DIR]`

Arguments: build is the only portal operation.

Options: --output selects the generated portal directory; --docs selects product documentation.

Safety: Writes generated static content only; it does not provide executable module content or expose secrets.

Examples: `boetticher portal build --site ./my-boetticher`

Related commands: access, verify, doctor

## Nested command details

### aiops status

Purpose: Inspect desired or bounded live AIOps incident lifecycle and usage state.

Usage: `boetticher aiops status [--site DIR] [--live] [--json]`

Arguments: status is the only operation.

Options: --live reads the adapter's loopback status through the normal bastion; --json emits machine-readable output.

Safety: Read-only. No investigation, note, acknowledgement, clearing, restart, or remediation is triggered.

Examples: `boetticher aiops status --site ./my-boetticher --live`

Related commands: module status, doctor, logs

### bootstrap-endpoint set

Purpose: Inspect or record the HOME-side Proxmox bootstrap address.

Usage: `boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]`

Arguments: set requires an IPv4 ADDRESS; show has no positional argument.

Options: --site selects the private site repository.

Safety: set changes local site configuration only; it does not connect or mutate Proxmox.

Examples: `boetticher bootstrap-endpoint set 192.0.2.73 --site ./my-boetticher`

Related commands: preflight, bootstrap

### bootstrap-endpoint show

Purpose: Inspect or record the HOME-side Proxmox bootstrap address.

Usage: `boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]`

Arguments: set requires an IPv4 ADDRESS; show has no positional argument.

Options: --site selects the private site repository.

Safety: set changes local site configuration only; it does not connect or mutate Proxmox.

Examples: `boetticher bootstrap-endpoint set 192.0.2.73 --site ./my-boetticher`

Related commands: preflight, bootstrap

### config schema

Purpose: Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.

Usage: `boetticher config validate|show|schema [--site DIR]`

Arguments: validate, show, and schema select the read-only operation.

Options: --site selects the private site repository; schema does not require a site directory.

Safety: Read-only. Unknown fields, invalid configuration, and mandatory-module disable attempts fail before infrastructure mutation.

Examples: `boetticher config validate --site ./my-boetticher`; `boetticher config schema`

Related commands: preflight, module list, deploy --dry-run

### config show

Purpose: Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.

Usage: `boetticher config validate|show|schema [--site DIR]`

Arguments: validate, show, and schema select the read-only operation.

Options: --site selects the private site repository; schema does not require a site directory.

Safety: Read-only. Unknown fields, invalid configuration, and mandatory-module disable attempts fail before infrastructure mutation.

Examples: `boetticher config validate --site ./my-boetticher`; `boetticher config schema`

Related commands: preflight, module list, deploy --dry-run

### config validate

Purpose: Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.

Usage: `boetticher config validate|show|schema [--site DIR]`

Arguments: validate, show, and schema select the read-only operation.

Options: --site selects the private site repository; schema does not require a site directory.

Safety: Read-only. Unknown fields, invalid configuration, and mandatory-module disable attempts fail before infrastructure mutation.

Examples: `boetticher config validate --site ./my-boetticher`; `boetticher config schema`

Related commands: preflight, module list, deploy --dry-run

### dhcp leases

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output; connection options select the target trust path when resolving a VMID.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp reservation add

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output; connection options select the target trust path when resolving a VMID.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp reservation list

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output; connection options select the target trust path when resolving a VMID.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp reservation remove

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output; connection options select the target trust path when resolving a VMID.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp status

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output; connection options select the target trust path when resolving a VMID.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dns

Purpose: Manage bounded user-owned A and CNAME records in the private lab namespace.

Usage: `boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]`

Arguments: add requires --name, --type, and --value; remove requires --name and --type; list has no required arguments.

Options: --value is an IPv4 address for A or a private FQDN for CNAME; --json emits machine-readable output; --site selects local desired state.

Safety: Changes are local site.yml intent only and apply through boetticher deploy. Core, module, and DHCP/DDNS-owned names cannot be replaced; arbitrary PowerDNS administration is not exposed.

Examples: `boetticher dns record add --name app.lab.home.arpa --type CNAME --value app-01.servers.lab.home.arpa --site ./my-boetticher`

Related commands: dhcp, config validate, deploy

### dns record add

Purpose: Manage bounded user-owned A and CNAME records in the private lab namespace.

Usage: `boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]`

Arguments: add requires --name, --type, and --value; remove requires --name and --type; list has no required arguments.

Options: --value is an IPv4 address for A or a private FQDN for CNAME; --json emits machine-readable output; --site selects local desired state.

Safety: Changes are local site.yml intent only and apply through boetticher deploy. Core, module, and DHCP/DDNS-owned names cannot be replaced; arbitrary PowerDNS administration is not exposed.

Examples: `boetticher dns record add --name app.lab.home.arpa --type CNAME --value app-01.servers.lab.home.arpa --site ./my-boetticher`

Related commands: dhcp, config validate, deploy

### dns record list

Purpose: Manage bounded user-owned A and CNAME records in the private lab namespace.

Usage: `boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]`

Arguments: add requires --name, --type, and --value; remove requires --name and --type; list has no required arguments.

Options: --value is an IPv4 address for A or a private FQDN for CNAME; --json emits machine-readable output; --site selects local desired state.

Safety: Changes are local site.yml intent only and apply through boetticher deploy. Core, module, and DHCP/DDNS-owned names cannot be replaced; arbitrary PowerDNS administration is not exposed.

Examples: `boetticher dns record add --name app.lab.home.arpa --type CNAME --value app-01.servers.lab.home.arpa --site ./my-boetticher`

Related commands: dhcp, config validate, deploy

### dns record remove

Purpose: Manage bounded user-owned A and CNAME records in the private lab namespace.

Usage: `boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]`

Arguments: add requires --name, --type, and --value; remove requires --name and --type; list has no required arguments.

Options: --value is an IPv4 address for A or a private FQDN for CNAME; --json emits machine-readable output; --site selects local desired state.

Safety: Changes are local site.yml intent only and apply through boetticher deploy. Core, module, and DHCP/DDNS-owned names cannot be replaced; arbitrary PowerDNS administration is not exposed.

Examples: `boetticher dns record add --name app.lab.home.arpa --type CNAME --value app-01.servers.lab.home.arpa --site ./my-boetticher`

Related commands: dhcp, config validate, deploy

### firewall counters

Purpose: Inspect the generated or live managed gateway policy and bounded checks.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: These views are read-only and do not edit nftables, DHCP, or routes; an external gateway remains operator-managed. Use the separate rule commands to change user firewall intent.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall diff

Purpose: Inspect the generated or live managed gateway policy and bounded checks.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: These views are read-only and do not edit nftables, DHCP, or routes; an external gateway remains operator-managed. Use the separate rule commands to change user firewall intent.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall logs

Purpose: Inspect the generated or live managed gateway policy and bounded checks.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: These views are read-only and do not edit nftables, DHCP, or routes; an external gateway remains operator-managed. Use the separate rule commands to change user firewall intent.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall rule add

Purpose: Add a bounded user-workload firewall rule to desired site configuration.

Usage: `boetticher firewall rule add [--source SOURCE] [--destination DESTINATION|--vmid VMID] [--protocol PROTOCOL] [--ports PORTS] [--id ID] [--site DIR] [--dry-run] [--confirm] [--json]`

Arguments: --source and --protocol are required; choose exactly one of --destination and --vmid.

Options: --dry-run previews the change; --confirm writes it; --age-identity, --proxmox-ca, and --insecure apply when resolving a VMID.

Safety: Changes site.yml only and never deploys. Core destinations remain rejected except a reserved SERVERS /32 to the fixed Pulse endpoint on TCP/443. Review the rule before confirming; deployment remains boetticher deploy.

Examples: `boetticher firewall rule add --source TRUSTED --destination 10.10.20.61 --protocol tcp --ports 8080 --confirm --site ./my-boetticher`; `boetticher firewall rule add --source 10.10.20.50/32 --destination 10.10.10.20/32 --protocol tcp --ports 443 --id ufr-lab-display-pulse --confirm --site ./my-boetticher`

Related commands: firewall diff, deploy, dhcp reservation

### firewall rule list

Purpose: List user-workload firewall rules recorded in the site.

Usage: `boetticher firewall rule list [--site DIR] [--json]`

Arguments: No positional arguments.

Options: --json emits machine-readable rules; --site selects local state.

Safety: Read-only. It does not change firewall policy or deploy anything.

Examples: `boetticher firewall rule list --site ./my-boetticher`

Related commands: firewall rule add, firewall rule remove

### firewall rule remove

Purpose: Remove a user-workload firewall rule from desired site configuration.

Usage: `boetticher firewall rule remove --id ID [--site DIR] [--dry-run] [--confirm] [--json]`

Arguments: --id is required.

Options: --dry-run previews the change; --confirm writes it; --json emits machine-readable output.

Safety: Changes site.yml only and never deploys. Review the rule before confirming; deployment remains boetticher deploy.

Examples: `boetticher firewall rule remove --id ufr-example --confirm --site ./my-boetticher`

Related commands: firewall rule list, deploy

### firewall show

Purpose: Inspect the generated or live managed gateway policy and bounded checks.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: These views are read-only and do not edit nftables, DHCP, or routes; an external gateway remains operator-managed. Use the separate rule commands to change user firewall intent.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall status

Purpose: Inspect the generated or live managed gateway policy and bounded checks.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: These views are read-only and do not edit nftables, DHCP, or routes; an external gateway remains operator-managed. Use the separate rule commands to change user firewall intent.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall verify

Purpose: Inspect the generated or live managed gateway policy and bounded checks.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: These views are read-only and do not edit nftables, DHCP, or routes; an external gateway remains operator-managed. Use the separate rule commands to change user firewall intent.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### hardware usb bind

Purpose: Inspect observed USB hardware and manage stable bindings for compiled-in module requirements.

Usage: `boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: status optionally filters MODULE REQUIREMENT; bind requires MODULE REQUIREMENT PORT; unbind requires MODULE REQUIREMENT.

Options: --live reads parent usb_device identities from Proxmox; --confirm is required to change desired state and invoke deploy; connection options select the target trust path.

Safety: Bindings cannot name device paths, VMIDs, or user workloads. Live identity and the compiled requirement allow-list are verified before mutation.

Examples: `boetticher hardware usb bind printer serial 1-2.4 --confirm --site ./my-boetticher`

Related commands: module, deploy, preflight

### hardware usb list

Purpose: Inspect observed USB hardware and manage stable bindings for compiled-in module requirements.

Usage: `boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: status optionally filters MODULE REQUIREMENT; bind requires MODULE REQUIREMENT PORT; unbind requires MODULE REQUIREMENT.

Options: --live reads parent usb_device identities from Proxmox; --confirm is required to change desired state and invoke deploy; connection options select the target trust path.

Safety: Bindings cannot name device paths, VMIDs, or user workloads. Live identity and the compiled requirement allow-list are verified before mutation.

Examples: `boetticher hardware usb bind printer serial 1-2.4 --confirm --site ./my-boetticher`

Related commands: module, deploy, preflight

### hardware usb status

Purpose: Inspect observed USB hardware and manage stable bindings for compiled-in module requirements.

Usage: `boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: status optionally filters MODULE REQUIREMENT; bind requires MODULE REQUIREMENT PORT; unbind requires MODULE REQUIREMENT.

Options: --live reads parent usb_device identities from Proxmox; --confirm is required to change desired state and invoke deploy; connection options select the target trust path.

Safety: Bindings cannot name device paths, VMIDs, or user workloads. Live identity and the compiled requirement allow-list are verified before mutation.

Examples: `boetticher hardware usb bind printer serial 1-2.4 --confirm --site ./my-boetticher`

Related commands: module, deploy, preflight

### hardware usb unbind

Purpose: Inspect observed USB hardware and manage stable bindings for compiled-in module requirements.

Usage: `boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: status optionally filters MODULE REQUIREMENT; bind requires MODULE REQUIREMENT PORT; unbind requires MODULE REQUIREMENT.

Options: --live reads parent usb_device identities from Proxmox; --confirm is required to change desired state and invoke deploy; connection options select the target trust path.

Safety: Bindings cannot name device paths, VMIDs, or user workloads. Live identity and the compiled requirement allow-list are verified before mutation.

Examples: `boetticher hardware usb bind printer serial 1-2.4 --confirm --site ./my-boetticher`

Related commands: module, deploy, preflight

### kiosk setup

Purpose: Configure one 64-bit Debian-based Raspberry Pi as the Boetticher CAGE Pulse kiosk and host-monitoring agent.

Usage: `boetticher kiosk setup ADDRESS [--site DIR] [--age-identity PATH] [--user USER] [--identity-file PATH] [--known-hosts PATH] [--host-key KEY] [--port PORT] [--confirm] [--dry-run]`

Arguments: ADDRESS is a canonical IPv4 address for the Raspberry Pi.

Options: --site selects the private site; --age-identity selects the operator-owned Age identity; --user selects the existing Pi SSH account; --identity-file selects the owner-only SSH private key; --known-hosts selects the strict host-key file; --host-key enrolls an independently verified host key; --port selects SSH port; --dry-run renders checks only; --confirm authorizes remote mutation.

Safety: Advanced and live. Requires an owner-only SSH key, an exact enrolled host key, and the encrypted pulse_agent_token created by a qualified boetticher deploy; no password or global SSH configuration fallback is used. The command changes the Pi, writes or reuses the separate kiosk PKI identity in external runtime state, and requires passwordless sudo for non-root SSH users. Live deployment, monitoring, and display acceptance remain separate qualification gates.

Examples: `boetticher kiosk setup 192.0.2.50 --site ./my-boetticher --identity-file ~/.ssh/id_ed25519 --known-hosts ./my-boetticher/generated/ssh/kiosk_known_hosts --confirm`

Related commands: pki client create, pki trust export, status, doctor

### module configure

Purpose: Configure one built-in module's desired state.

Usage: `boetticher module configure MODULE [--site DIR] [--dry-run] [--json] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--confirm]`

Arguments: MODULE is a registered first-party module.

Options: The interactive workflow asks only for fields the module needs. --set provides repeatable typed values; --usb provides repeatable physical bindings; --secret names a secret read from a hidden prompt or stdin; --age-identity selects the operator-owned private Age identity; --non-interactive suppresses prompts; --dry-run previews; --confirm applies.

Safety: Changes local desired state only and never deploys. Secret values come from a prompt or stdin and are never accepted as arguments or shown in plans.

Examples: `boetticher module configure printer --site ./my-boetticher`; `boetticher module configure aiops --non-interactive --enabled true --set model_alias=operations-investigator --confirm --site ./my-boetticher`

Related commands: module show, deploy, module secrets

### module disable

Purpose: Disable one optional built-in module and apply the resulting platform change.

Usage: `boetticher module disable NAME [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is a registered optional module.

Options: --dry-run validates and displays the plan without changing the site; --confirm applies the desired-state change and invokes deploy; --purge requests removal of owned resources; connection options select the target trust path.

Safety: A confirmed disable changes desired state and immediately invokes deploy. It retains owned resources by default. Purge is destructive and requires exact ownership proof and confirmation; --dry-run does not mutate or deploy.

Examples: `boetticher module disable printer --confirm --site ./my-boetticher`

Related commands: module status, deploy, recovery

### module enable

Purpose: Enable one optional built-in module and apply the resulting platform change.

Usage: `boetticher module enable NAME [--site DIR] [--dry-run] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is a registered optional module.

Options: --dry-run validates and displays the plan without changing the site; --confirm applies the desired-state change and invokes deploy; connection options select the target trust path.

Safety: A confirmed enable changes desired state and immediately invokes deploy. Review the plan first; --dry-run does not mutate or deploy.

Examples: `boetticher module enable monitoring --confirm --site ./my-boetticher`

Related commands: module configure, deploy

### module list

Purpose: List built-in modules, their policy, and current state.

Usage: `boetticher module list [--site DIR]`

Arguments: No positional arguments.

Options: --site selects the private site repository.

Safety: Read-only. It does not change desired state or deploy.

Examples: `boetticher module list --site ./my-boetticher`

Related commands: module show, module status

### module plan

Purpose: Preview the resolved changes for one built-in module.

Usage: `boetticher module plan NAME [--site DIR] [--dry-run]`

Arguments: NAME is a registered first-party module.

Options: --dry-run validates without writing; --site selects the private site repository.

Safety: Read-only planning does not deploy or change site state.

Examples: `boetticher module plan printer --site ./my-boetticher`

Related commands: module configure, deploy

### module secrets

Purpose: Inspect and manage declared operator-supplied secrets for a first-party module.

Usage: `boetticher module secrets MODULE list|set|remove|rotate [--site DIR] [--age-identity PATH] [--confirm]`

Arguments: MODULE is a registered first-party module; list, set, and remove select the secret operation, with NAME required for set and remove. AirVPN rotate removes the Core-generated retained profile and requires no NAME.

Options: --site selects the private site repository; --age-identity selects the operator-owned private Age identity; --confirm is required for secret removal and AirVPN profile rotation.

Safety: Secret values are read from a hidden prompt or stdin and are never accepted as arguments, displayed, logged, or written to generated output. The command changes encrypted desired state only; it never deploys. AirVPN rotation is limited to the Core-generated profile.

Examples: `boetticher module secrets bifrost list --site ./my-boetticher`; `boetticher module secrets bifrost set openrouter_api_key --site ./my-boetticher`; `boetticher module secrets bifrost remove openrouter_api_key --confirm --site ./my-boetticher`; `boetticher module secrets airvpn rotate --confirm --site ./my-boetticher`

Related commands: module configure, deploy, config validate

### module show

Purpose: Show one built-in module's policy, dependencies, and current configuration.

Usage: `boetticher module show NAME [--site DIR]`

Arguments: NAME is a registered first-party module.

Options: --site selects the private site repository.

Safety: Read-only. It does not change desired state or deploy.

Examples: `boetticher module show printer --site ./my-boetticher`

Related commands: module configure, module list

### module status

Purpose: Show desired and available status for built-in modules.

Usage: `boetticher module status [NAME] [--site DIR] [--age-identity PATH]`

Arguments: NAME optionally limits the view to one registered module.

Options: --site selects the private site repository; --age-identity selects the operator-owned private Age identity when inspecting named-module secrets.

Safety: Read-only. A local status result does not prove a deployed service journey; use top-level status, doctor, or verify for supported live evidence.

Examples: `boetticher module status printer --site ./my-boetticher`

Related commands: status, doctor, module list

### modules MODULE configure

Purpose: Inspect or change first-party module intent and manage declared operator secrets through the shared registry and deploy engine.

Usage: `boetticher modules list|MODULE show|plan|configure|enable|disable|status|secrets|purge [--site DIR] [--dry-run] [--json] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: MODULE is a registered first-party module. list retains the generic module inventory; lifecycle, configure, and secret commands use the same generic implementation.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration, destructive lifecycle changes, and secret removal; configure accepts repeatable --set KEY=VALUE, --usb REQUIREMENT=PORT, and --secret NAME (value from stdin).

Safety: tailnet-router, airvpn, bifrost, printer, and streamdeck are default-off. AirVPN profile rotation is explicit and uses the controller-only API key. Configure changes desired state only and never deploys; confirmed enable and disable invoke deploy. Secret values are never displayed or accepted as command arguments.

Examples: `boetticher modules printer configure --site ./my-boetticher`; `boetticher modules aiops configure --set model_alias=operations-investigator --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### modules MODULE secrets

Purpose: Inspect or change first-party module intent and manage declared operator secrets through the shared registry and deploy engine.

Usage: `boetticher modules list|MODULE show|plan|configure|enable|disable|status|secrets|purge [--site DIR] [--dry-run] [--json] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: MODULE is a registered first-party module. list retains the generic module inventory; lifecycle, configure, and secret commands use the same generic implementation.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration, destructive lifecycle changes, and secret removal; configure accepts repeatable --set KEY=VALUE, --usb REQUIREMENT=PORT, and --secret NAME (value from stdin).

Safety: tailnet-router, airvpn, bifrost, printer, and streamdeck are default-off. AirVPN profile rotation is explicit and uses the controller-only API key. Configure changes desired state only and never deploys; confirmed enable and disable invoke deploy. Secret values are never displayed or accepted as command arguments.

Examples: `boetticher modules printer configure --site ./my-boetticher`; `boetticher modules aiops configure --set model_alias=operations-investigator --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### modules list

Purpose: Inspect or change first-party module intent and manage declared operator secrets through the shared registry and deploy engine.

Usage: `boetticher modules list|MODULE show|plan|configure|enable|disable|status|secrets|purge [--site DIR] [--dry-run] [--json] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: MODULE is a registered first-party module. list retains the generic module inventory; lifecycle, configure, and secret commands use the same generic implementation.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration, destructive lifecycle changes, and secret removal; configure accepts repeatable --set KEY=VALUE, --usb REQUIREMENT=PORT, and --secret NAME (value from stdin).

Safety: tailnet-router, airvpn, bifrost, printer, and streamdeck are default-off. AirVPN profile rotation is explicit and uses the controller-only API key. Configure changes desired state only and never deploys; confirmed enable and disable invoke deploy. Secret values are never displayed or accepted as command arguments.

Examples: `boetticher modules printer configure --site ./my-boetticher`; `boetticher modules aiops configure --set model_alias=operations-investigator --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### network test

Purpose: Run bounded reachability, DNS, policy, mTLS, and performance checks from temporary probes in the selected zones.

Usage: `boetticher network test [--site DIR] [--zones ZONE,...] [--capture] [--cleanup-only] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: No positional arguments. By default all six modeled zones are exercised.

Options: --zones selects a comma-separated subset; --capture adds a bounded probe-local tcpdump case; --cleanup-only removes stale exact-owned probes; --json emits the redacted report model; connection options select the Proxmox trust path.

Safety: Advanced and live. It creates only exact-owned unprivileged LXC probes in VMIDs 910-919 and never changes firewall policy. It attempts cleanup after every run; a cleanup failure fails the command and must be resolved before retrying. Unknown occupants and ambiguous evidence fail with the reason. Results are private evidence and do not change desired state.

Examples: `boetticher network test --site ./my-boetticher`; `boetticher network test --zones TRUSTED,SANDBOX --json --site ./my-boetticher`

Related commands: network trunk status, firewall diff, dhcp leases, verify

### network trunk attach

Purpose: Inspect or explicitly change the physical trunk binding while preserving the virtual-only contract by default.

Usage: `boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: INTERFACE is required for attach and detach and must match observed hardware identity.

Options: --live queries Proxmox; --confirm authorizes a live trunk change; connection options select the target trust path.

Safety: Physical trunk changes can lock out management. Virtual-only sites do not claim spare NICs automatically.

Examples: `boetticher network trunk status --site ./my-boetticher --live`

Related commands: preflight, bootstrap, firewall

### network trunk detach

Purpose: Inspect or explicitly change the physical trunk binding while preserving the virtual-only contract by default.

Usage: `boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: INTERFACE is required for attach and detach and must match observed hardware identity.

Options: --live queries Proxmox; --confirm authorizes a live trunk change; connection options select the target trust path.

Safety: Physical trunk changes can lock out management. Virtual-only sites do not claim spare NICs automatically.

Examples: `boetticher network trunk status --site ./my-boetticher --live`

Related commands: preflight, bootstrap, firewall

### network trunk status

Purpose: Inspect or explicitly change the physical trunk binding while preserving the virtual-only contract by default.

Usage: `boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: INTERFACE is required for attach and detach and must match observed hardware identity.

Options: --live queries Proxmox; --confirm authorizes a live trunk change; connection options select the target trust path.

Safety: Physical trunk changes can lock out management. Virtual-only sites do not claim spare NICs automatically.

Examples: `boetticher network trunk status --site ./my-boetticher --live`

Related commands: preflight, bootstrap, firewall

### pki client create

Purpose: Manage bounded client certificates from the controller-side PKI authority.

Usage: `boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]`

Arguments: NAME is a validated client identity; trust export has no client NAME.

Options: --output selects an export path; --age-identity selects the external recovery identity; --site selects local state.

Safety: Private keys are never written to stdout and certificate actions update local generated state.

Examples: `boetticher pki client create operator --site ./my-boetticher`

Related commands: access, deploy, verify

### pki client export

Purpose: Manage bounded client certificates from the controller-side PKI authority.

Usage: `boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]`

Arguments: NAME is a validated client identity; trust export has no client NAME.

Options: --output selects an export path; --age-identity selects the external recovery identity; --site selects local state.

Safety: Private keys are never written to stdout and certificate actions update local generated state.

Examples: `boetticher pki client create operator --site ./my-boetticher`

Related commands: access, deploy, verify

### pki client revoke

Purpose: Manage bounded client certificates from the controller-side PKI authority.

Usage: `boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]`

Arguments: NAME is a validated client identity; trust export has no client NAME.

Options: --output selects an export path; --age-identity selects the external recovery identity; --site selects local state.

Safety: Private keys are never written to stdout and certificate actions update local generated state.

Examples: `boetticher pki client create operator --site ./my-boetticher`

Related commands: access, deploy, verify

### pki trust export

Purpose: Export the public Boetticher trust chain for an operator client.

Usage: `boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]`

Arguments: No positional arguments.

Options: --output selects a file or - for stdout; --age-identity selects the external recovery identity; --site selects local state.

Safety: Writes public certificates only. The private CA key is never exported.

Examples: `boetticher pki trust export --site ./my-boetticher --output -`

Related commands: pki client create, access

### portal build

Purpose: Build the passive, non-secret generated portal from the resolved model and evidence.

Usage: `boetticher portal build [--site DIR] [--output DIR] [--docs DIR]`

Arguments: build is the only portal operation.

Options: --output selects the generated portal directory; --docs selects product documentation.

Safety: Writes generated static content only; it does not provide executable module content or expose secrets.

Examples: `boetticher portal build --site ./my-boetticher`

Related commands: access, verify, doctor

### storage initialize

Purpose: Inspect the Core-owned storage substrate or perform its explicitly confirmed initialization.

Usage: `boetticher storage status|initialize [--site DIR] [--live] [--storage-confirmed] [--initial-user USER] [--known-hosts PATH]`

Arguments: status inspects; initialize prepares the configured dedicated data profile.

Options: --live reads the Proxmox host; --storage-confirmed authorizes fixed-device initialization; --initial-user and --known-hosts select the SSH path.

Safety: initialize can format the explicitly configured device. Modules cannot select disks or create VGs.

Examples: `boetticher storage status --site ./my-boetticher`

Related commands: bootstrap, deploy, doctor

### storage status

Purpose: Inspect the Core-owned storage substrate or perform its explicitly confirmed initialization.

Usage: `boetticher storage status|initialize [--site DIR] [--live] [--storage-confirmed] [--initial-user USER] [--known-hosts PATH]`

Arguments: status inspects; initialize prepares the configured dedicated data profile.

Options: --live reads the Proxmox host; --storage-confirmed authorizes fixed-device initialization; --initial-user and --known-hosts select the SSH path.

Safety: initialize can format the explicitly configured device. Modules cannot select disks or create VGs.

Examples: `boetticher storage status --site ./my-boetticher`

Related commands: bootstrap, deploy, doctor
