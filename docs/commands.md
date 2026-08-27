# Command reference

This reference is generated from the CLI command metadata. `deploy` is the only public platform-application command; inspection and planning commands are read-oriented unless they explicitly request confirmation.

## Usage

```text
boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]
boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]
boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run]
boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--confirm]
boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]
boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]
boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]
boetticher access [--site DIR]
boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]
boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]
boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]
boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]
boetticher dhcp status|leases [--site DIR] [--live] [--json]
boetticher dhcp reservation add|list|remove [--site DIR] [--hostname NAME] [--address ADDRESS] [--mac MAC] [--vmid VMID] [--json]
boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]
boetticher storage status|initialize [--site DIR] [--live] [--confirmed]
boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher modules list|MODULE show|plan|enable|disable|status|purge [--site DIR] [--dry-run] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher config validate|show|schema [--site DIR]
boetticher portal build [--site DIR] [--output DIR] [--docs DIR]
```

## Command details

### init

Purpose: Create a concise v3 site repository, SOPS/Age metadata, and recovery state.

Usage: `boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]`

Arguments: No positional arguments.

Options: --site-dir selects the site directory; --age-identity selects the external Age identity; --external-firewall selects the operator-owned gateway contract.

Safety: Creates local site and recovery files; it does not mutate Proxmox.

Examples: `boetticher init --site-dir ./my-boetticher`

Related commands: config validate, preflight, bootstrap

### preflight

Purpose: Validate controller, Proxmox, hardware, configuration, and deployment safety prerequisites.

Usage: `boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]`

Arguments: No positional arguments.

Options: --live performs bounded target checks; --site selects the private site; bootstrap and SSH options identify the target.

Safety: Read-only. Preflight performs no platform mutation.

Examples: `boetticher preflight --site ./my-boetticher --live`

Related commands: bootstrap, deploy --dry-run

### bootstrap

Purpose: Prepare Proxmox trust, bridges, storage, the temporary Linux builder, and qualified appliance artifacts.

Usage: `boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run]`

Arguments: No positional arguments.

Options: --dry-run renders only; --recovery-confirmed confirms the independent Age recovery copy; --storage-confirmed confirms explicit dedicated-storage initialization.

Safety: May change Proxmox bootstrap infrastructure and creates a temporary builder. Review the plan and recovery prerequisites before applying.

Examples: `boetticher bootstrap --site ./my-boetticher --recovery-confirmed`

Related commands: preflight, deploy, verify

### deploy

Purpose: Make boetticher-owned platform resources match the complete resolved desired model.

Usage: `boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--confirm]`

Arguments: No positional arguments.

Options: --dry-run plans without mutation; --confirm authorizes destructive operations supported by the active providers; an artifact qualification mismatch remains HOLD; connection options select the Proxmox trust path.

Safety: This is the sole public platform-application operation. Review the plan before applying it; unsupported rootfs replacement remains HOLD rather than being bypassed by --confirm.

Examples: `boetticher deploy --site ./my-boetticher --dry-run`; `boetticher deploy --site ./my-boetticher --confirm`

Related commands: preflight, verify, doctor

### logs

Purpose: Read a bounded journal view through the central collector using the normal Proxmox bastion path.

Usage: `boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]`

Arguments: HOST is a known boetticher-managed or retained endpoint; omitted HOST reads the collector-local journal.

Options: --site selects the private site repository; --unit accepts a bounded systemd unit name such as blocky or blocky.service; --since accepts a positive duration up to 168h; --priority accepts a fixed journal priority; --limit is 1-500 and defaults to 100.

Safety: Read-only. Output is bounded; there is no follow mode, TUI, arbitrary journal path, or query language. Central logging is asynchronous and not an availability dependency.

Examples: `boetticher logs lab-dns-01 --site ./my-boetticher --unit blocky --since 1h`; `boetticher logs lab-fw-01 --priority warning --limit 100`

Related commands: doctor, verify

### verify

Purpose: Verify the resolved model, ownership, artifacts, declarations, and supported live evidence.

Usage: `boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]`

Arguments: No positional arguments.

Options: --ssh-journey runs a bounded authenticated bastion journey; --ssh-config selects the generated SSH configuration.

Safety: Static checks are distinct from live evidence. Unsupported live checks remain NOT TESTED.

Examples: `boetticher verify --site ./my-boetticher`

Related commands: preflight, deploy, doctor

### doctor

Purpose: Diagnose current projections, module state, artifact evidence, ownership, and bounded live readiness.

Usage: `boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: No positional arguments.

Options: --live performs bounded Proxmox and endpoint checks; connection options select the target trust path.

Safety: Diagnostics do not repair infrastructure. Intentionally disabled modules are not reported unhealthy.

Examples: `boetticher doctor --site ./my-boetticher --live`

Related commands: logs, verify, deploy

### upgrade

Purpose: Run the guarded platform-version lifecycle gate.

Usage: `boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]`

Arguments: No positional arguments.

Options: --recovery-confirmed confirms an independent recovery copy; --site and --age-identity select local state.

Safety: Upgrade is a guarded lifecycle operation and is distinct from deploy.

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

Purpose: List operator access paths for enabled platform capabilities.

Usage: `boetticher access [--site DIR]`

Arguments: No positional arguments.

Options: --site selects the private site repository.

Safety: Read-only and non-secret. Logging is accessed with boetticher logs; it has no web UI.

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

### pki

Purpose: Manage bounded client certificates from the controller-side PKI authority.

Usage: `boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]`

Arguments: NAME is a validated client identity; trust export has no client NAME.

Options: --output selects an export path; --age-identity selects the external recovery identity; --site selects local state.

Safety: Private keys are never written to stdout and certificate actions update local generated state.

Examples: `boetticher pki client create operator --site ./my-boetticher`

Related commands: access, deploy, verify

### firewall

Purpose: Inspect the generated or live managed gateway policy and bounded evidence.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### dhcp

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output.

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

Usage: `boetticher storage status|initialize [--site DIR] [--live] [--confirmed]`

Arguments: status inspects; initialize prepares the configured dedicated data profile.

Options: --live reads the Proxmox host; --confirmed authorizes fixed-device initialization.

Safety: initialize can format the explicitly configured device. Modules cannot select disks or create VGs.

Examples: `boetticher storage status --site ./my-boetticher`

Related commands: bootstrap, deploy, doctor

### module

Purpose: Inspect or change first-party module intent through the shared deploy engine.

Usage: `boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.

Safety: DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.

Examples: `boetticher module list --site ./my-boetticher`; `boetticher module disable monitoring --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### modules

Purpose: Inspect or change first-party module intent through the shared registry and deploy engine.

Usage: `boetticher modules list|MODULE show|plan|enable|disable|status|purge [--site DIR] [--dry-run] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: MODULE is a registered first-party module. list retains the generic module inventory; lifecycle commands are resolved by the same generic implementation.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; purge requires --confirm and removes retained module resources only after exact ownership proof.

Safety: Both tailnet-router and litellm are default-off. Ordinary disable retains owned guests and persistent data; purge is destructive and never treats VMID range membership as ownership.

Examples: `boetticher modules list --site ./my-boetticher`; `boetticher modules tailnet-router plan --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### config

Purpose: Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.

Usage: `boetticher config validate|show|schema [--site DIR]`

Arguments: validate, show, and schema select the read-only operation.

Options: --site selects the private site repository; schema does not require a site directory.

Safety: Read-only. Unknown fields, invalid providers, and mandatory-module disable attempts fail before infrastructure mutation.

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

Safety: Read-only. Unknown fields, invalid providers, and mandatory-module disable attempts fail before infrastructure mutation.

Examples: `boetticher config validate --site ./my-boetticher`; `boetticher config schema`

Related commands: preflight, module list, deploy --dry-run

### config show

Purpose: Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.

Usage: `boetticher config validate|show|schema [--site DIR]`

Arguments: validate, show, and schema select the read-only operation.

Options: --site selects the private site repository; schema does not require a site directory.

Safety: Read-only. Unknown fields, invalid providers, and mandatory-module disable attempts fail before infrastructure mutation.

Examples: `boetticher config validate --site ./my-boetticher`; `boetticher config schema`

Related commands: preflight, module list, deploy --dry-run

### config validate

Purpose: Validate, display, or locate the typed non-secret SiteConfig schema and resolved model.

Usage: `boetticher config validate|show|schema [--site DIR]`

Arguments: validate, show, and schema select the read-only operation.

Options: --site selects the private site repository; schema does not require a site directory.

Safety: Read-only. Unknown fields, invalid providers, and mandatory-module disable attempts fail before infrastructure mutation.

Examples: `boetticher config validate --site ./my-boetticher`; `boetticher config schema`

Related commands: preflight, module list, deploy --dry-run

### dhcp leases

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp reservation add

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp reservation list

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp reservation remove

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output.

Safety: Reservation changes edit site.yml only and never adopt or mutate user guests; VMID lookup is read-only; deployment remains boetticher deploy. External-gateway DHCP remains outside boetticher management.

Examples: `boetticher dhcp reservation add --hostname app-01 --address 10.10.20.61 --mac 02:00:00:00:02:61 --site ./my-boetticher`; `boetticher dhcp leases --site ./my-boetticher --live`

Related commands: firewall, dns, verify

### dhcp status

Purpose: Inspect DHCP/DDNS intent, read bounded leases, or manage explicit user-workload reservations.

Usage: `boetticher dhcp status|leases|reservation add|list|remove [--site DIR] [--live] [--json]`

Arguments: status and leases select inspection; reservation add, list, and remove manage SERVERS reservations.

Options: --live queries the managed gateway for leases; --mac and --vmid identify reservations; --hostname and --address define additions; --json emits machine-readable output.

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

Purpose: Inspect the generated or live managed gateway policy and bounded evidence.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall diff

Purpose: Inspect the generated or live managed gateway policy and bounded evidence.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall logs

Purpose: Inspect the generated or live managed gateway policy and bounded evidence.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall show

Purpose: Inspect the generated or live managed gateway policy and bounded evidence.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall status

Purpose: Inspect the generated or live managed gateway policy and bounded evidence.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### firewall verify

Purpose: Inspect the generated or live managed gateway policy and bounded evidence.

Usage: `boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N]`

Arguments: Subcommands select the read-only view; firewall logs may accept a zone and limit.

Options: --live queries the managed firewall; --json emits machine-readable output; show accepts --format human|nft; logs accepts --zone and bounded --limit 1-1000.

Safety: Inspection only. This command does not edit nftables, DHCP, or routes; an external gateway remains operator-managed.

Examples: `boetticher firewall diff --site ./my-boetticher --live`

Related commands: dhcp, network, logs, verify

### module disable

Purpose: Inspect or change first-party module intent through the shared deploy engine.

Usage: `boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.

Safety: DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.

Examples: `boetticher module list --site ./my-boetticher`; `boetticher module disable monitoring --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### module enable

Purpose: Inspect or change first-party module intent through the shared deploy engine.

Usage: `boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.

Safety: DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.

Examples: `boetticher module list --site ./my-boetticher`; `boetticher module disable monitoring --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### module list

Purpose: Inspect or change first-party module intent through the shared deploy engine.

Usage: `boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.

Safety: DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.

Examples: `boetticher module list --site ./my-boetticher`; `boetticher module disable monitoring --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### module plan

Purpose: Inspect or change first-party module intent through the shared deploy engine.

Usage: `boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.

Safety: DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.

Examples: `boetticher module list --site ./my-boetticher`; `boetticher module disable monitoring --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### module show

Purpose: Inspect or change first-party module intent through the shared deploy engine.

Usage: `boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.

Safety: DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.

Examples: `boetticher module list --site ./my-boetticher`; `boetticher module disable monitoring --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### module status

Purpose: Inspect or change first-party module intent through the shared deploy engine.

Usage: `boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: NAME is required for show, plan, enable, disable, and optional for status.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; --purge requires --confirm and explicitly removes retained module resources.

Safety: DNS and logging are mandatory. Ordinary disable retains owned guests and persistent data; purge is destructive.

Examples: `boetticher module list --site ./my-boetticher`; `boetticher module disable monitoring --confirm --site ./my-boetticher`

Related commands: config validate, deploy, doctor

### modules list

Purpose: Inspect or change first-party module intent through the shared registry and deploy engine.

Usage: `boetticher modules list|MODULE show|plan|enable|disable|status|purge [--site DIR] [--dry-run] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]`

Arguments: MODULE is a registered first-party module. list retains the generic module inventory; lifecycle commands are resolved by the same generic implementation.

Options: --dry-run shows the resolved effect; --confirm authorizes configuration or destructive lifecycle changes; purge requires --confirm and removes retained module resources only after exact ownership proof.

Safety: Both tailnet-router and litellm are default-off. Ordinary disable retains owned guests and persistent data; purge is destructive and never treats VMID range membership as ownership.

Examples: `boetticher modules list --site ./my-boetticher`; `boetticher modules tailnet-router plan --site ./my-boetticher`

Related commands: config validate, deploy, doctor

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

Purpose: Manage bounded client certificates from the controller-side PKI authority.

Usage: `boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]`

Arguments: NAME is a validated client identity; trust export has no client NAME.

Options: --output selects an export path; --age-identity selects the external recovery identity; --site selects local state.

Safety: Private keys are never written to stdout and certificate actions update local generated state.

Examples: `boetticher pki client create operator --site ./my-boetticher`

Related commands: access, deploy, verify

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

Usage: `boetticher storage status|initialize [--site DIR] [--live] [--confirmed]`

Arguments: status inspects; initialize prepares the configured dedicated data profile.

Options: --live reads the Proxmox host; --confirmed authorizes fixed-device initialization.

Safety: initialize can format the explicitly configured device. Modules cannot select disks or create VGs.

Examples: `boetticher storage status --site ./my-boetticher`

Related commands: bootstrap, deploy, doctor

### storage status

Purpose: Inspect the Core-owned storage substrate or perform its explicitly confirmed initialization.

Usage: `boetticher storage status|initialize [--site DIR] [--live] [--confirmed]`

Arguments: status inspects; initialize prepares the configured dedicated data profile.

Options: --live reads the Proxmox host; --confirmed authorizes fixed-device initialization.

Safety: initialize can format the explicitly configured device. Modules cannot select disks or create VGs.

Examples: `boetticher storage status --site ./my-boetticher`

Related commands: bootstrap, deploy, doctor
