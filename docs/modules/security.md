# Module security boundary

Built-in modules are trusted release code, constrained to declarations. Core
rejects duplicate fixed VMIDs, ownership collisions, duplicate DNS identities,
unsafe network intent, missing capabilities, dependency cycles, and invalid
artifact identity before mutation.

Modules cannot adopt a user workload because a VMID, hostname, address, tag, or
DNS name happens to match. Reserved identities are fixed and collisions stop
deployment for operator review.

Modules cannot emit nftables rules, edit bridges, call arbitrary Proxmox APIs,
load plugins, download code, run hooks, or access SOPS/Age and CA authority.
Only first-party modules compiled into the boetticher release execute.

USB access is a Core-owned export, not a generic passthrough interface. Modules
declare named requirements and allowed physical identities; site configuration
can bind only those requirements. The Proxmox-host helper accepts no device
path or guest target from its caller and refuses unowned guests, ambiguous
slots, non-character devices, and identity mismatches before restart.
Raw USB consumers receive only the resolved parent device; serial consumers
receive only the single tty descendant below that parent. Enumeration names
are never accepted as desired-state identity.

A compromised service remains subject to its non-root service account and
systemd sandbox where supported. Proxmox/root is a trusted host boundary, and a
root compromise inside a guest is not treated as a controller compromise.

The durable `labadmin` identity has no general sudo authority on Proxmox or
appliances; the managed firewall exposes only fixed, read-only inspection
helpers. Core uses the scoped Proxmox API token for lifecycle operations and a
temporary root SSH transport for qualified convergence. Ansible connects as
root without `become`; successful convergence removes the temporary root
access. Bootstrap and operator break-glass root access remain separate
recovery authorities.

Firewall telemetry is a separate non-root service account. It reads one
root-owned, group-readable snapshot produced by the fixed
`boetticher-firewall-snapshot.service` and writes only its owned SQLite state
directory. The snapshot unit has the only `nft` inspection authority; neither
unit has a mutation command or a general sudo path. The HTTP API is bound to
the firewall INFRA address, has a fixed allow-list containing only Pulse, and
is blocked from the upstream/WAN interface.
