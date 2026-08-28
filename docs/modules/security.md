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

The AIOps module has no SSH or Internet path. Holmes is loopback-only and never
receives Pulse, AI Router, provider, PKI, SSH, or persistent-state credentials.
The adapter and journal query service enforce strict typed schemas and bounded
responses; HTTP path authorization remains distinct from firewall host/port
policy.
