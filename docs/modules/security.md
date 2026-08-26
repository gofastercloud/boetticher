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
