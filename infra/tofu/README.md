# OpenTofu integration boundary

The Go controller owns the deterministic model and local runtime state. This directory is the V1 integration boundary for the authenticated Proxmox provider configuration that will create:

- `lab-fw-01` VM;
- `lab-dns-01`, `lab-dns-02`, `lab-monitor-01`, and `lab-portal-01` LXCs;
- `vmbr1` and its VLAN-aware configuration;
- the selected storage profile.

The provider, backend, imports, locking, and clean-host recovery path must be qualified before live bootstrap is considered complete. No live credentials or state belong in this repository.
