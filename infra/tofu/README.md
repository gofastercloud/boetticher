# OpenTofu integration boundary

This stack consumes `generated/proxmox/desired-state.json`, so the canonical Go model remains the single source for guest identity, address, VLAN, gateway, sizing, and storage selection. The HCL does not contain site-specific credentials or a second hand-maintained inventory.

The pinned `bpg/proxmox` provider configuration manages the firewall VM and Debian LXC foundation guests. The provider token is supplied at runtime through a generated, short-lived, or SOPS-decoded variable; it is never committed. OpenTofu state, plans, plugin caches, and lock material are runtime state and stay outside the private site repository.

`vmbr1` creation and the initial Proxmox trust transition remain in the controller’s guarded API path because they are bootstrap-sensitive network operations. Provider apply, import, backend/locking behavior, prevent-destroy behavior, and clean-host recovery must be qualified on a real Proxmox node before V1 is called operationally proven. Run `tofu fmt -check` locally; a successful syntax check is not live apply evidence.
