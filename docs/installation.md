# Installation

Run `homelab init` on a supported controller. It creates a private site repository, an external Age identity, encrypted SOPS documents, and deterministic model metadata. Make an independent Age recovery copy before running destructive bootstrap.

`homelab preflight` validates controller platform and required tools. `bootstrap` begins from the HOME-side Proxmox DHCP address, creates the firewall VM, and performs the release-blocking unattended OPNsense integration. `provision` creates the foundation guests; `converge` applies policy and services.
