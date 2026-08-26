# Installation

V1 starts from a fresh Proxmox VE x86 host on the existing HOME/upstream network. The host must use the fixed product node name `lab-proxmox-01`; arbitrary node names are not supported by the V1 model.

The foundation needs at least 4 logical CPU threads, 16 GiB RAM, and 128 GiB usable storage. 4+ cores, 32 GiB RAM, and 256 GiB or more leaves useful room for user workloads. One physical Ethernet NIC is enough; a second NIC and managed 802.1Q switch are recommended for physical VLAN breakout.

## Controller and state

Supported controller platforms are macOS arm64, macOS amd64, Linux arm64, and Linux amd64. Native Windows is out of scope. WSL2 may be used only after a separate test confirms the required SSH, Age, SOPS, OpenTofu, and Ansible behavior.

`boetticher init` creates a private site repository containing:

- `site.yml` and `.sops.yaml` with only the public Age recipient;
- encrypted SOPS documents under `secrets/`;
- platform/version locks and generated non-secret model, inventory, portal, and status artifacts.

The Age private identity is created at `~/.config/boetticher/age/identity.txt` (or the explicit path supplied to `init`) with restrictive permissions. It is never written to the site repository. Before destructive bootstrap, make and verify an independent recovery copy. The CLI requires `--recovery-confirmed` for the live path.

Git may contain desired state, encrypted secrets, and non-secret status output. OpenTofu state, plans, provider caches, Ansible caches, bootstrap state, temporary credentials, and other runtime material stay outside Git and are treated as potentially sensitive.

## Sequence

1. Run `boetticher init --site-dir my-boetticher`.
2. Secure the independent Age recovery copy.
3. Reach fresh Proxmox on its HOME-side DHCP address and run `boetticher bootstrap-endpoint set ADDRESS --site my-boetticher`.
4. Run `boetticher preflight --site my-boetticher --live`. This identifies the active upstream NIC and proposes exactly one safe unused trunk NIC, or reports virtual-only/multiple-candidate state.
5. If multiple candidates remain, repeat with `--trunk-interface IFACE`; do not select by enumeration order.
6. Generate/check the SSH file with `boetticher ssh-config --site my-boetticher --force --install-include`.
7. Run `boetticher bootstrap --site my-boetticher --opnsense-iso VERIFIED_ISO --recovery-confirmed`, adding `--trunk-interface IFACE` only when required by discovery. Bootstrap owns the verified OPNsense ISO because it creates and starts the firewall VM.
8. Run `boetticher provision --site my-boetticher` and `boetticher converge --site my-boetticher` after the OPNsense API is available. Provision creates the DNS, monitor, and portal guests; it does not manage arbitrary user guests.
9. Run `boetticher verify --site my-boetticher`, `boetticher doctor --site my-boetticher`, and `boetticher portal build --site my-boetticher`.

The initial bootstrap trust transition is: operator authentication to fresh Proxmox → operator SSH key → `labadmin` and forwarding-only `lab-jump` → scoped Proxmox API token → direct encrypted SOPS handoff. Interactive secrets are not accepted through command arguments, persistent environment variables, logs, or generated files.

## The important OPNsense first run

OPNsense bootstrap is a core capability, not an optional documentation step. The required repeatable sequence is:

```text
fresh Proxmox
→ create firewall VM
→ unattended OPNsense installation/bootstrap
→ establish WAN and internal VLAN/trunk interfaces
→ establish MGMT reachability
→ create scoped automation identities
→ capture API credentials directly into SOPS
→ authenticate through supported APIs
→ converge Kea/firewall/network policy
→ remove temporary bootstrap privilege
→ repeat from a clean installation
```

The source build covers the deterministic contract, Proxmox VM creation,
secure secret handling, network configuration, and generated state boundary.
The unattended OPNsense installer and management interface/address transition
still need a real first run on exact OPNsense 26.7.2_2. Until then,
`boetticher bootstrap` stops after the Proxmox portion; that is a deliberate
reminder that the live part has not been tried yet.
