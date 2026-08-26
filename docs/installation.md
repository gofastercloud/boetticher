# Installation

V1 starts from a fresh Proxmox VE x86 host on the existing HOME/upstream network. The host must use the fixed product node name `lab-proxmox-01`; arbitrary node names are not supported by the V1 model.

## Controller and state

Supported controller platforms are macOS arm64, macOS amd64, Linux arm64, and Linux amd64. Native Windows is out of scope. WSL2 may be used only after a separate test confirms the required SSH, Age, SOPS, OpenTofu, and Ansible behavior.

`boetticher init` creates a private site repository containing:

- `site.yml` and `.sops.yaml` with only the public Age recipient;
- encrypted SOPS documents under `secrets/`;
- platform/version locks and generated non-secret model, inventory, portal, and evidence artifacts.

The Age private identity is created at `~/.config/boetticher/age/identity.txt` (or the explicit path supplied to `init`) with restrictive permissions. It is never written to the site repository. Before destructive bootstrap, make and verify an independent recovery copy. The CLI requires `--recovery-confirmed` for the live path.

Git may contain desired state, encrypted secrets, and non-secret evidence. OpenTofu state, plans, provider caches, Ansible caches, bootstrap state, temporary credentials, and other runtime material stay outside Git and are treated as potentially sensitive.

## Sequence

1. Run `boetticher init --site-dir my-boetticher`.
2. Secure the independent Age recovery copy.
3. Reach fresh Proxmox on its HOME-side DHCP address and run `boetticher bootstrap-endpoint set ADDRESS`.
4. Run `boetticher preflight --site my-boetticher --live`. This identifies the active upstream NIC and proposes exactly one safe unused trunk NIC, or reports virtual-only/multiple-candidate state.
5. If multiple candidates remain, repeat with `--trunk-interface IFACE`; do not select by enumeration order.
6. Generate/check the SSH file with `boetticher ssh-config --force --install-include`.
7. Run `boetticher bootstrap --recovery-confirmed`, adding `--trunk-interface IFACE` only when required by discovery.
8. Run `boetticher provision --opnsense-iso VERIFIED_ISO` and `boetticher converge` after the OPNsense API is available.
9. Run `boetticher verify`, `boetticher doctor`, and `boetticher portal build`.

The initial bootstrap trust transition is: operator authentication to fresh Proxmox → operator SSH key → `labadmin` and forwarding-only `lab-jump` → scoped Proxmox API token → direct encrypted SOPS handoff. Interactive secrets are not accepted through command arguments, persistent environment variables, logs, or generated files.

## Release-blocking OPNsense gate

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
→ repeat from a wiped environment
```

The source build currently implements and tests the deterministic contract, Proxmox VM creation, credential handoff, VLAN/Kea/firewall API adapters, and generated state boundary. It does not claim that the unattended OPNsense installer or the management interface-address transition is live-qualified. `boetticher bootstrap` therefore stops after the Proxmox portion until this gate is exercised on exact OPNsense 26.7.2_2 without manual OPNsense surgery.
