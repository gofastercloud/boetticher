# Lab-in-a-Box

Lab-in-a-Box is a small, opinionated Proxmox infrastructure distribution. It installs a fixed IPv4 security architecture with OPNsense routing and firewalling, dual DNS/NTP, Zabbix observability, internal PKI/mTLS, encrypted configuration, and a generated platform portal.

```text
HOME / upstream
       |
    Proxmox
       |
    OPNsense
       |
 vmbr1 VLAN bridge
       +-- TRUSTED  VLAN 10
       +-- SERVERS  VLAN 20
       +-- SANDBOX  VLAN 50
       `-- MGMT     VLAN 99
```

Core services are `lab-dns-01` and `lab-dns-02` (DNS/NTP), `lab-monitor-01` (Zabbix), and `lab-portal-01` (generated documentation and platform evidence).

## Requirements

- Fresh supported x86 Proxmox installation whose node name is `lab-proxmox-01`.
- One Ethernet NIC minimum; a second NIC and managed VLAN switch are recommended for physical networks.
- macOS arm64/amd64 or Linux arm64/amd64 controller.
- `ssh`, `ssh-keyscan`, `age-keygen`, `sops`, OpenTofu, and Ansible Core.
- OPNsense 26.7 at the exact qualified patch recorded in `site.yml`; a later 26.7 patch is not implicitly supported.
- Zabbix 7.0 LTS.
- Either the single-disk or dedicated-data-disk storage profile.

Native Windows is out of scope for V1; WSL2 is only supported if separately tested. IPv6, HA, arbitrary network addresses, arbitrary storage backends, and remote-access providers are also out of scope.

## Quickstart

```sh
homelab init --site-dir my-homelab
homelab bootstrap-endpoint set HOME_SIDE_PROXMOX_IP --site my-homelab
homelab preflight --site my-homelab --live
homelab ssh-config --site my-homelab --output ~/.ssh/config.d/labinabox.conf
homelab bootstrap --site my-homelab --opnsense-iso VERIFIED_ISO --recovery-confirmed
homelab provision --site my-homelab
homelab converge --site my-homelab
homelab ssh-config --site my-homelab --force --install-include
homelab verify --site my-homelab
```

The current source build completes the Proxmox trust transition and then reports a release-blocking OPNsense `HOLD` until the unattended installer and exact interface-address transition have been exercised on a fresh host. Do not treat that output as a complete deployment. Once that gate is qualified, import the generated OPNsense API credential through stdin and rerun provisioning/convergence:

```sh
homelab opnsense credentials import --site my-homelab < opnsense-credentials.json
```

Then use `ssh dns01`, `ssh monitor`, `homelab access`, and the generated portal at `https://portal.lab.home.arpa`.

The initial Proxmox connection is made through its HOME-side DHCP address. Proxmox then acts as the forwarding-only SSH bastion for internal hosts. Keep an independent recovery copy of the Age identity before bootstrap; the private identity never belongs in Git.

One physical NIC is sufficient. Preflight identifies the physical interface carrying the current upstream/bootstrap path. With exactly one additional eligible unused Ethernet interface, bootstrap proposes and can attach it to `vmbr1`; with multiple candidates, select one explicitly with `--trunk-interface`. A disconnected but otherwise clean candidate is valid. Interface names are observations, not identity: stable MAC/PCI evidence is persisted for later reconciliation.

## Operations

Use `verify` to prove expected journeys and security properties, `doctor` to diagnose model/projection drift, `upgrade` for controlled compatibility changes, `ssh-config` to regenerate operator access, `access` to discover endpoints, and `portal build` to rebuild the passive platform view. `network trunk`, `bootstrap-endpoint`, and `pki` own state-changing platform operations.

Core platform changes are owned by the CLI: `network trunk`, `bootstrap-endpoint`, and `pki client`/`pki trust`. Remote access is not a V1 core module. See the extension guides for Tailscale, Cloudflare private access, and WireGuard.

Lab-in-a-Box owns the platform, while Proxmox owns user workloads. There is no generic `homelab vm`, `homelab lxc`, or `homelab workload` lifecycle command. Create arbitrary workloads with Proxmox tooling, attach them to `vmbr1`, and choose the appropriate fixed security-zone VLAN. See [docs/platform-ownership.md](docs/platform-ownership.md).

## Recovery

Recovery requires both the private site repository and an independent copy of the Age private identity. See [docs/recovery/recovery.md](docs/recovery/recovery.md) for Proxmox, OPNsense, DNS, certificate, and changed-bootstrap-address procedures.

Detailed architecture, security, installation, networking, access, storage, workload, recovery, and troubleshooting guides live under [`docs/`](docs/). The same release documentation is rendered into `lab-portal-01`; the portal is a passive projection, not a second monitoring system.
