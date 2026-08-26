# Platform ownership

boetticher owns the platform. Proxmox owns the user's homelab.

boetticher converges only declared platform resources: the Proxmox host, firewall, DNS/NTP nodes, monitor, portal, `vmbr0`, the owned portions of `vmbr1`, fixed VLANs, OPNsense routing/firewall/NAT/Kea, platform DNS/NTP, PKI/mTLS, SOPS secrets, SSH bastion policy, Zabbix platform objects, platform backup policy, portal content, and verification/recovery metadata.

It does not adopt arbitrary VMs, LXCs, bridges, bonds, VLANs, routes, SDN objects, Zabbix objects, or backup jobs. OpenTofu state contains only platform guests and future official module resources. The suggested ID ranges are:

```text
100–199  boetticher core platform
200–499  official boetticher modules
500–899  user workloads
```

There is no generic `boetticher vm create`, `boetticher lxc create`, `boetticher guest delete`, or `boetticher workload create` command. Use Proxmox Web UI, `qm`, `pct`, OpenTofu, Ansible, Pulumi, or another user-owned tool:

```text
Create VM/LXC in Proxmox
→ attach NIC to vmbr1
→ choose TRUSTED, SERVERS, SANDBOX, or justified MGMT VLAN
→ use DHCP where appropriate
→ boot
```

The workload receives the zone's address, gateway, DNS, NTP, permitted Internet access, and inter-zone policy without entering boetticher ownership. DHCP-driven DNS registration is discovery, not adoption. An unknown guest is informational in doctor and never causes convergence failure, deletion, import, monitoring, or backup claims.

Official modules are a separate future extension point. `boetticher module enable|disable`, when introduced, will be reserved for boetticher capabilities that coordinate lifecycle, secrets, firewall, DNS, PKI, Zabbix, backup, verification, and portal concerns. It is not a generic application lifecycle API.
