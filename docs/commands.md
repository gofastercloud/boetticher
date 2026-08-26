# Command reference

All commands accept `--site DIR` where shown. The v0.2 CLI is deliberately
small: generated state is changed through the platform model and `converge`,
while inspection commands are read-oriented.

```text
boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]
boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]
boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run]
boetticher provision [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--debian-template TEMPLATE] [--dry-run]
boetticher converge [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--zabbix-url URL] [--insecure] [--ansible-playbook PATH] [--dry-run]
boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]
boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]
boetticher access [--site DIR]
boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json]
boetticher dhcp status|leases [--site DIR] [--live] [--json]
boetticher storage status|initialize [--site DIR] [--live] [--confirmed]
boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]
boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]
boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]
boetticher portal build [--site DIR] [--output DIR] [--docs DIR]
```

`firewall show` displays policy intent by default and accepts `--format nft`
for the generated managed ruleset. In external mode it displays the generated
firewall contract. `firewall diff`, `counters`, and `logs` inspect only the
managed gateway and explain when the appliance is external. They do not edit
firewall rules.

`dhcp` is similarly an inspection surface. DHCP is managed by the Debian
gateway in managed mode and by the operator’s appliance in external mode.
