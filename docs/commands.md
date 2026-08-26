# Command reference

All commands accept `--site DIR` where shown. `deploy` is the only public
platform-application command; inspection and module planning commands are
read-oriented unless they explicitly request confirmation.

```text
boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]
boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]
boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run]
boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--confirm]

boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]
boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]
boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]
boetticher access [--site DIR]
boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json]
boetticher dhcp status|leases [--site DIR] [--live] [--json]
boetticher storage status|initialize [--site DIR] [--live] [--confirmed]
boetticher module list|show|plan|enable|disable|status [NAME] [--site DIR] [--dry-run] [--confirm] [--purge] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher config validate|show|schema [--site DIR]
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
