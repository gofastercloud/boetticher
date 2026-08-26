# Command reference

```text
boetticher init [--site-dir DIR] [--age-identity PATH]
boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]
boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]
boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--opnsense-iso PATH] [--trunk-interface IFACE] [--dry-run]
boetticher provision [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--debian-template TEMPLATE] [--dry-run]
boetticher converge [--site DIR] [--age-identity PATH] [--opnsense-url URL] [--opnsense-ca PATH] [--proxmox-ca PATH] [--zabbix-url URL] [--insecure] [--ansible-playbook PATH] [--dry-run]
boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]
boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]
boetticher access [--site DIR]
boetticher portal build [--site DIR] [--output DIR] [--docs DIR]
boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]
boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]
boetticher opnsense credentials import [--site DIR] < credentials.json
```

`bootstrap`, `provision`, and `converge` are core capabilities. The current
build contains the source and offline contracts for each. The first real run
still needs to exercise unattended OPNsense setup, the API/interface
transition, and the physical network journeys.

Sensitive input is read from protected files or stdin where necessary. Do not place passwords, API secrets, private keys, or SOPS plaintext in arguments, persistent environment variables, logs, generated files, or Git.
