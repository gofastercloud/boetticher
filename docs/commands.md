# Command reference

```text
boetticher init [--site-dir DIR] [--age-identity PATH]
boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--trunk-interface IFACE]
boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]
boetticher bootstrap [--site DIR] [--opnsense-iso PATH] [--recovery-confirmed] [--trunk-interface IFACE] [--dry-run]
boetticher provision [--site DIR] [--debian-template TEMPLATE] [--dry-run]
boetticher converge [--site DIR] [--opnsense-url URL] [--opnsense-ca PATH] [--proxmox-ca PATH] [--dry-run]
boetticher verify | doctor | upgrade [--site DIR]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--install-include]
boetticher access [--site DIR]
boetticher portal build [--site DIR] [--output DIR] [--docs DIR]
boetticher network trunk status|attach|detach [INTERFACE] [--site DIR]
boetticher pki client create|export|revoke NAME [--site DIR]
boetticher pki trust export [--site DIR]
boetticher opnsense credentials import [--site DIR] < credentials.json
```

`bootstrap`, `provision`, and `converge` are core capabilities. The current build contains the source and offline contracts for each, but the OPNsense unattended-install/API/interface gate and physical network journeys remain explicit live qualification gates.

Sensitive input is read from protected files or stdin where necessary. Do not place passwords, API secrets, private keys, or SOPS plaintext in arguments, persistent environment variables, logs, generated files, or Git.
