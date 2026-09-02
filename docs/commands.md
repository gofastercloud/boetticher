---
layout: default
title: Command reference
section: commands
description: A generated menu of every public Boetticher command form.
---

# Command reference

This page is generated from the same usage menu as `boetticher help`. Most days you will use `deploy`, `status`, `doctor`, and `module configure`. Add `--help` to any command for the friendly, full explanation.

## The usual loop

```text
boetticher deploy --site ./my-boetticher --dry-run
boetticher deploy --site ./my-boetticher
boetticher status --site ./my-boetticher --live
boetticher doctor --site ./my-boetticher --live
```

## Full command menu

```text
boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall] [--storage-profile single-disk|dedicated-data-disk] [--storage-device /dev/disk/by-id/DEVICE]
boetticher tui [--site DIR] [--offline]
boetticher preflight [--site DIR] [--age-identity PATH] [--live] [--record] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]
boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--replace-scoped-credentials] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run] [--cleanup]
boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--insecure] [--dry-run] [--rotate-airvpn-profile] [--replace-firewall] [--recreate-legacy-lxcs] [--confirm]
boetticher status [--site DIR] [--ssh-config PATH] [--ssh-journey] [--live] [--verbose] [--json]
boetticher update [--site DIR] [--dry-run] [--confirm]
boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]
boetticher aiops status [--site DIR] [--live] [--json]
boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey] [--live]
boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]
boetticher access [--site DIR]
boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]
boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher network test [--site DIR] [--zones ZONE,...] [--capture] [--airvpn] [--cleanup-only] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher kiosk setup ADDRESS [--site DIR] [--age-identity PATH] [--user USER] [--identity-file PATH] [--known-hosts PATH] [--host-key KEY] [--port PORT] [--confirm] [--dry-run]
boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]
boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]
boetticher firewall status|show|diff|counters|logs|verify|rule add|list|remove [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N] [--source SOURCE] [--destination DESTINATION] [--vmid VMID] [--protocol PROTOCOL] [--ports PORTS] [--id ID] [--dry-run] [--confirm]
boetticher dhcp status|leases [--site DIR] [--live] [--json]
boetticher dhcp reservation add|list|remove [--site DIR] [--hostname NAME] [--address ADDRESS] [--mac MAC] [--vmid VMID] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]
boetticher storage status|initialize|recover [--site DIR] [--live] [--storage-confirmed] [--reinitialize] [--reboot] [--allow-shared-usb-bridge-quirk] [--initial-user USER] [--known-hosts PATH]
boetticher module list|show|plan|configure|enable|disable|status [NAME] [--site DIR] [--dry-run] [--json] [--confirm] [--purge] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher module secrets MODULE list|set|remove|rotate [--site DIR] [--age-identity PATH] [--confirm]
boetticher modules list|MODULE show|plan|configure|enable|disable|status|secrets|purge [--site DIR] [--dry-run] [--json] [--confirm] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher config validate|show|schema [--site DIR]
boetticher portal build [--site DIR] [--output DIR] [--docs DIR]
```

## Need a hand?

```text
boetticher help
boetticher help --advanced
boetticher deploy --help
boetticher module configure --help
```
