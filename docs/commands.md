---
layout: default
title: Command reference
section: commands
description: A generated menu of every public Boetticher command form.
---

# Command reference

This page is generated from the same usage menu as `boetticher help`. Most days you will change the site, make a live plan, deploy its digest, and check status. Add `--help` to any command for the friendly, full explanation.

## The usual loop

```text
boetticher bundle import ./boetticher-0.5.1.tar.gz --site ./my-boetticher
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:... --site ./my-boetticher
boetticher status --site ./my-boetticher --details --live
```

## Normal command menu

```text
boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall] [--storage-profile single-disk|dedicated-data-disk] [--storage-device /dev/disk/by-id/DEVICE]
boetticher enroll [--site DIR] [--bootstrap-address ADDRESS] [--operator-key PATH] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--known-hosts PATH] [--proxmox-ca PATH] [--initial-user USER] [--insecure] [--trunk-interface IFACE] [--replace-scoped-credentials] [--dry-run]
boetticher plan [--site DIR] [--live] [--json]
boetticher deploy --plan DIGEST [--site DIR] [--age-identity PATH] [--confirm]
boetticher status [--site DIR] [--live] [--details] [--json]
boetticher module list|configure|enable|disable NAME [--site DIR] [--confirm] [--json]
boetticher network reservation|record add|remove|list [--site DIR]
boetticher update [--bundle PATH] [--site DIR] [--dry-run] [--confirm]
boetticher help --advanced
```

## Advanced command menu

```text
boetticher bundle inspect|import PATH [--site DIR] [--json]
boetticher recover host|storage|guest ...
boetticher companion setup|status|migrate ...
boetticher tui [--site DIR] [--offline]
boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]
boetticher aiops status [--site DIR] [--live] [--json]
boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]
boetticher access [--site DIR]
boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher network test [--site DIR] [--zones ZONE,...] [--capture] [--airvpn] [--cleanup-only] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]
boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]
boetticher firewall status|show|diff|counters|logs|verify|rule add|list|remove [--site DIR] [--live] [--json] [--format FORMAT] [--zone ZONE] [--limit N] [--source SOURCE] [--destination DESTINATION] [--vmid VMID] [--protocol PROTOCOL] [--ports PORTS] [--id ID] [--dry-run] [--confirm]
boetticher dhcp status|leases [--site DIR] [--live] [--json]
boetticher dhcp reservation add|list|remove [--site DIR] [--hostname NAME] [--address ADDRESS] [--mac MAC] [--vmid VMID] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]
boetticher storage status|initialize|recover [--site DIR] [--live] [--storage-confirmed] [--reinitialize] [--reboot] [--allow-shared-usb-bridge-quirk] [--initial-user USER] [--known-hosts PATH]
boetticher module list|configure|enable|disable NAME [--site DIR] [--dry-run] [--json] [--confirm] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher module secrets MODULE list|set|remove|rotate [--site DIR] [--age-identity PATH] [--confirm]
boetticher config validate|show|schema [--site DIR]
```

## Need a hand?

```text
boetticher help
boetticher help --advanced
boetticher deploy --help
boetticher module configure --help
```
