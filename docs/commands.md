---
layout: default
title: Command reference
section: commands
description: A generated menu of every public Boetticher command form.
---

# Command reference

This page is generated from the same usage menu as `boetticher help`. The foundation lifecycle is Controller-driven and uses native Linux and Proxmox state. Add `--help` to any command for the full explanation. Healthy repeat convergence reports `No changes required.`

## The usual loop

```text
boetticher controller status
boetticher host status
boetticher storage status
boetticher network status
boetticher foundation converge
```

## Normal command menu

```text
boetticher controller bootstrap|status [--operator USER] [--confirm-key-login]
boetticher host identity|trust|enroll|status|prepare ...
boetticher storage plan|initialize|status [--device PATH] [--confirm]
boetticher network plan|configure|status
boetticher foundation status|converge|teardown
```

## Advanced command menu

```text
boetticher host status --details
boetticher storage status
boetticher network status
boetticher logs [HOST] [--site DIR] [--unit UNIT] [--since DURATION] [--priority LEVEL] [--limit N]
boetticher aiops status [--site DIR] [--live] [--json]
boetticher network test bridge-ipv6
boetticher hardware usb list|status|bind|unbind [MODULE REQUIREMENT [PORT]] [--site DIR] [--live] [--confirm] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher dhcp status|leases [--site DIR] [--live] [--json]
boetticher dhcp reservation add|list|remove [--site DIR] [--hostname NAME] [--address ADDRESS] [--mac MAC] [--vmid VMID] [--json] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
boetticher dns record add|list|remove [--site DIR] [--name NAME] [--type A|CNAME] [--value VALUE] [--json]
boetticher module list|configure|enable|disable NAME [--site DIR] [--dry-run] [--json] [--confirm] [--non-interactive] [--enabled BOOL] [--set KEY=VALUE] [--secret NAME] [--usb REQUIREMENT=PORT] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]
```

## Need a hand?

```text
boetticher help
boetticher help --advanced
boetticher foundation converge --help
boetticher network configure --help
```
