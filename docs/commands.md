---
layout: default
title: Command reference
section: commands
description: A generated menu of every public Boetticher command form.
---

# Command reference

This page is generated from the same usage menu as `boetticher help`. The Controller owns local runtime and trust; the Host owns Proxmox baseline, storage, and virtual networking; Modules provide later operator capabilities. Add `--help` to any command for the full explanation. Reapplying an already-correct Host is a successful no-op and reports `No changes required.`

## The usual loop

```text
boetticher controller bootstrap
boetticher controller status
boetticher host enroll root@PROXMOX_ADDRESS
boetticher host apply
boetticher host status
```

## Normal command menu

```text
boetticher controller bootstrap|status|reboot [--operator USER] [--confirm-key-login] [--yes]
boetticher host create-identity|show-public-key|import-host-key|enroll|apply|status|plan-storage|teardown|reboot ...
boetticher module <capability> <action> [flags]
boetticher module firewall plan|apply|status|reboot|test|teardown [flags]
boetticher module dns plan|apply|status|teardown|test|add-record|remove-record|list-records [flags]
boetticher module dhcp plan|apply|status|teardown|test|add-reservation|remove-reservation|list-reservations|list-leases [flags]
boetticher module vpn plan|apply|status|teardown|add-client [flags]
```

## Advanced command menu

```text
boetticher host status --details
boetticher host plan-storage
boetticher module <capability> <action> [--yes]
```

## Need a hand?

```text
boetticher help
boetticher help --advanced
boetticher host apply --help
boetticher host teardown --help
boetticher module firewall status --help
```
