# Module architecture

Core is always present. It loads and validates `SiteConfig`, resolves the
first-party registry, composes declarations, detects conflicts, and performs
privileged deployment through the platform providers.

The built-in modules are:

| Module | Policy | Capability |
| --- | --- | --- |
| `dns` | mandatory | DNS and NTP |
| `monitoring` | default-on | Zabbix monitoring |
| `firewall` | default-on | managed gateway |

External-firewall mode supplies the gateway capability outside the registry
and explicitly disables the managed firewall module.

Modules are compiled into boetticher. They are not downloaded, loaded as
plugins, or executed as arbitrary hooks. A module emits bounded declarations;
Core owns Proxmox, network, DNS, PKI, secrets, monitoring, backup, portal, and
deployment operations.

The desired path is:

```text
SiteConfig -> validation -> enablement/dependencies -> declarations
           -> conflict checks -> canonical Site -> boetticher deploy
```

There is no background controller or second application path.
