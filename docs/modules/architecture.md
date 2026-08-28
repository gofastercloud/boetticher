# Module architecture

Core is always present. It loads and validates `SiteConfig`, resolves the
first-party registry, composes declarations, detects conflicts, and performs
privileged deployment through the platform providers.

The built-in modules are:

| Module | Policy | Capability |
| --- | --- | --- |
| `logging` | mandatory | central systemd journal |
| `dns` | mandatory | DNS and NTP |
| `monitoring` | default-on | Pulse Proxmox API monitoring and tagged-host hardware telemetry |
| `aiops` | default-off | HolmesGPT read-only incident investigation through Pulse, journals, and LiteLLM |
| `firewall` | default-on | managed gateway and bounded firewall telemetry API |

External-firewall mode supplies the gateway capability outside the registry
and explicitly disables the managed firewall module.

DNS is one module with `blocky` as the default client-facing resolver/filter
and `adguard` as a supported typed alternative. PowerDNS Authoritative and
Chrony are common to both. Core shared infrastructure, including monitoring,
uses INFRA; `lab-monitor-01` is at `10.10.10.20`. Ordinary platform
applications remain in SERVERS and do not use MGMT placement.

Modules are compiled into boetticher. They are not downloaded, loaded as
plugins, or executed as arbitrary hooks. A module emits bounded declarations;
Core owns Proxmox, network, DNS, PKI, secrets, monitoring, backup, portal, and
deployment operations.

The generic `monitoring-agent` tag controls Pulse host-agent installation. The
default tag is attached to `lab-proxmox-01`; an explicitly tagged declared
managed component is an opt-in target. Untagged VMs and LXCs receive no agent.

The desired path is:

```text
SiteConfig -> validation -> enablement/dependencies -> declarations
           -> conflict checks -> canonical Site -> boetticher deploy
```

There is no background controller or second application path.
