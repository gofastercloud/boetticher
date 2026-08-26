# DNS/NTP module

`dns` is mandatory and provides authoritative DNS plus NTP. Its two fixed
SERVERS guests run PowerDNS Authoritative and Chrony, and persist their
PowerDNS state and stable endpoint identity across appliance replacement.

The client-facing recursive/filtering provider is selected in `site.yml`:

```yaml
modules:
  dns:
    provider: blocky
```

Blocky is the default; `adguard` is a supported alternative. Both providers
use the same qualified filtering policy and forward boetticher-owned zones to
PowerDNS. Negative authoritative answers never fall through to public DNS.
Provider changes replace the appliance pair sequentially, DNS02 first, while
retaining authoritative state.
