# DNS and NTP

`dns` is mandatory and provides the platform's DNS and NTP. Its two fixed
INFRA guests run PowerDNS Authoritative and Chrony, and persist their
PowerDNS state and stable endpoint identity across appliance replacement.

Blocky is the sole client-facing recursive/filtering implementation. It uses
the built-in filtering policy and forwards Boetticher-owned zones to PowerDNS.
Negative authoritative answers never fall through to public DNS.

There is no DNS provider choice and no disable switch. Add user-owned A or
CNAME records with `boetticher dns record`; platform and DHCP/DDNS records are
managed by Core. In managed mode, clients use the fixed DNS addresses described
in [the network guide](../networking/dhcp-dns-ntp.md). In external-firewall
mode, the operator's appliance must provide the same contract.

`boetticher dns record` changes desired state only; run `boetticher deploy` to
apply it. Use `boetticher doctor --live` when a live DNS or NTP path needs
investigation.
