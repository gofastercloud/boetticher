# DNS/NTP module

`dns` is mandatory and provides authoritative DNS plus NTP. Its two fixed
INFRA guests run PowerDNS Authoritative and Chrony, and persist their
PowerDNS state and stable endpoint identity across appliance replacement.

Blocky is the sole client-facing recursive/filtering implementation. It uses
the qualified filtering policy and forwards boetticher-owned zones to
PowerDNS. Negative authoritative answers never fall through to public DNS.
