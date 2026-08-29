# Lost DNS

Rebuild the failed DNS node from the site repository and its independent deployment inputs. Keep both fixed DNS/NTP addresses configured for clients. Run `boetticher deploy`, then check each node independently with `boetticher status --live` before treating service redundancy as restored.

If both nodes are unavailable, use the [main recovery runbook](recovery.md) and the [DNS module guide](../modules/dns.md); do not hand-edit PowerDNS state as a normal recovery path.
