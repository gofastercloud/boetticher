# Recovery

The minimum control-plane recovery set is the private site repository and an
independent copy of the Age private identity. The repository may contain
encrypted secrets and non-secret evidence; OpenTofu state, plans, caches, and
temporary credentials remain outside it.

In managed mode, a lost gateway is rebuilt as VM 100 from the qualified Debian
cloud image and deployed from the model: network interfaces, nftables, Kea,
SANDBOX DNS/NTP, SSH, and monitoring. Platform backups can shorten the path but
are not required to recreate the desired configuration.

In external mode, boetticher regenerates the network/security contract but does
not back up or restore the operator's appliance. Use that appliance's own
recovery procedure.

Local backups share the failure domain of their storage profile. They are useful
for rollback and local recovery, not independent disaster recovery.
