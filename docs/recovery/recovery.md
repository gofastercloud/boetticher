# Recovery

The minimum recovery authority is:

- the private site repository;
- an independent Age private identity;
- the required boetticher release and build definitions;
- the CA/recovery authority; and
- declared persistent data and backups where applicable.

Artifact binaries are reconstructable. Package manifests, SBOMs, scanner
reports, qualification records, and builder metadata are reconstructable
operational/build outputs, not recovery authority. Loss of `generated/artifacts/`,
Trivy reports, or builder provenance does not prevent rebuilding the platform.
Cached qualified artifacts can still shorten recovery when they are available
and their checksums remain valid.

In managed mode, a lost gateway is rebuilt as VM 100 from the qualified
boetticher firewall appliance artifact and deployed from the model: network
interfaces, nftables, Kea, SANDBOX DNS/NTP, SSH, and monitoring. Its declared
Kea lease and endpoint-identity volumes are preserved when available.
Platform backups can shorten the path but are not required to recreate the
desired configuration.

Appliance root filesystems are reconstructable from the boetticher version,
required release/build definitions, site configuration, and controller
recovery authority. Runtime configuration, credentials, and replaceable
certificates are regenerated during deploy. Persistent application data is
restored or reattached separately from the root filesystem.

In external mode, boetticher regenerates the network/security contract but does
not back up or restore the operator's appliance. Use that appliance's own
recovery procedure.

Local backups share the failure domain of their storage profile. They are useful
for rollback and local recovery, not independent disaster recovery.
