These definitions are boetticher-owned source inputs for the Zabbix desired
object manifest. Their stable boetticher/platform namespace is the ownership
boundary: convergence may create or update these objects, but must not delete
or overwrite user-managed Zabbix objects. The installation-specific manifest
is rendered from the canonical model at
/etc/zabbix/boetticher-platform/desired-objects.json.

This directory is deliberately non-secret.
