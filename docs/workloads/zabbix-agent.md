# User-managed Zabbix onboarding

boetticher automatically manages monitoring for its own platform hosts and services only. User workloads are not adopted because they are visible to Proxmox or Zabbix.

For a user-owned Linux workload, choose one of these user-owned paths:

- install Zabbix Agent 2 and add the host in the Zabbix UI/API;
- expose SNMP or an application API and create the corresponding Zabbix object;
- leave the workload unmonitored.

Use the zone policy to permit only the required monitoring path. Keep user objects outside the generated `boetticher/platform` host group and preserve their own names/tags. boetticher convergence must not delete or overwrite them.

The portal may state that a platform host is monitored by Zabbix, but it does not reproduce Zabbix telemetry. Live metrics, dashboards, events, alerting, and user-host lifecycle belong to Zabbix and the operator.
