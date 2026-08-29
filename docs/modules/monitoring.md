# Monitoring

`monitoring` is a default-on first-party module built around Pulse Community.
It gives the homelab a small view of Proxmox inventory, host health, alerts,
availability checks, and hardware telemetry for explicitly tagged hosts.

The default target is the Proxmox host. VMs and LXCs do not receive a Pulse
agent unless Core declares and tags them as monitoring targets. Boetticher
owns the Pulse configuration and its platform state; use the native Pulse UI
at `https://monitor.<your-domain>` for dashboards and alerts.

Monitoring is configured by the platform defaults. `boetticher module status`
and `boetticher status` show its desired state; `boetticher doctor --live`
helps investigate a current connection or service problem. Disable is
available for advanced use and retains owned state until the normal purge
procedure is explicitly confirmed.

Pulse credentials and agent tokens stay in the controller's encrypted secret
workflow and protected runtime credentials. A local configuration check does
not prove that the live Pulse UI, alerts, or backup is current.
