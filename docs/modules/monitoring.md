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

The kiosk uses its own non-administrative mTLS identity. Pulse 6.1.2 omits
admin-only security-posture fields from the kiosk response; its generic
frontend banner can therefore report missing API-token or protected-export
settings on that screen even when an admin response confirms both protections
are enabled. Do not grant the kiosk administrative or export privileges to
suppress that banner; verify the posture from an operator session instead.
