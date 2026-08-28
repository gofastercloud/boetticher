# streamdeck module

`streamdeck` is an optional, default-off status appliance at
`lab-streamdeck-01` (VMID 220, `10.10.20.70` in SERVERS). It is unprivileged,
has no inbound listener, and reads only Pulse summary and paginated Proxmox
resources. It has no Proxmox configuration, credentials, provider, or mutating
button actions.

Enablement requires `modules.streamdeck.enabled: true`, monitoring, and one
`usb_exports` binding for `streamdeck/display`. The binding records the stable
physical USB topology port plus the allowed VID/PID and optional serial. Use
`boetticher hardware usb list|status` to inspect and `bind|unbind --confirm`
to change desired state through the normal deploy engine.

Core installs a host reconciler whose caller supplies only a VMID. For each
VMID it takes `/run/lock/boetticher-usb-export-VMID.lock`, resolves every
configured parent `usb_device`, validates the complete LXC identity and device
set, applies all changes, verifies the complete result, atomically records
managed state, and then restarts a running LXC at most once. Interface-level
events cannot create a second physical identity, slot, or restart. Boot
reconciliation runs after `pve-cluster` and before guest autostart.

Pulse access uses both the platform client-certificate convention and a named,
dedicated `monitoring:read` token. The appliance creates its private key and
CSR locally; Core signs only the CSR. The token is retained in SOPS-encrypted
site state and delivered as an encrypted systemd credential.

Source checks can verify composition, generated reconciliation logic, polling,
rendering, fake-deck behavior, and failure handling. Physical detection, real
key readability, deployed mTLS access, detach/reconnect, LXC restart, and
unattended recovery remain `NOT TESTED` until exercised on the supported host
with the real device.
