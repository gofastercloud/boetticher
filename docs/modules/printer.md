# 3D printer management

The default-off `printer` module manages one physically attached Creality
Ender-3 V3 SE through OctoPrint 1.11.8. It creates the fixed unprivileged LXC
`lab-printer-01` (VMID 230) at `10.10.20.80` in SERVERS and publishes the UI at
`https://octoprint.<domain>` and `https://printer.<domain>`.

This first implementation deliberately has one manager, printer model, and
USB serial requirement. It does not provide webcam streaming, multiple-printer
scheduling, arbitrary OctoPrint plugins, firmware flashing, USB storage, or
printer power control.

## USB binding

The Ender is connected directly to the Proxmox host with a data-capable
USB-A-to-C cable. Core binds the compiled `printer/serial` requirement to a
physical USB port and the allowed CH340 identity `1a86:7523`; bus numbers and
`/dev/ttyUSBN` enumeration are observation only.

```yaml
modules:
  printer:
    enabled: true
usb_exports:
  - module: printer
    requirement: serial
    port: "1-2.4"
    vendor_id: "1a86"
    product_id: "7523"
```

Use `boetticher hardware usb list --live` to observe the actual parent port
and identity, then `boetticher hardware usb bind printer serial PORT --confirm`
to record it. A missing device, identity mismatch, multiple serial descendants,
unowned VMID 230, or occupied unmanaged LXC device slot is `HOLD`.

The host reconciler follows the physical port to its current tty descendant,
maps only that character device as UID/GID 2200 with mode `0660`, and restarts
the owned LXC only when the complete mapping changes. OctoPrint runs as the
non-login `octoprint` user under a closed systemd device policy.

## OctoPrint setup

The appliance contains pinned OctoPrint dependencies and cannot replace its
application or install plugins at runtime. Nginx is the only network listener;
it uses an endpoint-local key and a controller-signed certificate, while the
OctoPrint backend listens only on `127.0.0.1:5000`.

On first access, complete OctoPrint's first-run wizard and create the local
administrator account. Configure the printer profile as Ender-3 V3 SE,
rectangular 220 x 220 x 250 mm with a heated bed, and select 115200 baud. Leave
the serial port on automatic selection: the LXC receives only the declared
printer tty.

Before that wizard creates the administrator, the setup page is claimable by
another client already admitted to TRUSTED. Do not publish the service beyond
that zone, complete onboarding immediately after deploy, and keep the live
acceptance gate at `HOLD` until authenticated access and an unauthenticated
negative path have both been verified.

OctoPrint configuration, local account hashes, uploads, and job history live
on the backed-up sensitive `/var/lib/octoprint` volume. TLS and SSH identities
use their standard retained volumes. Disabling the module retains these
volumes; purge requires the normal exact ownership proof and confirmation.

## Network and acceptance

TRUSTED clients reach only the HTTPS frontend. The module declares DNS, NTP,
central logging, and no general Internet egress, so OctoPrint update and plugin
downloads are not runtime paths. Application changes require a newly built,
smoke-tested, Trivy-qualified appliance.

Source tests and `make image-check` do not qualify a printer. Acceptance needs
the real Proxmox host and Ender: observe the exact identity, bind and hotplug
the cable, verify stable tty remapping after re-enumeration, complete the
authenticated first-run journey, connect at 115200, query temperatures, home
safely, upload a known G-code file, complete a supervised test print, and
verify restart plus backup/restore behavior. Until exercised, these gates are
`NOT TESTED`.
