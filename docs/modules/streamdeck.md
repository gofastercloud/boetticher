# StreamDeck host display

`streamdeck` is an optional, default-off first-party module. It creates one
unprivileged LXC, `lab-streamdeck-01` (VMID 220) at `10.10.20.70`, and mounts
one attached Elgato StreamDeck through the existing Core-owned Proxmox USB
export reconciler.

The display is intentionally passive. It has one page, one tile per Proxmox
host, green for a current healthy host and red for a down, unknown, or stale
host. Each tile shows bounded CPU and RAM percentages. Remaining keys are
blank. No key callbacks, active buttons, navigation, guest controls, or
configuration knobs are provided.

Enable it by configuring the typed module and binding the compiled raw USB
requirement to a stable physical parent port:

```yaml
modules:
  streamdeck:
    enabled: true
usb_exports:
  - module: streamdeck
    requirement: display
    port: "1-2.5"
    vendor_id: "0fd9"
    product_id: "006d"
```

For a real site, let Boetticher find the device rather than copying a Linux
device path into the configuration:

```text
boetticher hardware usb list --live --site ./my-boetticher
boetticher module configure streamdeck --site ./my-boetticher
boetticher deploy --site ./my-boetticher
```

The configure command presents compatible devices and records the selected
physical parent port in the existing `usb_exports` configuration. If you are
automating the change, use `--usb display=PORT` with the port reported by the
live listing. A missing, ambiguous, or incompatible device stops the operation
before infrastructure is changed.

The module depends on `monitoring` and reads Pulse through the existing
bounded `X-API-Token` plus mTLS contract. Core signs the service-client
certificate, installs the shared Pulse read token as an encrypted systemd
credential, and starts the service only after both gates pass. The appliance
image contains a statically linked Go service and the pinned native Linux
`matthewpi/streamdeck` library; it has no LXC-local package environment and
does not contain certificates, tokens, or USB device paths.

The external Pi-hosted StreamDeck companion remains a separate deployment
shape. This LXC module needs the physical USB attachment and the live mTLS and
display checks on the target Proxmox host; deploy reports the first concrete
failure and the next action if one of those checks does not pass.
