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

The module depends on `monitoring` and reads Pulse through the existing
bounded `X-API-Token` plus mTLS contract. Core signs the service-client
certificate, installs the shared Pulse read token as an encrypted systemd
credential, and starts the service only after both gates pass. The appliance
image contains the pinned StreamDeck library, Pillow renderer, httpx client,
and `libhidapi-libusb0`; it does not contain certificates, tokens, or USB
device paths.

The external Pi-hosted StreamDeck companion remains a separate deployment
shape. This LXC module is source-tested and artifact-wired here; physical USB
attachment, deployed mTLS, and the live display journey remain `NOT TESTED`
until performed on the target Proxmox host and hardware.
