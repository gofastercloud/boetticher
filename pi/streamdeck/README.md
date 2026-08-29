# Raspberry Pi StreamDeck monitor

This is the external Pi-hosted StreamDeck companion for Boetticher. It uses a
read-only Pulse data shape, bounded HTTP client, exact StreamDeck hardware
selection, and mTLS credential contract, and runs directly on the ARM64 Pi.
The physical StreamDeck is owned by this companion; Boetticher does not deploy
a second StreamDeck appliance or LXC guest.

The default configuration is intentionally `screensaver_only: true`. It
renders an animated circuit-board/Matrix-style display using the same dark
navy, cyan, green, and OCR-A visual language as the HDMI kiosk. It does not
look for, create, or accept a Pulse token in this mode.

Live statistics are a separate, explicit gate. To enable them later, install
the controller-issued client certificate and CA plus a dedicated read-only
Pulse token at the Pi-local `/etc/boetticher/pi/pulse-token` source path
(root-owned and mode `0600`). The shipped systemd unit exposes that file only
through `LoadCredential=`. Set `screensaver_only` to `false` and configure the
real Pulse URL. No token, private key, or certificate value belongs in this
repository or in command-line arguments.

The recorded device observation (verify it again before deployment) is:

- Elgato Stream Deck original V2, USB `0fd9:006d`
- serial `AL33J2C14717`
- 15 keys, rendered at 72x72 pixels

The udev rule is an allow-list for that VID/PID/serial and the service runs as
the unprivileged `streamdeck` user. The example leaves the application serial
probe empty because this StreamDeck firmware/HIDAPI combination is reliably
opened through libusb but does not reliably answer the optional serial feature
report; the exact serial is enforced before the process can access the device.

## Local checks

From the repository root:

```sh
uv run --project pi/streamdeck --with pytest --with Pillow --with httpx pytest pi/streamdeck/tests
```

The source package is deliberately standalone because this companion is
external to the Proxmox cluster. The Pi adapter must not be mistaken for proof
of the ARM64 PBS or Proxmox appliance path.

## Pi deployment outline

Use approved Debian packages for Python, Pillow, HTTPX, and HIDAPI. Install
the pinned StreamDeck source dependency from `requirements-runtime.txt` into
the Pi virtual environment, copy `src/` to `/opt/boetticher-pi-streamdeck/`,
then install the service and udev rule. Reload udev and systemd, reconnect the
deck if necessary, and verify the service can update all 15 keys.

The service is screensaver-only until mTLS is ready. Physical key readability,
detach/reconnect recovery, and real Pulse access remain `NOT TESTED` until the
corresponding live checks pass.
