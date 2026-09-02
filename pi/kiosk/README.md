# Raspberry Pi kiosk

This directory contains the files installed on the Raspberry Pi HDMI kiosk.
Shared host configuration, including the GPIO14 fan profile and hardening
guidance, lives in `pi/base/`. The kiosk is deliberately independent of the
StreamDeck process in `pi/streamdeck/` so either display can be recovered
without taking the other one down.

## Runtime

- `visualizer/index.html` is the low-power CSS plus 2D-canvas visualizer. It
  uses the installed OCR-A font, keeps the Matrix layer at a bounded cadence,
  and displays local Pi telemetry and browser frame cadence.
- `libexec/pulse-kiosk-stats` publishes an atomic, non-secret `stats.js` file
  from `/proc`, `/sys`, and `df`.
- `systemd/pulse-kiosk-stats.service` and `.timer` refresh that file roughly
  every two seconds.
- `systemd/pulse-kiosk.service` runs the browser as the non-root `kiosk` user
  under Cage/seatd.
- The Ansible kiosk setup enables unattended APT upgrades, bounds persistent
  journald storage, and configures log2ram to keep `/var/log` in RAM with a
  daily disk sync.
- The pinned ARM64 Pulse host agent runs as a separate root-owned systemd
  service with its report token supplied through an encrypted systemd
  credential; it reports host telemetry only and does not self-update.
- `systemd/pulse-kiosk.service.d/20-pulse-dashboard.conf` selects the kiosk's
  dedicated mTLS client certificate for the Pulse origin. The private key
  remains in the Pi's NSS database and is never copied into this repository.
- `pulse-refresh-extension/` contains a permission-free Chromium content
  script scoped to the Pulse origin that reloads the kiosk page every 30
  seconds.

The screen is the HDMI-connected DUEX LITE display. The current network
bootstrap uses DHCP; Ethernet must be proven before Wi-Fi is disabled, and the
eventual VLAN 20 static assignment remains a network-change-window operation.

## Installing the kiosk files

Run as root on the Pi from this directory, after checking the target paths:

```sh
install -D -o kiosk -g kiosk -m 0644 visualizer/index.html /home/kiosk/visualizer/index.html
install -D -o root -g root -m 0755 libexec/pulse-kiosk-stats /usr/local/libexec/pulse-kiosk-stats
install -D -o root -g root -m 0644 systemd/pulse-kiosk-stats.service /etc/systemd/system/pulse-kiosk-stats.service
install -D -o root -g root -m 0644 systemd/pulse-kiosk-stats.timer /etc/systemd/system/pulse-kiosk-stats.timer
install -D -o root -g root -m 0644 systemd/pulse-kiosk.service /etc/systemd/system/pulse-kiosk.service
install -D -o root -g root -m 0644 systemd/pulse-kiosk.service.d/20-pulse-dashboard.conf /etc/systemd/system/pulse-kiosk.service.d/20-pulse-dashboard.conf
install -D -o kiosk -g kiosk -m 0644 pulse-refresh-extension/manifest.json /home/kiosk/pulse-refresh-extension/manifest.json
install -D -o kiosk -g kiosk -m 0644 pulse-refresh-extension/reload.js /home/kiosk/pulse-refresh-extension/reload.js
systemctl daemon-reload
systemctl enable pulse-kiosk.service
systemctl enable --now pulse-kiosk-stats.timer
systemctl restart pulse-kiosk.service
```

Do not put credentials in the visualizer or `stats.js`; this path is local
telemetry only.
