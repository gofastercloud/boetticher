# Raspberry Pi base configuration

This directory is the shared host baseline for the ARM64 Pi. Display-specific
files live under `pi/kiosk/` and `pi/streamdeck/`.

The baseline is intended to preserve the existing Debian 13 installation and
its rollback media while keeping host changes explicit and recoverable:

- `config/gpio-fan.conf` records the kernel-managed GPIO14 fan profile: 60 C
  on and 45 C off. Verify the transistor/controller and polarity before
  applying it. The overlay and trip point are host observations; recheck them
  on the Pi before changing its firmware.
- `config/sshd/60-boetticher.conf.example` is the key-only SSH policy. Confirm
  a working non-root administrative key and the recovery path before enabling
  it; root access is restricted to public-key authentication.
- `config/systemd/journald.conf` bounds local journal retention.
- `config/apt/20auto-upgrades` enables the Debian unattended-upgrades timer
  once the package is installed.

The remaining baseline checks are operational rather than secrets or desired
state: current Debian security updates, time synchronisation, `fstrim.timer`,
SMART support for the SSD, disabled unused services, and a tested recovery
boot. Credentials and private keys stay outside this directory.

## Live gates

The recorded Pi network observation is Ethernet DHCP at `10.10.20.50` and
Wi-Fi at `192.168.4.36`; recheck both before making a network change. Wi-Fi
must remain available as rollback until Ethernet has been independently
verified after reboot. VLAN 20 static addressing remains unavailable until the
switch/network assignment exists.

Before applying key-only SSH or storage-related changes, capture:

```sh
hostnamectl
ip -4 address
ip route
timedatectl show --property=NTPSynchronized --value
systemctl is-enabled fstrim.timer
systemctl is-active unattended-upgrades.service
lsblk -o NAME,MODEL,SERIAL,SIZE,FSTYPE,MOUNTPOINTS
```

Never infer SSD identity from `/dev/sdX`; use the exact model/serial and
`/dev/disk/by-id/` path for any destructive storage operation.
