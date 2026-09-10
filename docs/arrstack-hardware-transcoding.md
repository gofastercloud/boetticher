# Arrstack hardware transcoding

The media guest uses Intel VA-API only when the guest already exposes
`/dev/dri/renderD128`. The installed Compose contract passes that render node
to Jellyfin, adds the guest `render`/`video` group IDs, and writes Jellyfin's
VA-API encoding configuration. The Controller probes the character device
before installation and reports a hardware-transcoding `HOLD` if it is absent;
it never presents software transcoding as GPU acceleration.

The remaining prerequisite is physical Proxmox configuration: the Intel iGPU
must be passed through to VM 290 and the guest must boot with `/dev/dri` and
the expected render node. This slice does not change Proxmox PCI assignment,
kernel/IOMMU settings, or live systems. After passthrough, rerun the normal
media apply and verify Jellyfin's Dashboard playback reports VA-API.
