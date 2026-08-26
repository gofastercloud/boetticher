# Appliance images

Official appliance definitions use a pinned minimal Debian 13 boetticher base.
DNS and monitoring are LXC appliances; the managed firewall is a QEMU/KVM VM
because it is the network-security boundary.

The image definitions live under `images/`. They identify the base, release,
architecture, services, runtime configuration path, and persistent paths.
The module model records artifact name, module version, architecture, kind,
definition digest, and expected SHA-256. Deployment must verify the expected
artifact before use.

The ordinary Make targets validate the checked-in definitions:

```text
make image-base
make image-dns
make image-monitoring
make image-firewall
make images
```

Real image construction requires the supported build environment and remains
a qualification step. Build toolchains and caches do not belong in final
appliances. Release metadata should include a package manifest and SBOM.
