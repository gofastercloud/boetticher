#!/bin/sh
set -eu

# Linux-native appliance construction. The builder VM and a Linux controller
# execute this same script; macOS controllers intentionally stop before any
# image tooling is attempted.
target=${1:-images}
case "$target" in
  image-base|image-dns-blocky|image-dns-adguard|image-logging|image-monitoring|image-portal|image-firewall|images) ;;
  *) echo "unknown image target: $target" >&2; exit 2 ;;
esac

if [ "$(uname -s)" != Linux ]; then
  echo "HOLD: appliance construction requires the supported Linux builder environment; use boetticher bootstrap on macOS" >&2
  exit 2
fi

for tool in mmdebstrap tar zstd sha256sum curl chroot; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "HOLD: required Linux image-build tool is unavailable: $tool" >&2
    exit 2
  fi
done

output_root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
work_root=${BOETTICHER_IMAGE_WORK:-/tmp/boetticher-image-build}
mirror=${BOETTICHER_DEBIAN_MIRROR:-https://deb.debian.org/debian}
mkdir -p "$output_root" "$work_root"

cleanup() {
  if [ -n "${ACTIVE_ROOT:-}" ] && [ -d "$ACTIVE_ROOT" ]; then
    umount -R "$ACTIVE_ROOT/dev" 2>/dev/null || true
    umount -R "$ACTIVE_ROOT/proc" 2>/dev/null || true
    umount -R "$ACTIVE_ROOT/sys" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

rootfs_for() {
  printf '%s/%s-rootfs' "$work_root" "$1"
}

artifact_for() {
  printf '%s/%s/%s.tar.zst' "$output_root" "$1" "$1"
}

create_base_rootfs() {
  rootfs=$1
  rm -rf "$rootfs"
  mkdir -p "$rootfs"
  mmdebstrap --variant=minbase --architectures=amd64 \
    --include=systemd,systemd-sysv,systemd-journal-remote,ca-certificates,openssh-server,sudo,iproute2,iputils-ping,nftables,chrony,curl,jq,bash,python3 \
    trixie "$rootfs" "$mirror"
  mkdir -p "$rootfs/etc/boetticher" "$rootfs/usr/lib/boetticher" "$rootfs/run/boetticher/bootstrap"
  install -D -m 0755 images/base/first-boot/boetticher-first-boot.sh "$rootfs/usr/lib/boetticher/boetticher-first-boot.sh"
  install -D -m 0644 images/base/first-boot/boetticher-first-boot.service "$rootfs/etc/systemd/system/boetticher-first-boot.service"
  chroot "$rootfs" useradd --create-home --shell /bin/bash labadmin
  chroot "$rootfs" usermod --append --groups sudo labadmin
  chroot "$rootfs" passwd --lock labadmin
  printf '%s\n' 'labadmin ALL=(ALL) NOPASSWD:/usr/bin/systemctl, /usr/bin/install, /usr/bin/mkdir, /usr/bin/chown, /usr/bin/chmod, /usr/sbin/nft, /usr/sbin/kea-dhcp4, /usr/sbin/kea-dhcp-ddns' > "$rootfs/etc/sudoers.d/boetticher"
  chmod 0440 "$rootfs/etc/sudoers.d/boetticher"
  mkdir -p "$rootfs/etc/systemd/journald.conf.d"
  printf '%s\n' '[Journal]' 'SystemMaxUse=256M' 'RuntimeMaxUse=64M' > "$rootfs/etc/systemd/journald.conf.d/boetticher.conf"
  printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin prohibit-password' > "$rootfs/etc/ssh/sshd_config.d/boetticher.conf"
  rm -f "$rootfs/root/.ssh/authorized_keys" "$rootfs/home/labadmin/.ssh/authorized_keys"
  chroot "$rootfs" systemctl enable boetticher-first-boot.service
}

prepare_rootfs() {
  name=$1
  rootfs=$(rootfs_for "$name")
  if [ ! -d "$(rootfs_for boetticher-base)/etc" ]; then
    create_base_rootfs "$(rootfs_for boetticher-base)"
  fi
  rm -rf "$rootfs"
  cp -a "$(rootfs_for boetticher-base)" "$rootfs"
  ACTIVE_ROOT=$rootfs
  mkdir -p "$rootfs/var/lib/boetticher/identity/ssh" "$rootfs/etc/boetticher" "$rootfs/usr/lib/boetticher"
  printf '%s\n' "artifact=$name" > "$rootfs/usr/lib/boetticher/build-input.txt"
  printf '%s\n' "$rootfs"
}

install_packages() {
  rootfs=$1
  shift
  mount --bind /dev "$rootfs/dev"
  mount -t proc proc "$rootfs/proc"
  mount --rbind /sys "$rootfs/sys"
  chroot "$rootfs" apt-get update
  chroot "$rootfs" env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$@"
  chroot "$rootfs" apt-get clean
  rm -rf "$rootfs/var/lib/apt/lists/"*
  umount -R "$rootfs/dev" || true
  umount -R "$rootfs/proc" || true
  umount -R "$rootfs/sys" || true
}

package_lxc() {
  name=$1
  rootfs=$(rootfs_for "$name")
  destination="$output_root/$name"
  mkdir -p "$destination"
  ./scripts/smoke-appliance.sh "$name" "$rootfs"
  tar --numeric-owner --xattrs --acls -C "$rootfs" -cf - . | zstd -T0 -19 -o "$(artifact_for "$name")"
  tar -tf "$(artifact_for "$name")" > "$destination/package-manifest.txt"
  sha256sum "$(artifact_for "$name")" > "$destination/content.sha256"
}

build_base() {
  rootfs=$(rootfs_for boetticher-base)
  create_base_rootfs "$rootfs"
  package_lxc boetticher-base
}

build_dns_blocky() {
  rootfs=$(prepare_rootfs boetticher-dns-blocky)
  install_packages "$rootfs" pdns-server pdns-backend-sqlite3 sqlite3 chrony
  mkdir -p "$rootfs/usr/local/bin"
  archive="$work_root/blocky_v0.34.0_Linux_x86_64.tar.gz"
  curl --fail --location --silent --show-error --output "$archive" https://github.com/0xERR0R/blocky/releases/download/v0.34.0/blocky_v0.34.0_Linux_x86_64.tar.gz
  printf '%s  %s\n' 17b03f892346a160e9faf974ce68baae85fa4f2a94d7bf8ea52592a94be5eeb4 "$archive" | sha256sum --check --status
  tar -xOf "$archive" blocky > "$rootfs/usr/local/bin/blocky"
  chmod 0755 "$rootfs/usr/local/bin/blocky"
  chroot "$rootfs" useradd --system --home-dir /var/lib/blocky --create-home --shell /usr/sbin/nologin blocky
  cat > "$rootfs/etc/systemd/system/blocky.service" <<'EOF'
[Unit]
Description=Boetticher Blocky recursive resolver
After=network-online.target

[Service]
User=blocky
Group=blocky
ExecStart=/usr/local/bin/blocky --config /etc/blocky/config.yml
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blocky
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p "$rootfs/etc/blocky"
  package_lxc boetticher-dns-blocky
}

build_logging() {
  rootfs=$(prepare_rootfs boetticher-logging)
  install_packages "$rootfs" systemd-journal-remote
  package_lxc boetticher-logging
}

build_monitoring() {
  rootfs=$(prepare_rootfs boetticher-monitoring)
  install_packages "$rootfs" postgresql nginx zabbix-server-pgsql zabbix-frontend-php zabbix-nginx-conf zabbix-agent2
  package_lxc boetticher-monitoring
}

build_portal() {
  rootfs=$(prepare_rootfs boetticher-portal)
  install_packages "$rootfs" nginx
  package_lxc boetticher-portal
}

build_firewall() {
  echo "HOLD: a pinned bootable Debian 13 cloud-image input and VM customization toolchain are required for firewall QCOW2 construction" >&2
  return 2
}

case "$target" in
  image-base) build_base ;;
  image-dns-blocky) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_dns_blocky ;;
  image-logging) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_logging ;;
  image-monitoring) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_monitoring ;;
  image-portal) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_portal ;;
  image-dns-adguard) echo "HOLD: AdGuard provider qualification is outside the default Blocky readiness tranche" >&2; exit 2 ;;
  image-firewall) build_firewall ;;
  images)
    build_base
    build_dns_blocky
    build_logging
    build_monitoring
    build_portal
    build_firewall
    ;;
esac
