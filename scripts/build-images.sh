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

for tool in mmdebstrap tar zstd sha256sum curl chroot go; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "HOLD: required Linux image-build tool is unavailable: $tool" >&2
    exit 2
  fi
done

output_root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
work_root=${BOETTICHER_IMAGE_WORK:-/tmp/boetticher-image-build}
mirror=${BOETTICHER_DEBIAN_MIRROR:-https://deb.debian.org/debian}
powerdns_key_url=https://repo.powerdns.com/FD380FBB-pub.asc
powerdns_key_sha256=efeb5b1451c76de1dac8eefaddba5af5549e8fd93484728744ea7b4923decae8
powerdns_repo=https://repo.powerdns.com/debian
powerdns_suite=trixie-auth-49
powerdns_package_version=4.9.17-1pdns.trixie
zabbix_release_url=https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-release/zabbix-release_7.0-5+debian13_all.deb
zabbix_release_sha256=4a926b8815cdefddc31558fe622676730a3987610f75d5af0d4024809d21dd43
zabbix_package_version=1:7.0.30-1+debian13
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
	name=$1
	version=1.0.0
	if [ "$name" = boetticher-base ]; then
		version=0.3.1
	fi
	printf '%s/%s/%s-%s-amd64.tar.zst' "$output_root" "$name" "$name" "$version"
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

install_powerdns() {
  rootfs=$1
  key="$work_root/powerdns-auth-49-pub.asc"
  if [ ! -f "$key" ]; then
    curl --fail --location --silent --show-error --output "$key" "$powerdns_key_url"
  fi
  printf '%s  %s\n' "$powerdns_key_sha256" "$key" | sha256sum --check --status
  install -D -m 0644 "$key" "$rootfs/etc/apt/keyrings/auth-49-pub.asc"
  printf '%s\n' "deb [signed-by=/etc/apt/keyrings/auth-49-pub.asc] $powerdns_repo $powerdns_suite main" > "$rootfs/etc/apt/sources.list.d/pdns.list"
  printf '%s\n' 'Package: pdns-*' 'Pin: origin repo.powerdns.com' 'Pin-Priority: 600' > "$rootfs/etc/apt/preferences.d/auth-49"

  install_packages "$rootfs" \
    "pdns-server=$powerdns_package_version" \
    "pdns-backend-sqlite3=$powerdns_package_version" \
    sqlite3

  installed_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' pdns-server)
  if [ "$installed_version" != "$powerdns_package_version" ]; then
    echo "HOLD: unexpected PowerDNS package version: $installed_version" >&2
    return 2
  fi
  backend_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' pdns-backend-sqlite3)
  if [ "$backend_version" != "$powerdns_package_version" ]; then
    echo "HOLD: unexpected PowerDNS SQLite backend version: $backend_version" >&2
    return 2
  fi
  if ! chroot "$rootfs" /usr/sbin/pdns_server --version 2>&1 | grep -q '4\.9\.17'; then
    echo "HOLD: PowerDNS executable is not the qualified 4.9.17 release" >&2
    return 2
  fi

  rm -f "$rootfs/etc/apt/sources.list.d/pdns.list" \
    "$rootfs/etc/apt/preferences.d/auth-49" \
    "$rootfs/etc/apt/keyrings/auth-49-pub.asc"
}

install_zabbix() {
  rootfs=$1
  release="$work_root/zabbix-release_7.0-5+debian13_all.deb"
  if [ ! -f "$release" ]; then
    curl --fail --location --silent --show-error --output "$release" "$zabbix_release_url"
  fi
  printf '%s  %s\n' "$zabbix_release_sha256" "$release" | sha256sum --check --status
  install -D -m 0644 "$release" "$rootfs/tmp/zabbix-release.deb"
  mount --bind /dev "$rootfs/dev"
  mount -t proc proc "$rootfs/proc"
  mount --rbind /sys "$rootfs/sys"
  chroot "$rootfs" dpkg --install /tmp/zabbix-release.deb
  umount -R "$rootfs/dev" || true
  umount -R "$rootfs/proc" || true
  umount -R "$rootfs/sys" || true
  install_packages "$rootfs" \
    "zabbix-server-pgsql=$zabbix_package_version" \
    "zabbix-frontend-php=$zabbix_package_version" \
    "zabbix-nginx-conf=$zabbix_package_version" \
    "zabbix-agent2=$zabbix_package_version" \
    postgresql nginx
  installed_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' zabbix-server-pgsql)
  if [ "$installed_version" != "$zabbix_package_version" ]; then
    echo "HOLD: unexpected Zabbix server package version: $installed_version" >&2
    return 2
  fi
  if ! chroot "$rootfs" /usr/sbin/zabbix_server --version 2>&1 | grep -q '7\.0\.30'; then
    echo "HOLD: Zabbix executable is not the qualified 7.0.30 release" >&2
    return 2
  fi
  chroot "$rootfs" dpkg --purge zabbix-release >/dev/null 2>&1 || true
  rm -f "$rootfs/tmp/zabbix-release.deb"
}

package_lxc() {
  name=$1
  rootfs=$(rootfs_for "$name")
  destination="$output_root/$name"
  mkdir -p "$destination"
  ./scripts/smoke-appliance.sh "$name" "$rootfs"
  chroot "$rootfs" dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort > "$destination/package-manifest.txt"
  tar --numeric-owner --xattrs --acls -C "$rootfs" -cf - . | zstd -T0 -19 -o "$(artifact_for "$name")"
  sha256sum "$(artifact_for "$name")" > "$destination/content.sha256"
}

build_base() {
  rootfs=$(rootfs_for boetticher-base)
  create_base_rootfs "$rootfs"
  package_lxc boetticher-base
}

build_dns_blocky() {
  rootfs=$(prepare_rootfs boetticher-dns-blocky)
  install_powerdns "$rootfs"
  install_packages "$rootfs" chrony
  mkdir -p "$rootfs/usr/local/bin"
  archive="$work_root/blocky_v0.34.0_Linux_x86_64.tar.gz"
  curl --fail --location --silent --show-error --output "$archive" https://github.com/0xERR0R/blocky/releases/download/v0.34.0/blocky_v0.34.0_Linux_x86_64.tar.gz
  printf '%s  %s\n' 17b03f892346a160e9faf974ce68baae85fa4f2a94d7bf8ea52592a94be5eeb4 "$archive" | sha256sum --check --status
  tar -xOf "$archive" blocky > "$rootfs/usr/local/bin/blocky"
  chmod 0755 "$rootfs/usr/local/bin/blocky"
  blocky_config="$work_root/blocky-config.yml"
  go run ./cmd/render-blocky-config > "$blocky_config"
  install -D -m 0644 "$blocky_config" "$rootfs/tmp/blocky-config.yml"
  if ! chroot "$rootfs" /usr/local/bin/blocky validate --config /tmp/blocky-config.yml; then
    echo "HOLD: pinned Blocky rejected the canonical generated configuration" >&2
    return 2
  fi
  rm -f "$rootfs/tmp/blocky-config.yml"
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
  install_zabbix "$rootfs"
  package_lxc boetticher-monitoring
}

build_portal() {
  rootfs=$(prepare_rootfs boetticher-portal)
  install_packages "$rootfs" nginx
  package_lxc boetticher-portal
}

build_firewall() {
  for tool in qemu-img virt-customize virt-cat sha512sum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "HOLD: required firewall VM-image tool is unavailable: $tool" >&2
      return 2
    fi
  done
  destination="$output_root/boetticher-firewall"
  mkdir -p "$destination"
  input="$work_root/debian-13-genericcloud-amd64-20260327-2429.qcow2"
  if [ ! -f "$input" ]; then
    curl --fail --location --silent --show-error --output "$input" https://cloud.debian.org/images/cloud/trixie/20260327-2429/debian-13-genericcloud-amd64-20260327-2429.qcow2
  fi
  printf '%s  %s\n' 09559ec27d263997827dd8cddf76e97ea8e0f1803380aa501ea7eaa4b4968cd76ffef4ec7eb07ef1a9ccbeb0925a5020492ea9ed53eb167d62f3a2285039912c "$input" | sha512sum --check --status
  image="$destination/boetticher-firewall-1.0.0-amd64.qcow2"
  cp "$input" "$image"
  virt-customize -a "$image" \
    --install nftables,kea-dhcp4-server,kea-dhcp-ddns-server,dnsmasq,chrony,openssh-server,sudo,cloud-init,systemd-journal-remote,zabbix-agent2,curl,jq,openssl \
    --mkdir /etc/boetticher,/usr/lib/boetticher,/var/lib/boetticher/identity/ssh \
    --upload images/base/first-boot/boetticher-first-boot.sh:/usr/lib/boetticher/boetticher-first-boot.sh \
    --upload images/base/first-boot/boetticher-first-boot.service:/etc/systemd/system/boetticher-first-boot.service \
    --upload images/firewall/nocloud/network-config:/etc/boetticher/nocloud-network-config \
    --write /etc/systemd/journald.conf.d/boetticher.conf:'[Journal]\nSystemMaxUse=256M\nRuntimeMaxUse=64M\n' \
    --write /etc/sysctl.d/boetticher-forwarding.conf:'net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\n' \
    --run-command 'useradd --create-home --shell /bin/bash labadmin || true' \
    --run-command 'usermod --append --groups sudo labadmin' \
    --run-command 'passwd --lock labadmin' \
    --run-command 'printf "%s\\n" "labadmin ALL=(ALL) NOPASSWD:/usr/bin/systemctl, /usr/sbin/nft, /usr/sbin/kea-dhcp4, /usr/sbin/kea-dhcp-ddns" > /etc/sudoers.d/boetticher && chmod 0440 /etc/sudoers.d/boetticher' \
    --run-command 'dpkg-query -W -f="${binary:Package}\\t${Version}\\n" | sort > /var/lib/boetticher/package-manifest.txt' \
    --run-command 'systemctl enable boetticher-first-boot.service || true' \
    --run-command 'systemctl disable --now systemd-networkd-wait-online.service || true'
  sha256sum "$image" > "$destination/content.sha256"
  virt-cat -a "$image" /var/lib/boetticher/package-manifest.txt > "$destination/package-manifest.txt"
  ./scripts/smoke-firewall-image.sh "$image"
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
