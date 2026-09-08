#!/bin/sh
# Fixed Host-native Tailnet template builder; no private site or credentials.
set -eu
[ "$(id -u)" = 0 ] || { echo "Tailnet image construction requires the enrolled Host root" >&2; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo "Tailnet image construction requires x86_64" >&2; exit 1; }
cache=/var/lib/boetticher/tailnet-image
version=1.102.3
digest=88e1b0319da94a52ea409a1a5935e4e7215065a25cd99bc509b6dcbb73737fae
for path in /var/lib/boetticher "$cache"; do
 [ ! -L "$path" ] || { echo "Refusing symlinked image cache" >&2; exit 1; }
done
install -d -m 0700 "$cache"
input=$(sha256sum "$0" | cut -d ' ' -f 1)
if [ -f "$cache/input.sha256" ] && [ "$(cat "$cache/input.sha256")" = "$input" ] &&
 [ -f "$cache/template.sha256" ] && (cd "$cache" && sha256sum -c template.sha256 >/dev/null 2>&1) &&
 [ "$(sha256sum "$cache/tailscale.deb" | cut -d ' ' -f 1)" = "$digest" ]; then
 exit 0
fi
for tool in mmdebstrap zstd curl; do
 if ! command -v "$tool" >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends mmdebstrap zstd curl ca-certificates debian-archive-keyring
  break
 fi
done
work=$(mktemp -d /var/tmp/boetticher-tailnet-build.XXXXXX)
cleanup() {
 case "$work" in /var/tmp/boetticher-tailnet-build.*) rm -rf -- "$work";; *) exit 1;; esac
}
trap cleanup EXIT HUP INT TERM
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 180 \
 "https://pkgs.tailscale.com/stable/debian/pool/tailscale_${version}_amd64.deb" -o "$work/tailscale.deb"
printf '%s  %s\n' "$digest" "$work/tailscale.deb" | sha256sum -c -
mmdebstrap --variant=minbase --architectures=amd64 \
 --aptopt=Acquire::Check-Valid-Until=false --aptopt=Acquire::Retries=3 \
 --include=systemd,systemd-sysv,dbus,ca-certificates,iproute2,iptables,ifupdown,dhcpcd-base,nftables,bind9-dnsutils,procps \
 trixie "$work/rootfs" https://snapshot.debian.org/archive/debian/20260825T000000Z/
printf '#!/bin/sh\nexit 101\n' > "$work/rootfs/usr/sbin/policy-rc.d"
chmod 0755 "$work/rootfs/usr/sbin/policy-rc.d"
cp "$work/tailscale.deb" "$work/rootfs/tmp/tailscale.deb"
chroot "$work/rootfs" dpkg -i /tmp/tailscale.deb
# shellcheck disable=SC2016 # dpkg-query requires its literal format expression.
[ "$(chroot "$work/rootfs" dpkg-query -W -f='${Version}' tailscale)" = "$version" ]
rm -f "$work/rootfs/tmp/tailscale.deb" "$work/rootfs/usr/sbin/policy-rc.d"
chroot "$work/rootfs" systemctl mask tailscaled
install -d "$work/rootfs/etc/sysctl.d" "$work/rootfs/etc/boetticher"
printf 'net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\nnet.ipv6.conf.default.forwarding=0\n' > "$work/rootfs/etc/sysctl.d/99-boetticher-tailnet.conf"
printf 'tailnet-v1\n' > "$work/rootfs/etc/boetticher/tailnet-image"
: > "$work/rootfs/etc/machine-id"
tar --numeric-owner --xattrs --acls -C "$work/rootfs" -cf "$work/rootfs.tar" .
zstd -T0 -3 "$work/rootfs.tar" -o "$work/rootfs.tar.zst"
cp "$work/tailscale.deb" "$cache/tailscale.deb"
mv "$work/rootfs.tar.zst" "$cache/rootfs.tar.zst"
(cd "$cache" && sha256sum rootfs.tar.zst > template.sha256)
printf '%s\n' "$input" > "$cache/input.sha256"
