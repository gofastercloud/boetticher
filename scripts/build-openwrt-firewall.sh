#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: build-openwrt-firewall.sh OUTPUT.img MANAGEMENT_IPV4" >&2
    exit 2
fi

output=$1
management_address=$2
password_hash=$(cat)
case "$management_address" in
    *[!0-9.]*|.*|*.) echo "invalid management address" >&2; exit 2 ;;
esac
case "$password_hash" in
    \$6\$*) ;;
    *) echo "password hash must use SHA-512 crypt" >&2; exit 2 ;;
esac

version=25.12.5
builder_revision=r33051-f5dae5ece4
builder_url="https://downloads.openwrt.org/releases/${version}/targets/x86/64/openwrt-imagebuilder-${version}-x86-64.Linux-x86_64.tar.zst"
work=$(mktemp -d /tmp/boetticher-openwrt-image.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM

curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error --output "$work/imagebuilder.tar.zst" "$builder_url"
tar --zstd -xf "$work/imagebuilder.tar.zst" -C "$work"
builder=$(find "$work" -mindepth 1 -maxdepth 1 -type d -name 'openwrt-imagebuilder-*' -print -quit)
test -n "$builder"
grep -F "${builder_revision}" "$builder/Makefile" >/dev/null
test "$(uname -m)" = x86_64

files="$work/files"
mkdir -p "$files/etc/uci-defaults" "$files/usr/share/rpcd/acl.d"
cat >"$files/etc/uci-defaults/99-boetticher-firewall" <<EOF
#!/bin/sh
set -eu

uci -q set network.lan.proto='static'
uci -q set network.lan.ipaddr='$management_address'
uci -q set network.lan.netmask='255.255.255.0'
uci -q set network.lan.ip6assign='0'
uci -q set dhcp.lan.ignore='1'
uci -q set dhcp.lan.ra='disabled'
uci -q set dhcp.lan.dhcpv6='disabled'
uci -q set dhcp.lan.ndp='disabled'
uci -q set rpcd.boetticher='login'
uci -q set rpcd.boetticher.username='boetticher'
uci -q set rpcd.boetticher.password='$password_hash'
uci -q set rpcd.boetticher.acl='boetticher'
uci -q commit network
uci -q commit dhcp
uci -q commit rpcd
uci -q set uhttpd.main.redirect_https='1'
uci -q set uhttpd.main.listen_http='0.0.0.0:80'
uci -q set uhttpd.main.listen_https='0.0.0.0:443'
uci -q commit uhttpd
/etc/init.d/uhttpd enable
/etc/init.d/qemu-ga enable
/etc/init.d/uhttpd restart || true
exit 0
EOF
chmod 700 "$files/etc/uci-defaults/99-boetticher-firewall"
cat >"$files/usr/share/rpcd/acl.d/boetticher.json" <<'EOF'
{
  "boetticher": {
    "description": "Boetticher firewall capability management",
    "read": {
      "ubus": {
        "uci": ["get"],
        "network.interface": ["dump"]
      }
    },
    "write": {
      "ubus": {
        "uci": ["add", "set", "add_list", "delete", "commit", "apply"]
      }
    }
  }
}
EOF

packages='uhttpd uhttpd-mod-ubus rpcd rpcd-mod-file rpcd-mod-iwinfo px5g-mbedtls ca-bundle firewall4 nftables qemu-ga'
make -C "$builder" image PROFILE=generic PACKAGES="$packages" FILES="$files" >/dev/null
source_image=$(find "$builder/bin/targets/x86/64" -type f -name '*combined-ext4.img.gz' -print -quit)
test -n "$source_image"
mkdir -p "$(dirname "$output")"
temporary="$output.tmp"
trap 'rm -f "$temporary"; rm -rf "$work"' EXIT HUP INT TERM
gzip -dc "$source_image" >"$temporary"
chmod 600 "$temporary"
mv -f "$temporary" "$output"
printf '%s\n' "$builder_revision" >/dev/null
