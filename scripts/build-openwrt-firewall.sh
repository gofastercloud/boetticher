#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: build-openwrt-firewall.sh OUTPUT.img MANAGEMENT_IPV4 NETMASK HOME_GATEWAY CONTROLLER_IPV4" >&2
    exit 2
fi

output=$1
management_address=$2
management_netmask=$3
management_gateway=$4
controller_address=$5
password_hash=$(cat)
log() {
    printf '%s\n' "OpenWrt image build: $1" >&2
}
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
mkdir -p "$work/tmp"
TMPDIR="$work/tmp"
export TMPDIR

log "downloading pinned ImageBuilder"
curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error --output "$work/imagebuilder.tar.zst" "$builder_url"
log "extracting pinned ImageBuilder"
tar --zstd -xf "$work/imagebuilder.tar.zst" -C "$work"
builder=$(find "$work" -mindepth 1 -maxdepth 1 -type d -name 'openwrt-imagebuilder-*' -print -quit)
test -n "$builder"
mkdir -p "$builder/tmp"
log "verifying ImageBuilder revision"
grep -F "REVISION:=${builder_revision}" "$builder/include/version.mk" >/dev/null
test "$(uname -m)" = x86_64

files="$work/files"
mkdir -p "$files/etc/uci-defaults" "$files/usr/share/rpcd/acl.d"
cat >"$files/etc/uci-defaults/99-boetticher-firewall" <<EOF
#!/bin/sh
set -eu

uci -q delete network.lan || true
uci -q delete network.wan || true
uci -q delete network.wan6 || true
uci -q set network.boetticher_home='interface'
uci -q set network.boetticher_home.device='eth0'
uci -q set network.boetticher_home.proto='static'
uci -q set network.boetticher_home.ipaddr='$management_address'
uci -q set network.boetticher_home.netmask='$management_netmask'
uci -q set network.boetticher_home.gateway='$management_gateway'
uci -q set network.boetticher_home.delegate='0'
uci -q set network.boetticher_home.ip6assign='0'
uci -q delete dhcp.lan || true
uci -q delete dhcp.wan || true
uci -q set dhcp.boetticher_home='dhcp'
uci -q set dhcp.boetticher_home.interface='boetticher_home'
uci -q set dhcp.boetticher_home.ignore='1'
uci -q set dhcp.boetticher_home.ra='disabled'
uci -q set dhcp.boetticher_home.dhcpv6='disabled'
uci -q set dhcp.boetticher_home.ndp='disabled'
uci -q set rpcd.boetticher='login'
uci -q set rpcd.boetticher.username='boetticher'
uci -q set rpcd.boetticher.password='$password_hash'
uci -q delete rpcd.boetticher.read || true
uci -q delete rpcd.boetticher.write || true
uci -q add_list rpcd.boetticher.read='boetticher'
uci -q add_list rpcd.boetticher.write='boetticher'
uci -q commit network
uci -q commit dhcp
uci -q commit rpcd
uci -q delete firewall.lan || true
uci -q delete firewall.wan || true
uci -q delete firewall.wan6 || true
uci -q set firewall.boetticher_home_wan='zone'
uci -q set firewall.boetticher_home_wan.name='home_wan'
uci -q set firewall.boetticher_home_wan.input='DROP'
uci -q set firewall.boetticher_home_wan.output='ACCEPT'
uci -q set firewall.boetticher_home_wan.forward='DROP'
uci -q set firewall.boetticher_home_wan.family='ipv4'
uci -q set firewall.boetticher_home_wan.masq='1'
uci -q set firewall.boetticher_home_wan.mtu_fix='1'
uci -q add_list firewall.boetticher_home_wan.network='boetticher_home'
uci -q set firewall.boetticher_allow_home_api='rule'
uci -q set firewall.boetticher_allow_home_api.name='Boetticher Controller management API'
uci -q set firewall.boetticher_allow_home_api.src='home_wan'
uci -q set firewall.boetticher_allow_home_api.src_ip='$controller_address/32'
uci -q set firewall.boetticher_allow_home_api.proto='tcp'
uci -q set firewall.boetticher_allow_home_api.dest_port='443'
uci -q set firewall.boetticher_allow_home_api.family='ipv4'
uci -q set firewall.boetticher_allow_home_api.target='ACCEPT'
uci -q commit firewall
uci -q set uhttpd.main.redirect_https='1'
uci -q set uhttpd.main.listen_http='0.0.0.0:80'
uci -q set uhttpd.main.listen_https='0.0.0.0:443'
uci -q commit uhttpd
px5g selfsigned -days 3650 -newkey rsa:2048 -keyout /etc/uhttpd.key.new -out /etc/uhttpd.crt.new -subj /C=AU/ST=NSW/L=Sydney/O=Boetticher/CN=boetticher-firewall -addext subjectAltName=DNS:boetticher-firewall
mv /etc/uhttpd.key.new /etc/uhttpd.key
mv /etc/uhttpd.crt.new /etc/uhttpd.crt
chmod 600 /etc/uhttpd.key
chmod 644 /etc/uhttpd.crt
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
        "network.interface": ["dump"],
        "service": ["list"]
      },
      "uci": {
        "network": ["read"],
        "firewall": ["read"]
      }
    },
    "write": {
      "ubus": {
        "uci": ["set", "delete", "commit", "apply"]
      },
      "uci": {
        "network": ["read", "write"],
        "firewall": ["read", "write"]
      }
    }
  }
}
EOF

packages='uhttpd uhttpd-mod-ubus rpcd rpcd-mod-file rpcd-mod-iwinfo px5g-mbedtls ca-bundle firewall4 nftables qemu-ga'
log "checking ImageBuilder host prerequisites"
make -C "$builder" TOPDIR="$builder" -f include/prereq-build.mk prereq IB=1 V=s
touch "$builder/staging_dir/host/.prereq-build"
log "building generic x86/64 image"
make -C "$builder" image PROFILE=generic PACKAGES="$packages" FILES="$files"
log "locating generic ext4 combined image"
source_image=$(find "$builder/bin/targets/x86/64" -type f -name '*generic-ext4-combined.img.gz' -print -quit)
test -n "$source_image"
mkdir -p "$(dirname "$output")"
temporary="$output.tmp"
trap 'rm -f "$temporary"; rm -rf "$work"' EXIT HUP INT TERM
gzip -dc "$source_image" >"$temporary"
chmod 600 "$temporary"
mv -f "$temporary" "$output"
printf '%s\n' "$builder_revision" >/dev/null
