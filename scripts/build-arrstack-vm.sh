#!/bin/sh
set -eu

# This builder runs on the enrolled x86 Proxmox Host.  The cloud image is
# pinned to the same qualified Debian input used by the other amd64 QEMU
# appliance and is verified before any customization or import.
output=${1:-/var/lib/boetticher/arrstack-image/debian-13-arrstack-amd64.qcow2}
image_name=debian-13-genericcloud-amd64-20260327-2429.qcow2
image_url=https://cloud.debian.org/images/cloud/trixie/20260327-2429/$image_name
image_sha512=09559ec27d263997827dd8cddf76e97ea8e0f1803380aa501ea7eaa4b4968cd76ffef4ec7eb07ef1a9ccbeb0925a5020492ea9ed53eb167d62f3a2285039912c

for tool in curl qemu-img virt-customize sha512sum install mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required image builder tool is unavailable: $tool" >&2; exit 2; }
done
case "$output" in
  /var/lib/boetticher/arrstack-image/debian-13-arrstack-amd64.qcow2) ;;
  *) echo "refusing an unexpected arrstack image output path" >&2; exit 2 ;;
esac

stage=$(mktemp -d /var/tmp/boetticher-arrstack-image.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
input="$stage/$image_name"
curl --fail --location --proto '=https' --tlsv1.2 --output "$input" "$image_url"
printf '%s  %s\n' "$image_sha512" "$input" | sha512sum --check --status

customized="$stage/debian-13-arrstack-amd64.qcow2"
cp -- "$input" "$customized"
policy="$stage/boetticher-arrstack-firewall"
cat >"$policy" <<'EOF'
#!/bin/sh
set -eu
sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
nft add table inet boetticher_arrstack 2>/dev/null || true
nft 'add chain inet boetticher_arrstack input { type filter hook input priority 0; policy drop; }' 2>/dev/null || true
nft 'add chain inet boetticher_arrstack forward { type filter hook forward priority -100; policy drop; }' 2>/dev/null || true
nft flush chain inet boetticher_arrstack input
nft flush chain inet boetticher_arrstack forward
nft add rule inet boetticher_arrstack input iifname "lo" accept
nft add rule inet boetticher_arrstack input ct state established,related accept
nft add rule inet boetticher_arrstack input ip saddr { 10.10.30.0/24, 10.10.5.10 } tcp dport 443 accept
nft add rule inet boetticher_arrstack input tcp dport 35796 accept
nft add rule inet boetticher_arrstack input udp dport 35796 accept
nft add rule inet boetticher_arrstack forward ct state established,related accept
nft add rule inet boetticher_arrstack forward iifname "br-*" oifname "br-*" accept
nft add rule inet boetticher_arrstack forward iifname "br-*" ip daddr 10.10.20.1 accept
nft add rule inet boetticher_arrstack forward tcp dport 35796 accept
nft add rule inet boetticher_arrstack forward udp dport 35796 accept
nft add rule inet boetticher_arrstack forward drop
nft add rule inet boetticher_arrstack input drop
iptables -N DOCKER-USER 2>/dev/null || true
iptables -F DOCKER-USER
iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A DOCKER-USER -i docker0 -o docker0 -j ACCEPT
iptables -A DOCKER-USER -i docker0 -d 10.10.20.1 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 35796 -j ACCEPT
iptables -A DOCKER-USER -p udp --dport 35796 -j ACCEPT
iptables -A DOCKER-USER -j DROP
EOF
unit="$stage/boetticher-arrstack-firewall.service"
cat >"$unit" <<'EOF'
[Unit]
Description=Boetticher arrstack fail-closed firewall
Before=docker.service
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/boetticher-arrstack-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
virt-customize -a "$customized" --install docker.io,docker-compose,qemu-guest-agent,nftables,iptables,ca-certificates,curl --upload "$policy":/usr/local/sbin/boetticher-arrstack-firewall --upload "$unit":/etc/systemd/system/boetticher-arrstack-firewall.service --run-command 'chmod 0755 /usr/local/sbin/boetticher-arrstack-firewall; systemctl enable boetticher-arrstack-firewall.service qemu-guest-agent; systemctl disable docker.service docker.socket' --mkdir /var/lib/arrstack/media --mkdir /opt/arrstack
qemu-img check "$customized"
install -d -m 0755 /var/lib/boetticher/arrstack-image
install -m 0644 "$customized" "$output.new"
sha512sum "$output.new" >"$output.new.sha512"
mv -f -- "$output.new" "$output"
mv -f -- "$output.new.sha512" "$output.sha512"
printf '%s\n' "arrstack VM image: $output sha512=$image_sha512"
