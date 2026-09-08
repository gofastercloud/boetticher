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

case "$management_netmask" in
    255.255.255.0)
        IFS=. read -r home_a home_b home_c _ <<EOF
$management_address
EOF
        home_network="$home_a.$home_b.$home_c.0/24"
        ;;
    255.255.252.0)
        IFS=. read -r home_a home_b home_c _ <<EOF
$management_address
EOF
        home_c=$((home_c / 4 * 4))
        home_network="$home_a.$home_b.$home_c.0/22"
        ;;
    *) echo "unsupported management netmask" >&2; exit 2 ;;
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
mkdir -p "$files/etc/uci-defaults" "$files/usr/share/rpcd/acl.d" "$files/etc/boetticher" \
    "$files/etc/sysctl.d" "$files/etc/init.d" "$files/etc/rc.d" \
    "$files/usr/libexec/boetticher" "$files/usr/share/nftables.d/chain-pre/input" \
    "$files/usr/share/nftables.d/chain-pre/forward" "$files/usr/share/nftables.d/chain-pre/output" \
    "$files/usr/share/nftables.d/ruleset-pre" "$files/lib/preinit"

# preinit_main is sourced lexically before base-files' 10_indicate_preinit,
# which registers preinit_ip and brings the preinit interface up. Load the
# canonical persistent sysctl asset before that hook; S09 and the late 99
# sysctl stage repeat this state after the root filesystem is ready.
cat >"$files/lib/preinit/00_boetticher_safety" <<'EOF'
#!/bin/sh

boetticher_preinit_safety() {
    /sbin/sysctl -q -p /etc/sysctl.d/99-boetticher-safety.conf || return 1
    if [ -w /dev/kmsg ]; then
        printf '%s\n' 'boetticher: preinit network safety applied' >/dev/kmsg
    fi
}
boot_hook_add preinit_main boetticher_preinit_safety
EOF
chmod 0755 "$files/lib/preinit/00_boetticher_safety"

# These are firewall4 chain-pre snippets. They are source-controlled image
# assets, automatically loaded by firewall4 before its established/related
# acceptance, and contain no reservation or client database.
cat >"$files/usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft" <<'EOF'
iifname "lo" meta nfproto ipv6 accept comment "boetticher safety guard loopback"
iifname != "lo" meta nfproto ipv6 counter drop comment "boetticher safety guard ipv6 input"
EOF
cat >"$files/usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft" <<'EOF'
ip saddr @boetticher_vpn_protected4 ip daddr @boetticher_home4 counter drop comment "boetticher safety guard protected HOME"
ip saddr @boetticher_vpn_protected4 oifname "eth0" counter drop comment "boetticher safety guard protected HOME device"
iifname "eth0" ip daddr @boetticher_vpn_protected4 counter drop comment "boetticher safety guard HOME inbound protected"
ip saddr @boetticher_vpn_protected4 oifname "airvpn" ip saddr != @boetticher_vpn_clients4 counter drop comment "boetticher safety guard undeclared VPN client"
ip saddr @boetticher_vpn_protected4 oifname != "airvpn" ip daddr != @boetticher_lab4 counter drop comment "boetticher safety guard direct WAN"
iifname "airvpn" ip daddr @boetticher_vpn_protected4 ip daddr != @boetticher_vpn_clients4 counter drop comment "boetticher safety guard removed VPN client"
iifname "airvpn" ct status dnat meta l4proto tcp ip daddr . tcp dport != @boetticher_vpn_forwards_tcp4 counter drop comment "boetticher safety guard revoked TCP forward"
iifname "airvpn" ct status dnat meta l4proto udp ip daddr . udp dport != @boetticher_vpn_forwards_udp4 counter drop comment "boetticher safety guard revoked UDP forward"
iifname "airvpn" ct status dnat meta l4proto != { tcp, udp } counter drop comment "boetticher safety guard unsupported forward"
meta nfproto ipv6 counter drop comment "boetticher safety guard ipv6 forward"
EOF
cat >"$files/usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft" <<'EOF'
oifname "lo" meta nfproto ipv6 accept comment "boetticher safety guard loopback"
oifname != "lo" meta nfproto ipv6 counter drop comment "boetticher safety guard ipv6 output"
EOF
chmod 0644 "$files/usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft" \
    "$files/usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft" \
    "$files/usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft"
cat >"$files/usr/share/nftables.d/ruleset-pre/10-boetticher-safety-sets.nft" <<'EOF'
destroy set inet fw4 boetticher_home4
destroy set inet fw4 boetticher_lab4
destroy set inet fw4 boetticher_vpn_protected4
destroy set inet fw4 boetticher_vpn_clients4
destroy set inet fw4 boetticher_vpn_forwards_tcp4
destroy set inet fw4 boetticher_vpn_forwards_udp4
EOF
chmod 0644 "$files/usr/share/nftables.d/ruleset-pre/10-boetticher-safety-sets.nft"
{
    for asset in \
        "$files/usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft" \
        "$files/usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft" \
        "$files/usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft"; do
        digest=$(sha256sum "$asset" | awk '{print $1}')
        relative=${asset#"$files"}
        printf '%s  %s\n' "$digest" "$relative"
    done
    asset="$files/usr/share/nftables.d/ruleset-pre/10-boetticher-safety-sets.nft"
    digest=$(sha256sum "$asset" | awk '{print $1}')
    relative=${asset#"$files"}
    printf '%s  %s\n' "$digest" "$relative"
} >"$files/etc/boetticher/fw4-safety.sha256"
chmod 0644 "$files/etc/boetticher/fw4-safety.sha256"

cat >"$files/etc/sysctl.d/99-boetticher-safety.conf" <<'EOF'
# IPv6 is denied by the appliance contract; loopback remains enabled.
net.ipv4.ip_forward=0
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.all.autoconf=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.forwarding=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.lo.disable_ipv6=0
EOF
chmod 0644 "$files/etc/sysctl.d/99-boetticher-safety.conf"
cat >"$files/etc/init.d/boetticher-safety" <<'EOF'
#!/bin/sh /etc/rc.common
START=09
STOP=90

start() {
    /sbin/sysctl -q -p /etc/sysctl.d/99-boetticher-safety.conf
    for asset in \
        /usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft \
        /usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft \
        /usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft; do
        test -s "$asset"
    done
}
EOF
chmod 0755 "$files/etc/init.d/boetticher-safety"
ln -sf ../init.d/boetticher-safety "$files/etc/rc.d/S09boetticher-safety"

# fw4 is retained as the native launcher. The packaged gate only serializes
# and validates start/reload; it rejects flush/stop so an unsafe path cannot
# leave forwarding permissive. The stock launcher is copied on first boot,
# since the ImageBuilder supplies it from the firewall4 package.
cat >"$files/usr/libexec/boetticher/fw4-gate" <<'EOF'
#!/bin/sh
set -eu

stock=/usr/libexec/boetticher/fw4-stock
lock=/var/lock/boetticher-fw4.lock
manifest=/etc/boetticher/fw4-safety.sha256
fail() { echo "boetticher fw4 safety gate: $1" >&2; exit 1; }
asset_input=/usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft
asset_forward=/usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft
asset_output=/usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft
asset_sets=/usr/share/nftables.d/ruleset-pre/10-boetticher-safety-sets.nft

verify_asset() {
    asset=$1
    test -r "$asset" || fail "safety asset is missing: $asset"
    test ! -L "$asset" || fail "safety asset is a symlink: $asset"
    /usr/bin/ucode -e 'let fs = require("fs"); let info = fs.stat(ARGV[0]); if (!info || info.uid != 0 || info.gid != 0 || info.mode != 420 || info.type != "file") exit(1);' "$asset" || fail "safety asset ownership or mode is unsafe: $asset"
    expected=$(awk -v path="$asset" '$2 == path { print $1; exit }' "$manifest")
    actual=$(sha256sum "$asset" | awk '{print $1}')
    test -n "$expected" && test "$expected" = "$actual" || fail "safety asset digest mismatch: $asset"
}

reject_foreign_accepts() {
    for directory in /usr/share/nftables.d/chain-pre/input /usr/share/nftables.d/chain-pre/forward /usr/share/nftables.d/chain-pre/output; do
        for candidate in "$directory"/*.nft; do
            test -f "$candidate" || continue
            case "$candidate" in
                "$asset_input"|"$asset_forward"|"$asset_output") continue ;;
            esac
            fail "unowned chain-pre include is not permitted: $candidate"
        done
    done
    if uci -q show firewall | grep -Eq '=include$'; then
        fail "unowned UCI firewall include sections are not permitted"
    fi
}

reject_foreign_flowtables() {
    for directory in /usr/share/nftables.d /usr/share/nftables.d/* /usr/share/nftables.d/*/*; do
        for candidate in "$directory"/*.nft; do
            test -f "$candidate" || continue
            if grep -F 'flowtable' "$candidate" >/dev/null; then
                fail "flowtable include is not permitted: $candidate"
            fi
        done
    done
}

reject_active_flowtables() {
    flowtables=$(nft -j list flowtables 2>/dev/null) || fail "cannot inspect global nft flowtables"
    printf '%s' "$flowtables" | /usr/bin/ucode -e '
let fs = require("fs");
let root = json(fs.readfile("/dev/stdin"));
for (let item in (root.nftables ?? [])) if (item.flowtable != null) {
    warn("boetticher safety gate: active global flowtable bypass detected\n");
    exit(1);
}
' || fail "active global nft flowtable bypass is not permitted"
}

verify_sets() {
    for set in boetticher_home4 boetticher_lab4 boetticher_vpn_protected4 boetticher_vpn_clients4 boetticher_vpn_forwards_tcp4 boetticher_vpn_forwards_udp4; do
        uci -q get "firewall.$set" >/dev/null || fail "native safety set is missing: $set"
        test "$(uci -q get "firewall.$set.name")" = "$set" || fail "native safety set name is wrong: $set"
        test -n "$(uci -q get "firewall.$set.family")" || fail "native safety set family is empty: $set"
        test -n "$(uci -q get "firewall.$set.match")" || fail "native safety set match is empty: $set"
    done
    test "$(uci -q get firewall.boetticher_home4.match)" = dest_net || fail "HOME safety set does not preserve prefixes"
    test "$(uci -q get firewall.boetticher_lab4.match)" = dest_net || fail "LAB safety set does not preserve prefixes"
    test "$(uci -q get firewall.boetticher_vpn_protected4.match)" = src_net || fail "protected safety set does not preserve prefixes"
    test "$(uci -q get firewall.boetticher_vpn_forwards_tcp4.match)" = 'dest_ip dest_port' || fail "TCP forwarding set type is incomplete"
    test "$(uci -q get firewall.boetticher_vpn_forwards_udp4.match)" = 'dest_ip dest_port' || fail "UDP forwarding set type is incomplete"
    test "$(uci -q get firewall.@defaults[0].auto_includes)" = 1 || fail "firewall4 auto includes are disabled"
    test "$(uci -q get firewall.@defaults[0].flow_offloading)" = 0 || fail "software flow offload is enabled"
    test "$(uci -q get firewall.@defaults[0].flow_offloading_hw)" = 0 || fail "hardware flow offload is enabled"
}

verify() {
    test -x "$stock" || fail "stock fw4 launcher is missing"
    test -s "$manifest" || fail "safety asset manifest is missing"
    verify_asset "$asset_input"
    verify_asset "$asset_forward"
    verify_asset "$asset_output"
    verify_asset "$asset_sets"
    reject_foreign_accepts
    reject_foreign_flowtables
    reject_active_flowtables
    verify_sets
}

verify_generated() {
    printed=$("$stock" print) || fail "native fw4 print rejected the safe ruleset"
    include_paths=$(printf '%s\n' "$printed" | awk 'match($0, /\/usr\/share\/nftables\.d\/[^"[:space:]]*\.nft/) {print substr($0, RSTART, RLENGTH)}' | sort -u)
    while IFS= read -r include; do
        test -z "$include" && continue
        case "$include" in
            "$asset_input"|"$asset_forward"|"$asset_output"|"$asset_sets") ;;
            *) fail "generated ruleset contains an unowned include path: $include" ;;
        esac
    done <<GENERATED_INCLUDES
$include_paths
GENERATED_INCLUDES
    check_chain() {
        chain=$1
        asset=$2
        section=$(printf '%s\n' "$printed" | awk -v chain="$chain" '$0 ~ "^[[:space:]]*chain " chain "[[:space:]]*\\{" {active=1; depth=0} active {line=$0; opens=gsub(/\{/, "{", line); closes=gsub(/\}/, "}", line); depth += opens - closes; print; if (active && depth <= 0) exit}')
        printf '%s\n' "$section" | grep -F "$asset" >/dev/null || fail "generated $chain chain omitted safety include path: $asset"
    }
    check_chain input "$asset_input"
    check_chain forward "$asset_forward"
    check_chain output "$asset_output"
    preamble_line=$(printf '%s\n' "$printed" | grep -n -F "$asset_sets" | awk -F: 'NR == 1 {print $1}')
    flush_line=$(printf '%s\n' "$printed" | grep -n -F 'flush table inet fw4' | awk -F: 'NR == 1 {print $1}')
    first_set_line=$(printf '%s\n' "$printed" | grep -n -F 'set boetticher_home4' | awk -F: 'NR == 1 {print $1}')
    test -n "$preamble_line" && test -n "$flush_line" && test -n "$first_set_line" && test "$flush_line" -lt "$preamble_line" && test "$preamble_line" -lt "$first_set_line" || fail "safety set destroy preamble is not after flush and before definitions"
    for set in boetticher_home4 boetticher_lab4 boetticher_vpn_protected4 boetticher_vpn_clients4; do
        section=$(printf '%s\n' "$printed" | awk -v set="$set" '$0 ~ "^[[:space:]]*set " set "[[:space:]]*\\{" {active=1; depth=0} active {line=$0; opens=gsub(/\{/, "{", line); closes=gsub(/\}/, "}", line); depth += opens - closes; print; if (active && depth <= 0) exit}')
        printf '%s\n' "$section" | grep -F 'type ipv4_addr' >/dev/null || fail "generated safety set has wrong type: $set"
        case "$set" in
            boetticher_home4|boetticher_lab4|boetticher_vpn_protected4)
                printf '%s\n' "$section" | grep -F 'flags interval' >/dev/null || fail "generated range set lacks interval flag: $set"
                ;;
        esac
    done
    for set in boetticher_vpn_forwards_tcp4 boetticher_vpn_forwards_udp4; do
        section=$(printf '%s\n' "$printed" | awk -v set="$set" '$0 ~ "^[[:space:]]*set " set "[[:space:]]*\\{" {active=1; depth=0} active {line=$0; opens=gsub(/\{/, "{", line); closes=gsub(/\}/, "}", line); depth += opens - closes; print; if (active && depth <= 0) exit}')
        printf '%s\n' "$section" | grep -F 'type ipv4_addr . inet_service' >/dev/null || fail "generated forwarding set has wrong type: $set"
    done
    forward=$(printf '%s\n' "$printed" | awk '$0 ~ "^[[:space:]]*chain forward[[:space:]]*\\{" {active=1; depth=0} active {line=$0; opens=gsub(/\{/, "{", line); closes=gsub(/\}/, "}", line); depth += opens - closes; print; if (active && depth <= 0) exit}')
    guard_line=$(printf '%s\n' "$forward" | awk -v path="$asset_forward" '$0 ~ path {print NR; exit}')
    state_line=$(printf '%s\n' "$forward" | awk '/ct state .*accept/{print NR; exit}')
    test -n "$guard_line" && test -n "$state_line" && test "$guard_line" -lt "$state_line" || fail "safety guard is not before established acceptance"
    if printf '%s\n' "$printed" | grep -F 'flowtable' >/dev/null; then fail "generated ruleset contains a flowtable"; fi
}

exact_sets_json() {
    printf '%s' "$1" | /usr/bin/ucode -e '
let fs = require("fs");
let uci = require("uci");

let root = json(fs.readfile("/dev/stdin"));
let cursor = uci.cursor();
let mode = ARGV[0] ?? "post";
let names = ["boetticher_home4", "boetticher_lab4", "boetticher_vpn_protected4", "boetticher_vpn_clients4", "boetticher_vpn_forwards_tcp4", "boetticher_vpn_forwards_udp4"];

function fail(message) { warn(`boetticher safety set check: ${message ?? "malformed native set data"}\n`); exit(1); }
function ip_number(value) {
    let parts = split(value, ".");
    if (length(parts) != 4) fail("malformed IPv4 address");
    return +parts[0] * 16777216 + +parts[1] * 65536 + +parts[2] * 256 + +parts[3];
}
function span(value) {
    if (type(value) == "object" && value.addr != null)
        return span(`${value.addr}/${value.len}`);
    let parts = split(`${value}`, "/");
    let start = ip_number(parts[0]);
    if (length(parts) == 1) return [start, start];
    let size = 1;
    for (let n = +parts[1]; n < 32; n++) size *= 2;
    return [start, start + size - 1];
}
function merge(values) {
    let spans = [];
    for (let value in values) push(spans, span(value));
    sort(spans, (a, b) => a[0] - b[0]);
    let merged = [];
    for (let item in spans) {
        if (!length(merged) || item[0] > merged[length(merged) - 1][1] + 1)
            push(merged, [item[0], item[1]]);
        else if (item[1] > merged[length(merged) - 1][1])
            merged[length(merged) - 1][1] = item[1];
    }
    return sprintf("%J", merged);
}
function native_value(value) {
    if (value == null) fail("malformed set element");
    if (type(value) == "string") return value;
    if (type(value) == "array") return `${value[0]} . ${value[1]}`;
    if (type(value) != "object") fail("unsupported set element shape");
    if (value.prefix != null) return `${value.prefix.addr}/${value.prefix.len}`;
    if (value.val != null) return `${value.val}`;
    if (value.concat != null) return `${value.concat[0]} . ${value.concat[1]}`;
    fail("unsupported set element shape");
}
function exact(name, set) {
    let expected = cursor.get("firewall", name, "entry");
    if (expected == null) expected = [];
    else if (type(expected) == "string") expected = [expected];
    let actual = [];
    for (let item in (set.elem ?? [])) push(actual, native_value(item));
    if (set.type != "ipv4_addr" && name != "boetticher_vpn_forwards_tcp4" && name != "boetticher_vpn_forwards_udp4") fail(`${name}: wrong set type`);
    if (name == "boetticher_home4" || name == "boetticher_lab4" || name == "boetticher_vpn_protected4") {
        let interval = false;
        for (let flag in (set.flags ?? [])) if (flag == "interval") interval = true;
        if (!interval || !length(expected) || !length(actual)) fail(`${name}: missing interval flag or required membership`);
        if (merge(expected) != merge(actual)) fail(`${name}: exact interval membership mismatch`);
    } else {
        if (name == "boetticher_vpn_forwards_tcp4" || name == "boetticher_vpn_forwards_udp4") {
            if (type(set.type) != "array" || length(set.type) != 2 || set.type[0] != "ipv4_addr" || set.type[1] != "inet_service") fail(`${name}: wrong tuple set type`);
        }
        if (mode == "pre") return;
        if (name == "boetticher_vpn_forwards_tcp4" || name == "boetticher_vpn_forwards_udp4") {
            for (let n = 0; n < length(expected); n++) expected[n] = `${split(expected[n], " ")[0]} . ${split(expected[n], " ")[1]}`;
        }
        sort(expected);
        sort(actual);
        if (sprintf("%J", expected) != sprintf("%J", actual)) fail(`${name}: exact membership mismatch`);
    }
}
for (let name in names) {
    let found = null;
for (let item in (root.nftables ?? [])) if (item.set?.name == name && item.set.family == "inet" && item.set.table == "fw4") found = item.set;
    if (found == null) fail(`${name}: set is missing`);
    exact(name, found);
}
' "$2" || return 1
    return 0
}

chain_rules() {
    nft -s list chain inet fw4 "$1" 2>/dev/null | awk '/^[[:space:]]*type /{inside=1; next} inside && /^[[:space:]]*}/{exit} inside {sub(/^[[:space:]]+/, ""); if (length($0)) print}'
}

require_prefix() {
    chain=$1
    expected=$2
    actual=$(chain_rules "$chain") || return 1
    expected=$(printf '%s\n' "$expected" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/counter packets [0-9]+ bytes [0-9]+/counter/g; s/meta l4proto (tcp|udp) //g')
    actual=$(printf '%s\n' "$actual" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/counter packets [0-9]+ bytes [0-9]+/counter/g')
    count=$(printf '%s\n' "$expected" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
    test "$count" -gt 0 || return 1
    test "$(printf '%s\n' "$actual" | head -n "$count")" = "$expected" || return 1
    next=$(printf '%s\n' "$actual" | sed -n "$((count + 1))p")
    printf '%s\n' "$next" | grep -Eq '^ct state .*established.*accept|^ct state .*related.*accept' || return 1
}

runtime_safe() {
    mode=${1:-post}
    runtime=$(nft -j list ruleset 2>/dev/null) || return 1
    if printf '%s\n' "$runtime" | grep -F 'flowtable' >/dev/null; then return 1; fi
    exact_sets_json "$runtime" "$mode" || return 1
    input_expected=$(cat <<'EXPECTED_INPUT'
iif "lo" accept comment "!fw4: Accept traffic from loopback"
iifname "lo" meta nfproto ipv6 accept comment "boetticher safety guard loopback"
iifname != "lo" meta nfproto ipv6 counter drop comment "boetticher safety guard ipv6 input"
EXPECTED_INPUT
)
    output_expected=$(cat <<'EXPECTED_OUTPUT'
oif "lo" accept comment "!fw4: Accept traffic towards loopback"
oifname "lo" meta nfproto ipv6 accept comment "boetticher safety guard loopback"
oifname != "lo" meta nfproto ipv6 counter drop comment "boetticher safety guard ipv6 output"
EXPECTED_OUTPUT
)
    forward_expected=$(cat <<'EXPECTED_FORWARD'
ip saddr @boetticher_vpn_protected4 ip daddr @boetticher_home4 counter drop comment "boetticher safety guard protected HOME"
ip saddr @boetticher_vpn_protected4 oifname "eth0" counter drop comment "boetticher safety guard protected HOME device"
iifname "eth0" ip daddr @boetticher_vpn_protected4 counter drop comment "boetticher safety guard HOME inbound protected"
ip saddr @boetticher_vpn_protected4 oifname "airvpn" ip saddr != @boetticher_vpn_clients4 counter drop comment "boetticher safety guard undeclared VPN client"
ip saddr @boetticher_vpn_protected4 oifname != "airvpn" ip daddr != @boetticher_lab4 counter drop comment "boetticher safety guard direct WAN"
iifname "airvpn" ip daddr @boetticher_vpn_protected4 ip daddr != @boetticher_vpn_clients4 counter drop comment "boetticher safety guard removed VPN client"
iifname "airvpn" ct status dnat ip daddr . tcp dport != @boetticher_vpn_forwards_tcp4 counter drop comment "boetticher safety guard revoked TCP forward"
iifname "airvpn" ct status dnat ip daddr . udp dport != @boetticher_vpn_forwards_udp4 counter drop comment "boetticher safety guard revoked UDP forward"
iifname "airvpn" ct status dnat meta l4proto != { tcp, udp } counter drop comment "boetticher safety guard unsupported forward"
meta nfproto ipv6 counter drop comment "boetticher safety guard ipv6 forward"
EXPECTED_FORWARD
)
    require_prefix input "$input_expected" || return 1
    require_prefix forward "$forward_expected" || return 1
    require_prefix output "$output_expected" || return 1
    return 0
}

verify_safety_status_sysctls() {
    test "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = 1 || return 1
    for scope in all default; do
        test "$(sysctl -n "net.ipv6.conf.$scope.disable_ipv6" 2>/dev/null)" = 1 || return 1
        test "$(sysctl -n "net.ipv6.conf.$scope.autoconf" 2>/dev/null)" = 0 || return 1
        test "$(sysctl -n "net.ipv6.conf.$scope.accept_ra" 2>/dev/null)" = 0 || return 1
        test "$(sysctl -n "net.ipv6.conf.$scope.forwarding" 2>/dev/null)" = 0 || return 1
    done
    for path in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        interface=${path%/disable_ipv6}; interface=${interface##*/}
        test "$interface" = lo || test "$(cat "$path" 2>/dev/null)" = 1 || return 1
    done
}

if [ "$#" -gt 0 ]; then
    quiet=0
    verbose=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -q) quiet=1; shift ;;
            -v) verbose=1; shift ;;
            *) break ;;
        esac
    done
else
    quiet=0
    verbose=0
fi
if [ "$#" -gt 0 ]; then command=$1; shift; else command=start; fi

run_stock() {
    if [ "$quiet" -eq 1 ] && [ "$verbose" -eq 1 ]; then
        "$stock" -q -v "$@"
    elif [ "$quiet" -eq 1 ]; then
        "$stock" -q "$@"
    elif [ "$verbose" -eq 1 ]; then
        "$stock" -v "$@"
    else
        "$stock" "$@"
    fi
}
case "$command" in
	 safety-status)
		# Read-only complete gate for Controller verification; no UCI, sysctl,
		# service, lock, or network operation is performed in this branch.
		verify
		verify_sets
		verify_safety_status_sysctls || fail "persistent IPv4/IPv6 safety sysctls are not active"
		runtime_safe post || fail "loaded firewall safety policy is not active"
		printf '%s\n' 'BOETTICHER_SAFETY_OK'
		exit 0
		;;
	restart|reload-sets) command=reload ;;
	start|reload) test "$#" -eq 0 || fail "fw4 $command does not accept lifecycle arguments" ;;
    check|print)
        verify
        run_stock "$command" "$@"
        exit $?
        ;;
    network|zone|device|table|version|help)
        # firewall4 hotplug uses network/zone/device lookups to decide whether
        # a reload is needed. These are read-only stock queries and must stay
        # available before the provider's UCI sets exist.
        run_stock "$command" "$@"
        exit $?
        ;;
    stop|flush) fail "refusing unsafe $command; the persistent safety policy must remain loaded" ;;
    *) fail "unsupported fw4 action: $command" ;;
esac

exec 9>"$lock"
lock_started=$(awk '{print int($1)}' /proc/uptime 2>/dev/null) || fail "cannot measure fw4 lock deadline"
while ! flock -n 9; do
    lock_now=$(awk '{print int($1)}' /proc/uptime 2>/dev/null) || fail "cannot measure fw4 lock deadline"
    test "$((lock_now - lock_started))" -lt 30 || fail "another fw4 operation is in progress"
    sleep 1
done
# Preserve healthy ordinary-client forwarding while the current safe ruleset
# is checked. A missing or unsafe live table is fail-closed before preflight.
if ! runtime_safe pre; then /sbin/sysctl -q -w net.ipv4.ip_forward=0 || true; fi
verify
verify_generated
run_stock check >/dev/null || fail "native fw4 check rejected the safe ruleset"
if run_stock "$command" "$@"; then
    :
else
    if ! runtime_safe pre; then /sbin/sysctl -q -w net.ipv4.ip_forward=0 || true; fi
    fail "native fw4 $command failed; partial result, previous runtime permissions may remain"
fi
if ! runtime_safe post; then
    /sbin/sysctl -q -w net.ipv4.ip_forward=0 || true
    fail "loaded fw4 table failed the complete safety check; forwarding remains disabled"
fi
/sbin/sysctl -q -w net.ipv4.ip_forward=1
EOF
chmod 0755 "$files/usr/libexec/boetticher/fw4-gate"
cat >"$files/etc/uci-defaults/09-boetticher-safety" <<'EOF'
#!/bin/sh
set -eu

stock=/usr/libexec/boetticher/fw4-stock
if [ ! -x "$stock" ]; then
    test -x /sbin/fw4
    cp -Lp /sbin/fw4 "$stock"
    chmod 0755 "$stock"
fi
cp -Lp /usr/libexec/boetticher/fw4-gate /sbin/fw4
chmod 0755 /sbin/fw4
manifest=/etc/boetticher/fw4-safety.sha256
test -s "$manifest"
for asset in \
    /usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft \
    /usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft \
    /usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft \
    /usr/share/nftables.d/ruleset-pre/10-boetticher-safety-sets.nft; do
    test -s "$asset"
done
exit 0
EOF
chmod 0700 "$files/etc/uci-defaults/09-boetticher-safety"
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
uci -q set network.boetticher_home.ipv6='0'
uci -q set network.boetticher_home_device='device'
uci -q set network.boetticher_home_device.name='eth0'
uci -q set network.boetticher_home_device.ipv6='0'
uci -q delete dhcp.lan || true
uci -q delete dhcp.wan || true
while uci -q delete dhcp.@dnsmasq[0]; do :; done
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
uci -q set firewall.@defaults[0].auto_includes='1'
uci -q set firewall.@defaults[0].flow_offloading='0'
uci -q set firewall.@defaults[0].flow_offloading_hw='0'

# Native sets are the sole data projection point for the static guard. The
# client and forward sets intentionally start empty and are populated only by
# the later VPN capability reconciler.
uci -q set firewall.boetticher_home4='ipset'
uci -q set firewall.boetticher_home4.name='boetticher_home4'
uci -q set firewall.boetticher_home4.family='ipv4'
uci -q add_list firewall.boetticher_home4.match='dest_net'
uci -q add_list firewall.boetticher_home4.entry='$home_network'
uci -q set firewall.boetticher_lab4='ipset'
uci -q set firewall.boetticher_lab4.name='boetticher_lab4'
uci -q set firewall.boetticher_lab4.family='ipv4'
uci -q add_list firewall.boetticher_lab4.match='dest_net'
for lab_network in 10.10.5.0/24 10.10.10.0/24 10.10.20.0/24 10.10.30.0/24 10.10.40.0/24 10.10.99.0/24; do
    uci -q add_list firewall.boetticher_lab4.entry="\$lab_network"
done
uci -q set firewall.boetticher_vpn_protected4='ipset'
uci -q set firewall.boetticher_vpn_protected4.name='boetticher_vpn_protected4'
uci -q set firewall.boetticher_vpn_protected4.family='ipv4'
uci -q add_list firewall.boetticher_vpn_protected4.match='src_net'
for protected_network in 10.10.10.224/28 10.10.20.224/28 10.10.30.224/28 10.10.40.224/28; do
    uci -q add_list firewall.boetticher_vpn_protected4.entry="\$protected_network"
done
uci -q set firewall.boetticher_vpn_clients4='ipset'
uci -q set firewall.boetticher_vpn_clients4.name='boetticher_vpn_clients4'
uci -q set firewall.boetticher_vpn_clients4.family='ipv4'
uci -q add_list firewall.boetticher_vpn_clients4.match='src_ip'
for forward_protocol in tcp udp; do
    set_name="boetticher_vpn_forwards_\${forward_protocol}4"
    uci -q set firewall."\$set_name"='ipset'
    uci -q set firewall."\$set_name".name="\$set_name"
    uci -q set firewall."\$set_name".family='ipv4'
    uci -q add_list firewall."\$set_name".match='dest_ip'
    uci -q add_list firewall."\$set_name".match='dest_port'
done
uci -q commit firewall
uci -q set uhttpd.main.redirect_https='1'
uci -q set uhttpd.main.listen_http='0.0.0.0:80'
uci -q set uhttpd.main.listen_https='0.0.0.0:443'
uci -q commit uhttpd
uci -q delete stubby.global || true
while uci -q delete stubby.@resolver[0]; do :; done
uci -q set stubby.global='stubby'
uci -q set stubby.global.manual='0'
uci -q set stubby.global.trigger='boetticher_home'
uci -q set stubby.global.tls_authentication='1'
uci -q set stubby.global.tls_min_version='1.2'
uci -q set stubby.global.edns_client_subnet_private='1'
uci -q set stubby.global.round_robin_upstreams='1'
uci -q delete stubby.global.listen_address || true
uci -q add_list stubby.global.listen_address='127.0.0.1@5453'
uci -q delete stubby.global.dns_transport || true
uci -q add_list stubby.global.dns_transport='GETDNS_TRANSPORT_TLS'
uci -q set stubby.boetticher_resolver_9_9_9_9='resolver'
uci -q set stubby.boetticher_resolver_9_9_9_9.address='9.9.9.9'
uci -q set stubby.boetticher_resolver_9_9_9_9.tls_auth_name='dns.quad9.net'
uci -q set stubby.boetticher_resolver_9_9_9_9.tls_port='853'
uci -q set stubby.boetticher_resolver_149_112_112_112='resolver'
uci -q set stubby.boetticher_resolver_149_112_112_112.address='149.112.112.112'
uci -q set stubby.boetticher_resolver_149_112_112_112.tls_auth_name='dns.quad9.net'
uci -q set stubby.boetticher_resolver_149_112_112_112.tls_port='853'
uci -q commit stubby
mkdir -p /etc/boetticher
touch /etc/boetticher/dhcp.leases
chown dnsmasq:dnsmasq /etc/boetticher/dhcp.leases
chmod 0640 /etc/boetticher/dhcp.leases
printf '%s\n' 'v8' >/etc/boetticher/client-services-contract
chmod 0644 /etc/boetticher/client-services-contract
uci -q delete system.ntp || true
uci -q set system.ntp='timeserver'
uci -q delete system.ntp.server || true
uci -q add_list system.ntp.server='162.159.200.1'
uci -q add_list system.ntp.server='17.253.34.125'
uci -q add_list system.ntp.server='129.6.15.28'
uci -q set system.ntp.enabled='1'
uci -q set system.ntp.use_dhcp='0'
uci -q set system.ntp.enable_server='0'
uci -q commit system
/etc/init.d/dnsmasq enable 2>/dev/null || true
/etc/init.d/stubby enable 2>/dev/null || true
/etc/init.d/sysntpd enable 2>/dev/null || true
/etc/init.d/odhcpd disable 2>/dev/null || true
/etc/init.d/dnsmasq restart 2>/dev/null || true
/etc/init.d/stubby restart 2>/dev/null || true
/etc/init.d/sysntpd restart 2>/dev/null || true
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
        "firewall": ["read"],
        "dhcp": ["read"],
        "stubby": ["read"],
        "system": ["read"]
      }
    },
    "write": {
      "ubus": {
        "uci": ["set", "add", "delete", "commit", "apply"],
        "service": ["event"],
        "file": ["exec"]
      },
      "file": {
        "/sbin/fw4": ["exec"]
      },
      "uci": {
        "network": ["read", "write"],
        "firewall": ["read", "write"],
        "dhcp": ["read", "write"],
        "stubby": ["read", "write"],
        "system": ["read", "write"]
      }
    }
  }
}
EOF

packages='uhttpd uhttpd-mod-ubus rpcd rpcd-mod-file rpcd-mod-iwinfo px5g-mbedtls ca-bundle firewall4 nftables dnsmasq stubby qemu-ga wireguard-tools kmod-wireguard ip-full flock'
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
