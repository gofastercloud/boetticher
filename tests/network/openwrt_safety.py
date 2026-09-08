#!/usr/bin/env python3
"""Run the first-mile OpenWrt safety contract in an isolated QEMU fixture.

Run explicitly inside the pinned network-test container. Only UUID-scoped
bridges, taps, namespaces, QEMU overlays, and echo processes are created.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import shutil
import tempfile
import time
import uuid


CONTRACT = "v8"
HOME = "192.0.2.2"
GATEWAY = "192.0.2.1"
HOME_MAC = "52:54:00:4c:00:01"
LAB_MAC = "52:54:00:4c:00:02"


def run(*args: str, check: bool = True, timeout: int = 20, input: str | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout, input=input)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()}")
    return result


def qga(sock_path: Path, request: dict, timeout: float = 8.0) -> dict:
    request = dict(request, id=str(time.monotonic_ns()))
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(0.5)
        while True:
            try:
                channel.connect(str(sock_path))
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("QEMU guest-agent socket did not become ready")
                time.sleep(0.1)
        channel.sendall((json.dumps(request) + "\n").encode())
        data = b""
        while time.monotonic() < deadline:
            try:
                data += channel.recv(65536)
            except TimeoutError:
                continue
            for line in data.splitlines():
                try:
                    response = json.loads(line)
                except ValueError:
                    continue
                if response.get("id") != request["id"]:
                    continue
                if "error" in response:
                    raise RuntimeError(str(response["error"]))
                return response.get("return", {})
        raise RuntimeError("correlated guest-agent response timed out")


def guest(sock_path: Path, command: str, timeout: int = 45) -> dict[str, str | int]:
    started = qga(sock_path, {"execute": "guest-exec", "arguments": {"path": "/bin/sh", "arg": ["-c", command], "capture-output": True}})
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = qga(sock_path, {"execute": "guest-exec-status", "arguments": {"pid": started["pid"]}})
        if result.get("exited"):
            return {"exitcode": result.get("exitcode", 255), "stdout": base64.b64decode(result.get("out-data", "")).decode(errors="replace"), "stderr": base64.b64decode(result.get("err-data", "")).decode(errors="replace")}
        time.sleep(0.2)
    raise TimeoutError("guest command exceeded its bounded window")


def require_guest(sock_path: Path, command: str, timeout: int = 45) -> str:
    result = guest(sock_path, command, timeout)
    if result["exitcode"] != 0:
        raise RuntimeError(f"guest command failed: {result['stderr']}")
    return str(result["stdout"])


def netns(name: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("ip", "netns", "exec", name, *args, check=check, timeout=15)


def setup_network(prefix: str, names: list[str], bridges: list[str], taps: list[str], links: list[str]) -> None:
    for suffix in ("home", "lab"):
        bridge = f"br-{prefix[-7:]}-{suffix}"
        bridges.append(bridge)
        run("ip", "link", "add", bridge, "type", "bridge")
        run("ip", "link", "set", bridge, "up")
    for suffix in ("home", "protected", "ordinary"):
        name = f"{prefix}-{suffix}"
        names.append(name)
        run("ip", "netns", "add", name)
        netns(name, "ip", "link", "set", "lo", "up")

    def endpoint(namespace: str, bridge: str, address: str, label: str) -> None:
        host_if, ns_if = f"{prefix[-5:]}-{label[:1]}h", f"{prefix[-5:]}-{label[:1]}n"
        links.append(host_if)
        run("ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if)
        run("ip", "link", "set", ns_if, "netns", namespace)
        run("ip", "link", "set", host_if, "master", bridge)
        run("ip", "link", "set", host_if, "up")
        netns(namespace, "ip", "addr", "add", address, "dev", ns_if)
        netns(namespace, "ip", "link", "set", ns_if, "up")

    endpoint(names[0], bridges[0], "192.0.2.1/24", "home")
    endpoint(names[1], bridges[1], "10.10.20.226/24", "protected")
    endpoint(names[2], bridges[1], "10.10.20.250/24", "ordinary")
    home_if = f"{prefix[-5:]}-hn"
    netns(names[0], "ip", "addr", "add", "198.51.100.1/24", "dev", home_if)
    netns(names[0], "ip", "-6", "addr", "add", "2001:db8:4::1/64", "dev", home_if, check=False)
    for name in names[1:]:
        netns(name, "ip", "route", "add", "default", "via", "10.10.20.1", check=False)
    for bridge, label in zip(bridges, ("home", "lab")):
        tap = f"{prefix[-5:]}-{label[:1]}tap"
        taps.append(tap)
        run("ip", "tuntap", "add", tap, "mode", "tap")
        run("ip", "link", "set", tap, "master", bridge)
        run("ip", "link", "set", tap, "up")


def start_echo(namespace: str) -> subprocess.Popen[str]:
    code = "import socket,threading\ndef echo(c):\n try:\n  c.sendall(c.recv(4096))\n finally:\n  c.close()\ndef tcp():\n s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('198.51.100.1',18080));s.listen()\n while True:\n  c,_=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()\ndef udp():\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.51.100.1',18081))\n while True:\n  d,p=s.recvfrom(4096);s.sendto(d,p)\nthreading.Thread(target=tcp,daemon=True).start();threading.Thread(target=udp,daemon=True).start();threading.Event().wait()"
    return subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable, "-u", "-c", code], text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def wait_capture(process: subprocess.Popen[str]) -> None:
    if process.stderr is None:
        raise RuntimeError("packet capture has no readiness stream")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if select.select([process.stderr], [], [], 0.2)[0]:
            if "listening on" in process.stderr.readline():
                return
    raise RuntimeError("IPv6 boot capture did not become ready")


def probe(namespace: str, source: str, udp: bool = False) -> bool:
    code = "import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if sys.argv[2]=='u' else socket.SOCK_STREAM);s.settimeout(2);s.bind((sys.argv[1],0));s.connect(('198.51.100.1',18081 if sys.argv[2]=='u' else 18080));s.send(b'probe');print(s.recv(32).decode())"
    result = netns(namespace, sys.executable, "-c", code, source, "u" if udp else "t", check=False)
    return result.returncode == 0 and result.stdout.strip() == "probe"


def wait_echo(namespace: str, source: str, echo: subprocess.Popen[str] | None = None) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if probe(namespace, source) and probe(namespace, source, True):
            return
        time.sleep(0.2)
    details = [f"client addr/route: {netns(namespace, 'ip', '-4', 'addr', check=False).stdout.strip()} / {netns(namespace, 'ip', 'route', check=False).stdout.strip()}"]
    if echo is not None and echo.stderr is not None:
        echo_stderr = ""
        if select.select([echo.stderr], [], [], 0)[0]:
            echo_stderr = echo.stderr.read(4096).strip()
        details.append(f"echo stderr: {echo_stderr}")
    raise RuntimeError("owned TCP/UDP echo target did not become ready; " + "; ".join(details))


def configure_guest(sock_path: Path) -> None:
    command = f"""set -eu
uci set network.safety_lab=interface
uci set network.safety_lab.device=eth1
uci set network.safety_lab.proto=static
uci set network.safety_lab.ipaddr=10.10.20.1
uci set network.safety_lab.netmask=255.255.255.0
uci set network.safety_lab.ipv6=0
uci set network.safety_lab.delegate=0
uci set firewall.safety_lab=zone
uci set firewall.safety_lab.name=safety_lab
uci set firewall.safety_lab.family=ipv4
uci set firewall.safety_lab.input=DROP
uci set firewall.safety_lab.forward=DROP
uci set firewall.safety_lab.output=ACCEPT
uci add_list firewall.safety_lab.network=safety_lab
uci set firewall.safety_lab_home=forwarding
uci set firewall.safety_lab_home.src=safety_lab
uci set firewall.safety_lab_home.dest=home_wan
uci commit network
/etc/init.d/network reload
for attempt in $(seq 1 30); do
    ip link show dev eth1 up >/dev/null 2>&1 && break
    sleep 0.2
done
ip -4 addr show dev eth1 | grep -F '10.10.20.1/24'
uci commit firewall
/sbin/fw4 reload
test \"$(uci -q get network.boetticher_home.ipaddr)\" = {HOME}
test \"$(uci -q get network.boetticher_home.gateway)\" = {GATEWAY}
test \"$(cat /etc/boetticher/client-services-contract)\" = {CONTRACT}
test \"$(cat /sys/class/net/eth0/address)\" = {HOME_MAC}
test \"$(cat /sys/class/net/eth1/address)\" = {LAB_MAC}
"""
    result = guest(sock_path, command)
    if result["exitcode"] != 0:
        raise RuntimeError(f"synthetic guest configuration failed: {result['stderr']}")


def run_checks(sock_path: Path, names: list[str], report: dict) -> None:
    protected, ordinary = names[1], names[2]
    link_prefix = names[0][:-5][-5:]
    boundaries = [("10.10.20.224", False), ("10.10.20.225", False), ("10.10.20.239", False), ("10.10.20.223", True), ("10.10.20.240", True)]
    report["range_boundaries"] = {}
    for address, allowed in boundaries:
        netns(protected, "ip", "addr", "add", f"{address}/24", "dev", f"{link_prefix}-pn")
        tcp_ok = probe(protected, address)
        udp_ok = probe(protected, address, True)
        report["range_boundaries"][address] = {"tcp": tcp_ok, "udp": udp_ok, "expected": allowed}
        netns(protected, "ip", "addr", "del", f"{address}/24", "dev", f"{link_prefix}-pn")
        if tcp_ok != allowed or udp_ok != allowed:
            raise AssertionError(f"range boundary failed: {address}")
    report["ordinary_positive_control"] = {"tcp": probe(ordinary, "10.10.20.250"), "udp": probe(ordinary, "10.10.20.250", True)}
    if not all(report["ordinary_positive_control"].values()):
        raise AssertionError("ordinary client lost normal HOME egress")
    require_guest(sock_path, "set -eu; uci add_list firewall.boetticher_vpn_clients4.entry=10.10.20.224; uci add_list firewall.boetticher_vpn_forwards_tcp4.entry='10.10.20.224 18080'; uci commit firewall; /sbin/fw4 reload")
    added = require_guest(sock_path, "nft -j list set inet fw4 boetticher_vpn_clients4; nft -j list set inet fw4 boetticher_vpn_forwards_tcp4")
    if "10.10.20.224" not in added or "18080" not in added:
        raise AssertionError("native scalar/tuple add did not appear")
    require_guest(sock_path, "set -eu; uci del_list firewall.boetticher_vpn_clients4.entry=10.10.20.224; uci del_list firewall.boetticher_vpn_forwards_tcp4.entry='10.10.20.224 18080'; uci commit firewall; /sbin/fw4 reload")
    removed = require_guest(sock_path, "nft -j list set inet fw4 boetticher_vpn_clients4; nft -j list set inet fw4 boetticher_vpn_forwards_tcp4")
    if "10.10.20.224" in removed or "18080" in removed:
        raise AssertionError("native scalar/tuple removal retained stale membership")


def run_reload_failures(sock_path: Path, names: list[str], report: dict) -> None:
    asset = "/usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft"
    link_prefix = names[0][:-5][-5:]
    netns(names[1], "ip", "addr", "add", "10.10.20.224/24", "dev", f"{link_prefix}-pn", check=False)
    for label, operation in [("missing-asset", f"rm {asset}"), ("corrupt-asset", f"printf '\\ninvalid_bt4c_rule\\n' >> {asset}")]:
        before = require_guest(sock_path, "nft -s list table inet fw4 | sha256sum").strip()
        result = None
        try:
            result = guest(sock_path, f"set -eu; cp -p {asset} /tmp/bt4c-safety-save; {operation}; /sbin/fw4 reload")
            after = require_guest(sock_path, "nft -s list table inet fw4 | sha256sum").strip()
            if result["exitcode"] == 0 or before != after:
                raise AssertionError(f"{label} did not preserve active ruleset")
            if (not probe(names[2], "10.10.20.250") or not probe(names[2], "10.10.20.250", True)
                    or probe(names[1], "10.10.20.224") or probe(names[1], "10.10.20.224", True)):
                raise AssertionError(f"{label} changed ordinary/protected packet behavior")
        finally:
            restore = guest(sock_path, f"set -eu; test -f /tmp/bt4c-safety-save; mv /tmp/bt4c-safety-save {asset}; /sbin/fw4 reload")
            if restore["exitcode"] != 0:
                raise RuntimeError(f"{label} cleanup reload failed: {restore['stderr']}")
        report[label] = {"rejected": True, "ruleset_unchanged": True}
    netns(names[1], "ip", "addr", "del", "10.10.20.224/24", "dev", f"{link_prefix}-pn", check=False)

    for chain, rule in ((
        ("input", "ip saddr 10.10.20.225 accept"),
        ("forward", "ip saddr 10.10.20.225 accept"),
        ("output", "ip daddr 10.10.20.225 accept"),
    )):
        unowned = f"/usr/share/nftables.d/chain-pre/{chain}/00-bt4c-accept-fixture.nft"
        before = require_guest(sock_path, "nft -s list table inet fw4 | sha256sum").strip()
        try:
            result = guest(sock_path, f"set -eu; printf '%s\\n' '{rule}' > {unowned}; /sbin/fw4 reload")
            after = require_guest(sock_path, "nft -s list table inet fw4 | sha256sum").strip()
            if result["exitcode"] == 0 or before != after or "unowned" not in str(result["stderr"]):
                raise AssertionError(f"unowned {chain} include was accepted or changed the active ruleset")
        finally:
            cleanup = guest(sock_path, f"set -eu; rm -f {unowned}; /sbin/fw4 reload")
            if cleanup["exitcode"] != 0:
                raise RuntimeError(f"unowned {chain} include cleanup reload failed: {cleanup['stderr']}")
        report[f"unowned-{chain}-include"] = {"rejected": True, "ruleset_unchanged": True}

    foreign_table = "bt4c-foreign-flowtable"
    before = require_guest(sock_path, "nft -s list table inet fw4 | sha256sum").strip()
    try:
        require_guest(sock_path, f"set -eu; nft add table inet {foreign_table}; nft 'add flowtable inet {foreign_table} ft {{ hook ingress priority 0; devices = {{ eth0 }}; }}'; nft -j list flowtables | grep -F 'flowtable'")
        result = guest(sock_path, "/sbin/fw4 reload")
        after = require_guest(sock_path, "nft -s list table inet fw4 | sha256sum").strip()
        if result["exitcode"] == 0 or before != after or "flowtable" not in str(result["stderr"]):
            raise AssertionError("active foreign-table flowtable was accepted or changed the active ruleset")
    finally:
        cleanup = guest(sock_path, f"set -eu; nft delete table inet {foreign_table}; /sbin/fw4 reload")
        if cleanup["exitcode"] != 0:
            raise RuntimeError(f"foreign flowtable cleanup reload failed: {cleanup['stderr']}")
    report["foreign-table-flowtable"] = {"rejected": True, "ruleset_unchanged": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--image-sha256")
    parser.add_argument("--results", type=Path, default=Path("/tmp/boetticher-openwrt-safety.json"))
    options = parser.parse_args()
    if not Path("/.dockerenv").exists():
        parser.error("run inside the dedicated network-test container")
    if options.image.is_symlink() or not options.image.is_file():
        parser.error("image must be a regular file")
    if options.image_sha256:
        digest = hashlib.sha256()
        with options.image.open("rb") as image_file:
            for block in iter(lambda: image_file.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != options.image_sha256:
            parser.error("image digest mismatch")
    prefix = "bt4c-" + uuid.uuid4().hex[:10]
    namespaces: list[str] = []
    bridges: list[str] = []
    taps: list[str] = []
    links: list[str] = []
    children: list[subprocess.Popen[str]] = []
    work = Path(tempfile.mkdtemp(prefix="boetticher-safety-"))
    qga_path = work / "qga.sock"
    overlay = work / "overlay.qcow2"
    capture = work / "boot.pcap"
    report: dict[str, object] = {"status": "INCONCLUSIVE", "fixture": prefix}
    qemu: subprocess.Popen[str] | None = None
    try:
        os.unshare(os.CLONE_NEWNET)
        run("ip", "link", "set", "lo", "up")
        setup_network(prefix, namespaces, bridges, taps, links)
        run("qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(options.image), str(overlay), timeout=30)
        tcpdump = subprocess.Popen(["tcpdump", "-U", "-nn", "-i", bridges[0], "-w", str(capture), f"ether src {HOME_MAC} and ip6"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        children.append(tcpdump)
        wait_capture(tcpdump)
        qemu = subprocess.Popen(["qemu-system-x86_64", "-accel", "tcg", "-m", "1024", "-smp", "2", "-nographic", "-drive", f"file={overlay},if=virtio,format=qcow2", "-chardev", f"socket,id=qga,path={qga_path},server=on,wait=off", "-device", "virtio-serial", "-device", "virtserialport,chardev=qga,name=org.qemu.guest_agent.0", "-netdev", f"tap,id=home,ifname={taps[0]},script=no,downscript=no", "-device", f"virtio-net-pci,netdev=home,mac={HOME_MAC}", "-netdev", f"tap,id=lab,ifname={taps[1]},script=no,downscript=no", "-device", f"virtio-net-pci,netdev=lab,mac={LAB_MAC}"], stdout=(work / "qemu-console.log").open("w"), stderr=subprocess.STDOUT)
        children.append(qemu)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                identity = require_guest(qga_path, "set -eu; uci -q get network.boetticher_home.ipaddr; uci -q get network.boetticher_home.gateway; cat /etc/boetticher/client-services-contract; cat /sys/class/net/eth0/address; cat /sys/class/net/eth1/address", 8).splitlines()
                if identity == [HOME, GATEWAY, CONTRACT, HOME_MAC, LAB_MAC]:
                    break
            except (RuntimeError, TimeoutError):
                if qemu.poll() is not None:
                    console = (work / "qemu-console.log").read_text(encoding="utf-8", errors="replace")[-4000:]
                    raise RuntimeError(f"QEMU exited with status {qemu.returncode}; console tail: {console}")
                pass
            time.sleep(1)
        else:
            raise RuntimeError("QEMU guest did not reach a correlated ready state")
        tcpdump.send_signal(signal.SIGINT)
        tcpdump.wait(timeout=5)
        boot_packets = run("tcpdump", "-nn", "-r", str(capture), f"ether src {HOME_MAC} and ip6", check=False, timeout=15)
        if boot_packets.returncode == 0 and boot_packets.stdout.strip():
            raise AssertionError("preinit emitted IPv6 traffic on the HOME bridge")
        configure_guest(qga_path)
        echo = start_echo(namespaces[0]); children.append(echo)
        wait_echo(namespaces[2], "10.10.20.250", echo)
        run_checks(qga_path, namespaces, report)
        run_reload_failures(qga_path, namespaces, report)
        report["status"] = "PASS"
    except KeyboardInterrupt:
        report["status"] = "CANCELLED"
        report["error"] = "maintainer interrupted the bounded run"
    except Exception as exc:  # noqa: BLE001 - preserve first useful boundary
        report["status"] = "FAIL"
        report["error"] = str(exc)
        try:
            report["guest_diagnostics"] = guest(qga_path, "cat /proc/sys/net/ipv4/ip_forward; ip -4 addr; ip -4 route; ubus call network.interface.safety_lab status; nft -s list chain inet fw4 forward", timeout=10)
        except Exception as diagnostic_error:
            report["guest_diagnostics_error"] = str(diagnostic_error)
        if (work / "qemu-console.log").is_file():
            report["qemu_console_tail"] = (work / "qemu-console.log").read_text(encoding="utf-8", errors="replace")[-4000:]
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=5)
        cleanup_errors: list[str] = []
        for tap in taps:
            result = run("ip", "link", "del", tap, check=False)
            if result.returncode != 0 and "Cannot find device" not in result.stderr:
                cleanup_errors.append(f"tap {tap}: {result.stderr.strip()}")
        for link in links:
            result = run("ip", "link", "del", link, check=False)
            if result.returncode != 0 and "Cannot find device" not in result.stderr:
                cleanup_errors.append(f"veth {link}: {result.stderr.strip()}")
        for name in reversed(namespaces):
            result = run("ip", "netns", "del", name, check=False)
            if result.returncode != 0 and "No such file" not in result.stderr:
                cleanup_errors.append(f"namespace {name}: {result.stderr.strip()}")
        for bridge in bridges:
            result = run("ip", "link", "del", bridge, check=False)
            if result.returncode != 0 and "Cannot find device" not in result.stderr:
                cleanup_errors.append(f"bridge {bridge}: {result.stderr.strip()}")
        if cleanup_errors:
            report["status"] = "FAIL"
            report["cleanup_errors"] = cleanup_errors
        else:
            report["cleanup"] = "owned QEMU, taps, bridges, namespaces, echo process, and overlay released"
        options.results.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        options.results.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        shutil.rmtree(work, ignore_errors=True)
        if report["status"] == "PASS" and not options.results.is_file():
            report["status"] = "FAIL"
    print(json.dumps({"status": report["status"], "results": str(options.results)}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
