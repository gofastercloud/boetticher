#!/usr/bin/env python3
"""Read-only package and recovery preflight for a Boetticher Controller/Host."""

from __future__ import annotations

import argparse
import contextlib
import datetime
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Sequence

CONTROLLER_KEY = "/var/lib/boetticher/controller/ssh/id_ed25519"
CONTROLLER_KNOWN_HOSTS = "/var/lib/boetticher/controller/ssh/known_hosts"
GUEST_TARGET = re.compile(r"(lxc|qemu):([1-9][0-9]{0,8})\Z")
HOST_ACCESS = re.compile(r"Controller access\s+root@([0-9.]+)")
GUEST_LINE = re.compile(r"^\s+(\d+)\s+(\S+)\s+(lxc|qemu)\s+(running|stopped)\s+\S+\s*$")
STORAGE_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
BACKUP_STAMP = re.compile(r"vzdump-(?:lxc|qemu)-\d+-(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})")
KERNEL_IMAGE = re.compile(r"vmlinuz-(\S+)\Z")
DEFAULT_MAX_BACKUP_AGE_HOURS = 168
EXIT_READY = 0
EXIT_ERROR = 2
EXIT_BLOCKED = 3
LOCALE_ENV = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}


class PreflightError(RuntimeError):
    """A required identity or read-only check could not be established."""


@dataclass(frozen=True)
class Target:
    kind: str
    guest_type: str = ""
    guest_id: int = 0


def parse_target(value: str) -> Target:
    if value in {"controller", "host"}:
        return Target(value)
    match = GUEST_TARGET.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError("use controller, host, lxc:VMID, or qemu:VMID")
    guest_id = int(match.group(2))
    if not 100 <= guest_id <= 999_999_999:
        raise argparse.ArgumentTypeError("guest VMID must be between 100 and 999999999")
    return Target("guest", match.group(1), guest_id)


def run(argv: Sequence[str], timeout: int = 60) -> str:
    """Run one read-only command without a shell and preserve useful failures."""
    try:
        result = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=LOCALE_ENV,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError(f"command could not complete: {argv[0]} ({exc})") from exc
    output = result.stdout.strip()
    if result.returncode:
        detail = result.stderr.strip() or output or f"exit {result.returncode}"
        raise PreflightError(f"{argv[0]} failed: {detail[:500]}")
    return output


def safe_file(path: str, *, private: bool = False, executable: bool = False) -> bool:
    candidate = Path(path)
    if not candidate.is_absolute():
        return False
    current = Path("/")
    try:
        for part in candidate.parts[1:-1]:
            current = current / part
            info = os.lstat(current)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
            ):
                return False
        info = os.lstat(candidate)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        return False
    if private and info.st_mode & 0o077:
        return False
    if executable and not info.st_mode & 0o111:
        return False
    return True


def trusted_binary(path: str) -> bool:
    candidate = Path(path)
    if not candidate.is_absolute():
        return False
    current = Path("/")
    pending = list(candidate.parts[1:])
    followed_links: set[str] = set()
    while pending:
        part = pending.pop(0)
        if part in {"", ".", ".."}:
            return False
        current = current / part
        try:
            info = os.lstat(current)
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode):
            link_path = str(current)
            if info.st_uid != 0 or link_path in followed_links or len(followed_links) >= 40:
                return False
            followed_links.add(link_path)
            target = os.readlink(current)
            if not os.path.isabs(target):
                target = os.path.join(str(current.parent), target)
            resolved = Path(os.path.normpath(target))
            pending = list(resolved.parts[1:]) + pending
            current = Path("/")
            continue
        if pending:
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
            ):
                return False
            continue
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o022
            and bool(info.st_mode & 0o111)
        )
    return False


def local_boetticher() -> str:
    path = "/usr/local/bin/boetticher"
    if not trusted_binary(path):
        raise PreflightError("installed /usr/local/bin/boetticher is unavailable or unsafe")
    return path


def parse_host_status(
    text: str,
) -> tuple[str, str, dict[int, tuple[str, str, str]], list[tuple[str, set[str]]]]:
    if (
        "PASS  Host trust" not in text
        or "PASS  Enrollment" not in text
        or "Host readiness: PASS" not in text
    ):
        raise PreflightError("installed host status did not confirm trust, enrollment, and readiness")
    access = HOST_ACCESS.search(text)
    if not access:
        raise PreflightError("installed host status did not expose its enrolled IPv4 route")
    address = access.group(1)
    try:
        ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError as exc:
        raise PreflightError("installed host status returned an invalid IPv4 route") from exc
    enrollment = re.search(r"PASS\s+Enrollment\s+(\S+)", text)
    if not enrollment:
        raise PreflightError("installed host status did not expose its enrolled node")
    guests: dict[int, tuple[str, str, str]] = {}
    storages: list[tuple[str, set[str]]] = []
    in_guests = False
    in_storage = False
    for line in text.splitlines():
        if line.strip() == "Guests":
            in_guests = True
            continue
        if line.strip() == "Storage":
            in_guests = False
            in_storage = True
            continue
        if in_storage and line.strip() == "Physical disks (lsblk)":
            in_storage = False
        if in_storage:
            match = re.match(r"^\s+(\S+)\s+\S+\s+active=\d+\s+content=([^\s]+)", line)
            if match:
                storages.append((match.group(1), set(match.group(2).split(","))))
        if in_guests:
            match = GUEST_LINE.match(line)
            if match:
                guest_id, name, kind, status = match.groups()
                guests[int(guest_id)] = (name, kind, status)
    return enrollment.group(1), address, guests, storages


class Preflight:
    def __init__(
        self,
        target: Target,
        expected_name: str,
        expected_node: str = "",
        max_backup_age_hours: int = DEFAULT_MAX_BACKUP_AGE_HOURS,
    ):
        self.max_backup_age_hours = max_backup_age_hours
        self.target = target
        self.expected_name = expected_name
        self.expected_node = expected_node
        self.binary = local_boetticher()
        self.host_ip = ""

    def controller_status(self) -> str:
        status = run([self.binary, "controller", "status"])
        if "Controller readiness: PASS" not in status:
            raise PreflightError("Controller readiness is not PASS")
        hostname = run(["hostname"])
        if hostname != self.expected_name:
            raise PreflightError(
                f"Controller identity mismatch: expected {self.expected_name}, observed {hostname}"
            )
        return status

    def host_status(self) -> tuple[str, dict[int, tuple[str, str, str]], list[tuple[str, set[str]]]]:
        status = run([self.binary, "host", "status", "--details"], timeout=90)
        node, self.host_ip, guests, storages = parse_host_status(status)
        expected_node = self.expected_node or self.expected_name
        if node != expected_node:
            raise PreflightError(
                f"Host identity mismatch: expected {expected_node}, observed {node}"
            )
        return status, guests, storages

    def remote(self, command: Sequence[str], timeout: int = 60) -> str:
        if not safe_file(CONTROLLER_KEY, private=True) or not safe_file(CONTROLLER_KNOWN_HOSTS):
            raise PreflightError("Controller Host identity or pinned known-hosts file is unavailable or unsafe")
        remote_command = "LC_ALL=C " + shlex.join(command)
        return run(
            [
                "/usr/bin/ssh",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={CONTROLLER_KNOWN_HOSTS}",
                "-o",
                "IdentitiesOnly=yes",
                "-i",
                CONTROLLER_KEY,
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
                "-o",
                "ForwardAgent=no",
                "-o",
                "ForwardX11=no",
                "-o",
                "RequestTTY=no",
                f"root@{self.host_ip}",
                remote_command,
            ],
            timeout=timeout,
        )

    def run(self) -> int:
        if os.geteuid() != 0:
            raise PreflightError("run on the Controller as root, using the installed host identity")
        if self.target.kind == "controller":
            self.controller_status()
            os_release = run(["cat", "/etc/os-release"])
            os_id = parse_os_id(os_release)
            if os_id not in {"debian", "ubuntu"}:
                raise PreflightError(f"unsupported Controller operating system: {os_id or 'unknown'}")
            kernel = run(["uname", "-r"])
            reboot = run(["sh", "-c", "if test -e /var/run/reboot-required; then cat /var/run/reboot-required; else echo none; fi"])
            installed = run(["sh", "-c", "ls /boot"])
            package_plan = run(["apt-get", "-s", "dist-upgrade"], timeout=180)
            print("TARGET Controller")
            print(f"IDENTITY {self.expected_name}")
            print_os(os_release)
            print(f"RUNNING_KERNEL {kernel}")
            print_package_plan(package_plan)
            print(f"REBOOT_MARKER {reboot}")
            print_kernel_state(kernel, installed)
            print("RECOVERY HOLD: no Controller backup or recovery readiness was verified")
            return 0

        if self.target.kind == "guest" and not self.expected_node:
            raise PreflightError("guest targets require --expect-node for the enrolled Proxmox Host")
        _, guests, storages = self.host_status()
        if self.target.kind == "host":
            print(f"TARGET Proxmox Host {self.expected_name}")
            print(f"ROUTE root@{self.host_ip} (strict pinned-key SSH)")
            self.report_host(storages)
            return 0

        guest = guests.get(self.target.guest_id)
        if guest is None:
            raise PreflightError(f"guest {self.target.guest_id} is not in the enrolled Host inventory")
        name, kind, state = guest
        if kind != self.target.guest_type:
            raise PreflightError(
                f"guest type mismatch: requested {self.target.guest_type}, inventory says {kind}"
            )
        if name != self.expected_name:
            raise PreflightError(
                f"guest identity mismatch: expected {self.expected_name}, observed {name}"
            )
        if state != "running":
            raise PreflightError(f"guest {self.target.guest_id} is {state}; no guest query was run")
        print(f"TARGET {kind} {self.target.guest_id}")
        print(f"IDENTITY {name} ({state})")
        self.report_guest(kind, self.target.guest_id, storages)
        return 0

    def report_host(self, storages: list[tuple[str, set[str]]]) -> None:
        version = self.remote(["pveversion"])
        kernel = self.remote(["uname", "-r"])
        packages = self.remote(["apt-get", "-s", "dist-upgrade"], timeout=300)
        reboot = self.remote(["sh", "-c", "if test -e /var/run/reboot-required; then cat /var/run/reboot-required; else echo none; fi"])
        installed = self.remote(["ls", "/boot"])
        backup_inventory = self.list_backups(storages)
        capacity = self.remote(["pvesm", "status"])
        print(f"VERSION {version}")
        print(f"RUNNING_KERNEL {kernel}")
        print_package_plan(packages)
        print(f"REBOOT_MARKER {reboot}")
        print_kernel_state(kernel, installed)
        print("STORAGE_CAPACITY")
        print(capacity)
        print("BACKUP_INVENTORY")
        print(backup_inventory or "no backup archive observed in registered backup-capable storage")
        print("RECOVERY HOLD: archive coverage and restore readiness require operator review")

    def list_backups(self, storages: list[tuple[str, set[str]]]) -> str:
        observed: list[str] = []
        for storage, content in storages:
            if "backup" not in content:
                continue
            if not STORAGE_ID.fullmatch(storage):
                raise PreflightError("Host status returned an invalid storage identifier")
            result = self.remote(["pvesm", "list", storage, "--content", "backup"])
            entries = [entry for entry in result.splitlines()[1:] if entry.strip()]
            observed.extend(f"{storage} {entry.strip()}" for entry in entries)
        if not any("backup" in content for _, content in storages):
            return "no registered storage advertises backup content"
        return "\n".join(observed)

    def report_guest(
        self, kind: str, guest_id: int, storages: list[tuple[str, set[str]]]
    ) -> None:
        if kind == "lxc":
            self.remote(["pct", "status", str(guest_id)])
            config = self.remote(
                [
                    "sh",
                    "-c",
                    f"pct config {guest_id} | grep -E '^(hostname|ostype|arch|onboot|startup|unprivileged|rootfs|mp[0-9]+):'",
                ]
            )
            os_release = self.remote(["pct", "exec", str(guest_id), "--", "cat", "/etc/os-release"])
            guest_os = os_release
        else:
            self.remote(["qm", "status", str(guest_id)])
            config = self.remote(
                [
                    "sh",
                    "-c",
                    f"qm config {guest_id} | grep -E '^(name|bios|machine|ostype|onboot|startup|agent|boot|scsi[0-9]+|virtio[0-9]+|sata[0-9]+|ide[0-9]+|efidisk[0-9]+):'",
                ]
            )
            os_info = self.remote(["qm", "guest", "cmd", str(guest_id), "get-osinfo"], timeout=20)
            os_data = json.loads(os_info)
            guest_os = json.dumps(os_data, sort_keys=True)
        os_id = parse_os_id(guest_os)
        print(f"CONFIG\n{config}")
        print_os(guest_os)
        matching_backups = [
            entry for entry in self.list_backups(storages).splitlines()
            if matches_guest_backup(entry, kind, guest_id)
        ]
        print("BACKUP_INVENTORY")
        print("\n".join(matching_backups) or f"no {kind} {guest_id} backup archive observed")
        host_now = self.remote(["date", "+%Y_%m_%d-%H_%M_%S"]) if matching_backups else ""
        print(backup_freshness(matching_backups, host_now, self.max_backup_age_hours))
        if os_id not in {"debian", "ubuntu"}:
            print("PACKAGE_PLAN UNSUPPORTED: only Debian and Ubuntu package simulation is included")
            print("RECOVERY HOLD: use the appliance or provider-specific update procedure")
            return
        if kind == "lxc":
            package_plan = self.remote(
                ["pct", "exec", str(guest_id), "--", "env", "LC_ALL=C", "apt-get", "-s", "dist-upgrade"],
                timeout=180
            )
        else:
            package_result = self.remote(
                [
                    "qm",
                    "guest",
                    "exec",
                    str(guest_id),
                    "--synchronous",
                    "1",
                    "--timeout",
                    "120",
                    "--",
                    "/usr/bin/env",
                    "LC_ALL=C",
                    "/usr/bin/apt-get",
                    "-s",
                    "dist-upgrade",
                ],
                timeout=150,
            )
            package_data = json.loads(package_result)
            if package_data.get("exitcode") != 0:
                raise PreflightError("guest package simulation failed")
            package_plan = str(package_data.get("out-data", ""))
        print_package_plan(package_plan)
        print("RECOVERY HOLD: verify software/config/database restore scope and record explicit data exclusions")


def matches_guest_backup(entry: str, kind: str, guest_id: int) -> bool:
    fields = entry.split()
    if not fields:
        return False
    volume = fields[0].rsplit(":", 1)[-1]
    match = re.match(r"^vzdump-(lxc|qemu)-(\d+)-", volume)
    return bool(match and match.group(1) == kind and int(match.group(2)) == guest_id)


def parse_os_id(text: str) -> str:
    try:
        data = json.loads(text)
        return str(data.get("id", "")).lower()
    except (json.JSONDecodeError, AttributeError):
        match = re.search(r"^ID=(?:\"([^\"]+)\"|([^\s]+))$", text, re.MULTILINE)
        return (match.group(1) or match.group(2)).lower() if match else ""


def print_os(text: str) -> None:
    lines = []
    for key in ("PRETTY_NAME", "VERSION_ID"):
        match = re.search(rf"^{key}=(.*)$", text, re.MULTILINE)
        if match:
            lines.append(f"{key}={match.group(1).strip(chr(34))}")
    if not lines:
        try:
            data = json.loads(text)
            lines = [f"OS={data.get('pretty-name', data.get('name', 'unknown'))}"]
        except json.JSONDecodeError:
            lines = ["OS=unavailable"]
    print("\n".join(lines))


def print_package_plan(text: str) -> None:
    installs = [line for line in text.splitlines() if line.startswith("Inst ")]
    removals = [line for line in text.splitlines() if line.startswith("Remv ")]
    summary = next((line for line in text.splitlines() if " upgraded," in line), "summary unavailable")
    print(f"PACKAGE_SIMULATION installs={len(installs)} removals={len(removals)}")
    print(f"PACKAGE_SUMMARY {summary}")
    for line in removals[:10]:
        print(f"PACKAGE_REMOVAL {line}")
    if removals:
        print("PACKAGE_PLAN HOLD: simulation proposes removals")
    elif summary == "summary unavailable":
        print("PACKAGE_PLAN HOLD: simulation summary could not be parsed")
    else:
        print("PACKAGE_PLAN review required; indexes were not refreshed")


def kernel_key(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"[.\-+_]", version))


def print_kernel_state(running: str, boot_listing: str) -> None:
    """Compare the running kernel with the newest installed one; the
    reboot-required marker is Debian/Ubuntu-specific and absent on Proxmox."""
    installed = [m.group(1) for name in boot_listing.split() if (m := KERNEL_IMAGE.fullmatch(name))]
    if not installed:
        print("KERNEL_PENDING unknown: no /boot/vmlinuz-* images found")
        return
    newest = max(installed, key=kernel_key)
    if kernel_key(newest) > kernel_key(running):
        print(f"KERNEL_PENDING yes running={running} installed={newest}")
    else:
        print(f"KERNEL_PENDING no running={running} installed={newest}")


def backup_freshness(entries: Sequence[str], host_now: str, max_age_hours: int) -> str:
    """Report the newest archive age against the Host clock (both Host-local)."""
    stamps = []
    for entry in entries:
        match = BACKUP_STAMP.search(entry)
        if match:
            stamps.append(datetime.datetime.strptime(match.group(1), "%Y_%m_%d-%H_%M_%S"))
    if not stamps:
        return "BACKUP_FRESHNESS none: no dated archive observed"
    try:
        now = datetime.datetime.strptime(host_now.strip(), "%Y_%m_%d-%H_%M_%S")
    except ValueError:
        return "BACKUP_FRESHNESS unknown: Host clock could not be read"
    age = (now - max(stamps)).total_seconds() / 3600
    state = "fresh" if age <= max_age_hours else "stale"
    return f"BACKUP_FRESHNESS {state} newest_age_hours={age:.1f} limit_hours={max_age_hours}"


def blocking_lines(lines: Sequence[str]) -> list[str]:
    """Lines that stop an upgrade. The standing RECOVERY HOLD is review-only."""
    blocked = []
    for line in lines:
        if line.startswith(("PACKAGE_PLAN HOLD", "PACKAGE_PLAN UNSUPPORTED")):
            blocked.append(line)
        elif line.startswith(("BACKUP_FRESHNESS none", "BACKUP_FRESHNESS stale", "BACKUP_FRESHNESS unknown")):
            blocked.append(line)
    return blocked


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        required=True,
        type=parse_target,
        help="one explicit target: controller, host, lxc:VMID, or qemu:VMID",
    )
    parser.add_argument("--expect-name", required=True, help="expected Controller, Host node, or guest name")
    parser.add_argument("--expect-node", help="expected enrolled Proxmox node for a guest target")
    parser.add_argument(
        "--max-backup-age-hours",
        type=int,
        default=DEFAULT_MAX_BACKUP_AGE_HOURS,
        help="newest guest archive older than this blocks the plan (default 168)",
    )
    parser.add_argument("--json", action="store_true", help="emit one machine-readable JSON result")
    args = parser.parse_args(argv)
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            Preflight(
                args.target, args.expect_name, args.expect_node or "", args.max_backup_age_hours
            ).run()
    except PreflightError as exc:
        print(f"HOLD {exc}", file=sys.stderr)
        return EXIT_ERROR
    lines = captured.getvalue().splitlines()
    blocked = blocking_lines(lines)
    if args.json:
        print(json.dumps({"status": "blocked" if blocked else "review", "blocking": blocked, "lines": lines}))
    else:
        print("\n".join(lines))
    return EXIT_BLOCKED if blocked else EXIT_READY


if __name__ == "__main__":
    raise SystemExit(main())
