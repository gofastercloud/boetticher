from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "maintain-homelab.py"
SPEC = importlib.util.spec_from_file_location("maintain_homelab", SCRIPT)
assert SPEC and SPEC.loader
maintenance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = maintenance
SPEC.loader.exec_module(maintenance)


HOST_STATUS = """Proxmox host
PASS  Host trust         Established
PASS  Controller access  root@192.0.2.10 (node pve-one)
PASS  Enrollment         pve-one
PASS  Proxmox            pve-manager/9.2.20
Host readiness: PASS

Guests
  120  monitor-01              lxc  running    pve-one
  290  media-01                qemu running    pve-one

Storage
  local            dir      active=1 content=rootdir,backup
  data             lvmthin  active=1 content=rootdir,images
Physical disks (lsblk)
"""


class MaintainHomelabTests(unittest.TestCase):
    def test_explicit_targets_are_bounded_and_reject_shell_text(self):
        self.assertEqual(maintenance.parse_target("lxc:120"), maintenance.Target("guest", "lxc", 120))
        self.assertEqual(maintenance.parse_target("qemu:290"), maintenance.Target("guest", "qemu", 290))
        for value in ("all", "openwrt:280", "lxc:1;id", "qemu:1000000000", "host; reboot"):
            with self.subTest(value=value), self.assertRaises(maintenance.argparse.ArgumentTypeError):
                maintenance.parse_target(value)

    def test_host_status_requires_trust_readiness_and_parses_bound_targets(self):
        node, address, guests, storages = maintenance.parse_host_status(HOST_STATUS)
        self.assertEqual((node, address), ("pve-one", "192.0.2.10"))
        self.assertEqual(guests[120], ("monitor-01", "lxc", "running"))
        self.assertEqual(guests[290], ("media-01", "qemu", "running"))
        self.assertEqual(storages, [("local", {"rootdir", "backup"}), ("data", {"rootdir", "images"})])
        for changed in (
            HOST_STATUS.replace("PASS  Host trust", "FAIL  Host trust"),
            HOST_STATUS.replace("Host readiness: PASS", "Host readiness: HOLD"),
            HOST_STATUS.replace("root@192.0.2.10", "root@999.1.1.1"),
        ):
            with self.subTest(changed=changed[-80:]), self.assertRaises(maintenance.PreflightError):
                maintenance.parse_host_status(changed)

    def test_guest_identity_mismatch_stops_before_any_guest_query(self):
        check = maintenance.Preflight.__new__(maintenance.Preflight)
        check.target = maintenance.Target("guest", "lxc", 120)
        check.expected_name = "unexpected"
        check.expected_node = "pve-one"
        check.binary = "/usr/local/bin/boetticher"
        with mock.patch.object(check, "host_status", return_value=("status", {120: ("monitor-01", "lxc", "running")}, [])):
            with mock.patch.object(maintenance.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(maintenance.PreflightError, "identity mismatch"):
                    check.run()

    def test_unsupported_appliance_does_not_run_apt_or_guest_exec(self):
        check = maintenance.Preflight.__new__(maintenance.Preflight)
        check.host_ip = "192.0.2.10"
        check.max_backup_age_hours = 168
        calls = []

        def fake_remote(command, timeout=60):
            calls.append(list(command))
            if command[:3] == ["qm", "guest", "cmd"]:
                return '{"id":"openwrt","pretty-name":"OpenWrt 25.12.5"}'
            return "ostype: l26"

        check.remote = fake_remote
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check.report_guest("qemu", 280, [])
        self.assertIn("UNSUPPORTED", output.getvalue())
        self.assertFalse(any("apt-get" in call or "exec" in call for call in calls))

    def test_remote_uses_pinned_strict_ssh_and_argv_execution(self):
        check = maintenance.Preflight.__new__(maintenance.Preflight)
        check.host_ip = "192.0.2.10"
        with mock.patch.object(maintenance, "safe_file", return_value=True):
            with mock.patch.object(maintenance, "run", return_value="ok") as run:
                self.assertEqual(check.remote(["qm", "config", "290"]), "ok")
        argv = run.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn(f"UserKnownHostsFile={maintenance.CONTROLLER_KNOWN_HOSTS}", argv)
        self.assertIn(f"-i", argv)
        self.assertEqual(argv[-2], "root@192.0.2.10")
        self.assertEqual(argv[-1], "LC_ALL=C qm config 290")
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_trust_files_require_root_owned_safe_paths_and_private_key_mode(self):
        def info(mode, uid=0):
            return SimpleNamespace(st_mode=mode, st_uid=uid)

        def safe_lstat(path):
            if Path(path) == Path(maintenance.CONTROLLER_KEY):
                return info(stat.S_IFREG | 0o600)
            return info(stat.S_IFDIR | 0o755)

        with mock.patch.object(maintenance.os, "lstat", side_effect=safe_lstat):
            self.assertTrue(maintenance.safe_file(maintenance.CONTROLLER_KEY, private=True))

        def writable_parent(path):
            if Path(path) == Path("/var/lib"):
                return info(stat.S_IFDIR | 0o777)
            return safe_lstat(path)

        with mock.patch.object(maintenance.os, "lstat", side_effect=writable_parent):
            self.assertFalse(maintenance.safe_file(maintenance.CONTROLLER_KEY, private=True))

        def broad_private_mode(path):
            if Path(path) == Path(maintenance.CONTROLLER_KEY):
                return info(stat.S_IFREG | 0o640)
            return safe_lstat(path)

        with mock.patch.object(maintenance.os, "lstat", side_effect=broad_private_mode):
            self.assertFalse(maintenance.safe_file(maintenance.CONTROLLER_KEY, private=True))

        def symlink_key(path):
            if Path(path) == Path(maintenance.CONTROLLER_KEY):
                return info(stat.S_IFLNK | 0o777)
            return safe_lstat(path)

        with mock.patch.object(maintenance.os, "lstat", side_effect=symlink_key):
            self.assertFalse(maintenance.safe_file(maintenance.CONTROLLER_KEY, private=True))

        def wrong_owner(path):
            if Path(path) == Path(maintenance.CONTROLLER_KEY):
                return info(stat.S_IFREG | 0o600)
            return info(stat.S_IFDIR | 0o755, uid=501)

        with mock.patch.object(maintenance.os, "lstat", side_effect=wrong_owner):
            self.assertFalse(maintenance.safe_file(maintenance.CONTROLLER_KEY, private=True))

    def test_controller_binary_path_is_fixed(self):
        with mock.patch.object(maintenance, "trusted_binary", return_value=True) as trusted:
            self.assertEqual(maintenance.local_boetticher(), "/usr/local/bin/boetticher")
        trusted.assert_called_once_with("/usr/local/bin/boetticher")

    def test_installed_binary_chain_allows_root_owned_release_links_and_rejects_unsafe_paths(self):
        root = "/"
        entries = {
            "/usr": (stat.S_IFDIR | 0o755, 0),
            "/usr/local": (stat.S_IFDIR | 0o755, 0),
            "/usr/local/bin": (stat.S_IFDIR | 0o755, 0),
            "/usr/local/bin/boetticher": (stat.S_IFLNK | 0o777, 0),
            "/opt": (stat.S_IFDIR | 0o755, 0),
            "/opt/boetticher": (stat.S_IFDIR | 0o755, 0),
            "/opt/boetticher/current": (stat.S_IFLNK | 0o777, 0),
            "/opt/boetticher/releases": (stat.S_IFDIR | 0o755, 0),
            "/opt/boetticher/releases/release": (stat.S_IFDIR | 0o755, 0),
            "/opt/boetticher/releases/release/bin": (stat.S_IFDIR | 0o755, 0),
            "/opt/boetticher/releases/release/bin/boetticher": (stat.S_IFREG | 0o755, 0),
        }
        links = {
            "/usr/local/bin/boetticher": "/opt/boetticher/current/bin/boetticher",
            "/opt/boetticher/current": "releases/release",
        }

        def lstat(path):
            mode, uid = entries[str(path)]
            return SimpleNamespace(st_mode=mode, st_uid=uid)

        with mock.patch.object(maintenance.os, "lstat", side_effect=lstat):
            with mock.patch.object(maintenance.os, "readlink", side_effect=lambda path: links[str(path)]):
                self.assertTrue(maintenance.trusted_binary("/usr/local/bin/boetticher"))

        entries["/opt/boetticher/releases"] = (stat.S_IFDIR | 0o775, 0)
        with mock.patch.object(maintenance.os, "lstat", side_effect=lstat):
            with mock.patch.object(maintenance.os, "readlink", side_effect=lambda path: links[str(path)]):
                self.assertFalse(maintenance.trusted_binary("/usr/local/bin/boetticher"))

        entries["/opt/boetticher/releases"] = (stat.S_IFDIR | 0o755, 0)
        entries["/usr/local/bin/boetticher"] = (stat.S_IFLNK | 0o777, 501)
        with mock.patch.object(maintenance.os, "lstat", side_effect=lstat):
            with mock.patch.object(maintenance.os, "readlink", side_effect=lambda path: links[str(path)]):
                self.assertFalse(maintenance.trusted_binary("/usr/local/bin/boetticher"))

    def test_backup_matching_uses_exact_guest_id(self):
        self.assertTrue(
            maintenance.matches_guest_backup(
                "local:vzdump-qemu-290-2026_10_06-01_00_00.vma.zst vma.zst backup 1024",
                "qemu",
                290,
            )
        )
        self.assertFalse(
            maintenance.matches_guest_backup(
                "local:vzdump-qemu-2900-2026_10_06-01_00_00.vma.zst vma.zst backup 1024",
                "qemu",
                290,
            )
        )

    def test_remote_rejects_a_key_that_does_not_pass_private_file_check(self):
        check = maintenance.Preflight.__new__(maintenance.Preflight)
        check.host_ip = "192.0.2.10"

        def key_is_unsafe(path, *, private=False, executable=False):
            if path == maintenance.CONTROLLER_KEY:
                return not private
            return True

        with mock.patch.object(maintenance, "safe_file", side_effect=key_is_unsafe):
            with mock.patch.object(maintenance, "run") as run:
                with self.assertRaisesRegex(maintenance.PreflightError, "unavailable or unsafe"):
                    check.remote(["qm", "config", "290"])
        run.assert_not_called()

    def test_process_runner_preserves_error_and_never_requests_a_shell(self):
        with mock.patch.object(
            maintenance.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=9, stdout="", stderr="permission denied"),
        ) as run:
            with self.assertRaisesRegex(maintenance.PreflightError, "permission denied"):
                maintenance.run(["apt-get", "-s", "dist-upgrade"])
        self.assertIsInstance(run.call_args.args[0], list)
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertIn("-s", run.call_args.args[0])

    def test_backup_listing_queries_only_storage_that_advertises_backup(self):
        check = maintenance.Preflight.__new__(maintenance.Preflight)
        check.remote = mock.Mock(return_value="Volid Format Type Size")
        self.assertEqual(
            check.list_backups([("local", {"rootdir", "backup"}), ("data", {"images"})]),
            "",
        )
        check.remote.assert_called_once_with(["pvesm", "list", "local", "--content", "backup"])

    def test_removal_simulation_is_reported_as_hold(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            maintenance.print_package_plan(
                "Remv old-package [1.0]\\n2 upgraded, 0 newly installed, 1 to remove and 0 not upgraded."
            )
        self.assertIn("removals=1", output.getvalue())
        self.assertIn("PACKAGE_PLAN HOLD", output.getvalue())

    def test_pending_kernel_compares_running_with_newest_installed(self):
        for running, listing, expected in (
            ("6.17.2-1-pve", "vmlinuz-6.17.2-1-pve vmlinuz-6.17.4-1-pve config-6.17.4-1-pve", "yes"),
            ("6.17.4-1-pve", "vmlinuz-6.17.2-1-pve vmlinuz-6.17.4-1-pve", "no"),
            ("6.9.1-pve", "vmlinuz-6.10.1-pve", "yes"),
        ):
            output = io.StringIO()
            with self.subTest(running=running), contextlib.redirect_stdout(output):
                maintenance.print_kernel_state(running, listing)
            self.assertIn(f"KERNEL_PENDING {expected}", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            maintenance.print_kernel_state("6.1.0", "config-6.1.0")
        self.assertIn("KERNEL_PENDING unknown", output.getvalue())

    def test_backup_freshness_uses_newest_archive_and_host_clock(self):
        entries = [
            "local:backup/vzdump-lxc-120-2026_10_01-01_00_00.tar.zst tar.zst backup 1",
            "local:backup/vzdump-lxc-120-2026_10_05-01_00_00.tar.zst tar.zst backup 1",
        ]
        self.assertIn("fresh newest_age_hours=48.0", maintenance.backup_freshness(entries, "2026_10_07-01_00_00", 168))
        self.assertIn("stale", maintenance.backup_freshness(entries, "2026_10_07-01_00_00", 24))
        self.assertIn("none", maintenance.backup_freshness([], "", 168))
        self.assertIn("unknown", maintenance.backup_freshness(entries, "garbage", 168))

    def test_only_plan_and_backup_holds_block_and_recovery_hold_is_review_only(self):
        self.assertEqual(maintenance.blocking_lines(["RECOVERY HOLD: review", "PACKAGE_PLAN review required"]), [])
        blocked = maintenance.blocking_lines(
            ["PACKAGE_PLAN HOLD: simulation proposes removals", "BACKUP_FRESHNESS stale x", "BACKUP_FRESHNESS fresh y"]
        )
        self.assertEqual(len(blocked), 2)

    def test_main_returns_distinct_exit_codes_and_json(self):
        def fake_run(self):
            print("PACKAGE_PLAN HOLD: simulation proposes removals")
            return 0

        output = io.StringIO()
        with mock.patch.object(maintenance.Preflight, "__init__", lambda *a, **k: None):
            with mock.patch.object(maintenance.Preflight, "run", fake_run):
                with contextlib.redirect_stdout(output):
                    code = maintenance.main(["--target", "controller", "--expect-name", "c", "--json"])
        self.assertEqual(code, maintenance.EXIT_BLOCKED)
        self.assertEqual(json.loads(output.getvalue())["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
