import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "files" / "boetticher-usb-export"
LOADER = importlib.machinery.SourceFileLoader("boetticher_usb_export", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
usb_export = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(usb_export)


class USBExportHostTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        usb_export.SYS_USB = self.root / "sys" / "bus" / "usb" / "devices"
        usb_export.DEV_ROOT = self.root / "dev"
        usb_export.DEV_USB = usb_export.DEV_ROOT / "bus" / "usb"
        usb_export.MANIFEST_DIR = self.root / "etc" / "boetticher" / "usb-exports"
        usb_export.STATE_DIR = self.root / "var" / "lib" / "boetticher" / "usb-export"
        usb_export.LOCK_DIR = self.root / "run" / "lock"
        for directory in (
            usb_export.SYS_USB,
            usb_export.DEV_USB,
            usb_export.MANIFEST_DIR,
            usb_export.STATE_DIR,
            usb_export.LOCK_DIR,
        ):
            directory.mkdir(parents=True)
        self.sleep = mock.patch.object(usb_export.time, "sleep", return_value=None)
        self.sleep.start()

    def tearDown(self):
        self.sleep.stop()
        self.temporary.cleanup()

    def parent(self, port="1-2.4", vendor="1a86", product="7523", bus="1", device="41"):
        parent = usb_export.SYS_USB / port
        parent.mkdir(parents=True, exist_ok=True)
        (parent / "idVendor").write_text(vendor + "\n")
        (parent / "idProduct").write_text(product + "\n")
        (parent / "busnum").write_text(bus + "\n")
        (parent / "devnum").write_text(device + "\n")
        return parent

    def add_tty(self, parent, name):
        tty = parent / f"{parent.name}:1.0" / "tty" / name
        tty.mkdir(parents=True)
        device = usb_export.DEV_ROOT / name
        device.touch()
        return device

    def serial_export(self, **overrides):
        export = {
            "port": "1-2.4",
            "vendor_id": "1a86",
            "product_id": "7523",
            "device_type": "serial",
        }
        export.update(overrides)
        return export

    def manifest(self):
        return {
            "vmid": 230,
            "hostname": "lab-printer-01",
            "ownership_tag": "module-printer",
            "unprivileged": True,
            "managed_slots": ["dev0"],
            "exports": [{**self.serial_export(), "slot": "dev0"}],
        }

    def write_manifest(self, manifest=None):
        path = usb_export.MANIFEST_DIR / "230.json"
        path.write_text(json.dumps(manifest or self.manifest()))
        return path

    def test_physical_port_tracks_raw_usb_bus_and_device_renumbering(self):
        parent = self.parent(bus="1", device="41")
        first = usb_export.DEV_USB / "001" / "041"
        first.parent.mkdir(parents=True, exist_ok=True)
        first.touch()
        export = self.serial_export(device_type="raw-usb")
        with mock.patch.object(usb_export.stat, "S_ISCHR", return_value=True):
            self.assertEqual(usb_export.resolve(export), str(first))
            (parent / "busnum").write_text("2\n")
            (parent / "devnum").write_text("7\n")
            second = usb_export.DEV_USB / "002" / "007"
            second.parent.mkdir(parents=True)
            second.touch()
            self.assertEqual(usb_export.resolve(export), str(second))

    def test_serial_resolution_tracks_ttyusb_reenumeration(self):
        parent = self.parent()
        first = self.add_tty(parent, "ttyUSB0")
        with mock.patch.object(usb_export.stat, "S_ISCHR", return_value=True):
            self.assertEqual(usb_export.resolve(self.serial_export()), str(first))
            shutil.rmtree(parent / f"{parent.name}:1.0")
            first.unlink()
            second = self.add_tty(parent, "ttyUSB7")
            self.assertEqual(usb_export.resolve(self.serial_export()), str(second))

    def test_wrong_vendor_or_product_holds(self):
        for field, value in (("vendor_id", "ffff"), ("product_id", "ffff")):
            with self.subTest(field=field):
                self.parent()
                with self.assertRaises(usb_export.Hold):
                    usb_export.resolve(self.serial_export(**{field: value}))

    def test_absent_tty_returns_no_mapping(self):
        self.parent()
        self.assertIsNone(usb_export.resolve(self.serial_export()))

    def test_multiple_tty_descendants_hold(self):
        parent = self.parent()
        self.add_tty(parent, "ttyUSB0")
        self.add_tty(parent, "ttyUSB1")
        with self.assertRaises(usb_export.Hold):
            usb_export.resolve(self.serial_export())

    def test_non_character_serial_device_holds(self):
        parent = self.parent()
        self.add_tty(parent, "ttyUSB0")
        with self.assertRaises(usb_export.Hold):
            usb_export.resolve(self.serial_export())

    def test_raw_usb_resolution_remains_supported(self):
        self.parent()
        device = usb_export.DEV_USB / "001" / "041"
        device.parent.mkdir(parents=True, exist_ok=True)
        device.touch()
        with mock.patch.object(usb_export.stat, "S_ISCHR", return_value=True):
            self.assertEqual(
                usb_export.resolve(self.serial_export(device_type="raw-usb")),
                str(device),
            )

    def test_unplug_removes_mapping_and_restarts_running_guest(self):
        path = self.write_manifest()
        old_value = f"{usb_export.DEV_ROOT}/ttyUSB0,uid=2200,gid=2200,mode=0660"
        (usb_export.STATE_DIR / "230.json").write_text(
            json.dumps({"vmid": 230, "managed": {"dev0": old_value}})
        )
        devices = {"dev0": old_value}
        calls = []

        def fake_run(*args):
            calls.append(args)
            if args[:2] == ("pct", "config"):
                lines = [
                    "hostname: lab-printer-01",
                    "tags: boetticher;managed;module-printer",
                    "unprivileged: 1",
                ]
                lines.extend(f"{slot}: {value}" for slot, value in devices.items())
                return "\n".join(lines)
            if args[:4] == ("pct", "set", "230", "--delete"):
                devices.pop(args[4])
                return ""
            if args[:2] == ("pct", "status"):
                return "status: running\n"
            if args[:2] == ("pct", "reboot"):
                return ""
            self.fail(f"unexpected command: {args}")

        with mock.patch.object(usb_export, "run", side_effect=fake_run):
            usb_export.reconcile(path)
        self.assertIn(("pct", "set", "230", "--delete", "dev0"), calls)
        self.assertIn(("pct", "reboot", "230"), calls)
        state = json.loads((usb_export.STATE_DIR / "230.json").read_text())
        self.assertEqual(state["managed"], {})

    def test_unchanged_mapping_restarts_running_guest_when_device_is_missing(self):
        parent = self.parent()
        device = self.add_tty(parent, "ttyUSB0")
        path = self.write_manifest()
        value = f"{device},uid=2200,gid=2200,mode=0660"
        calls = []

        def fake_run(*args):
            calls.append(args)
            if args[:2] == ("pct", "config"):
                return "\n".join(
                    [
                        "hostname: lab-printer-01",
                        "tags: boetticher;managed;module-printer",
                        "unprivileged: 1",
                        f"dev0: {value}",
                    ]
                )
            if args[:2] == ("pct", "status"):
                return "status: running\n"
            if args[:2] == ("pct", "reboot"):
                return ""
            self.fail(f"unexpected command: {args}")

        missing = mock.Mock(returncode=1, stderr="")
        with mock.patch.object(usb_export.stat, "S_ISCHR", return_value=True), mock.patch.object(
            usb_export, "run", side_effect=fake_run
        ), mock.patch.object(usb_export, "run_result", return_value=missing) as run_result:
            usb_export.reconcile(path)

        run_result.assert_called_once_with(
            "pct", "exec", "230", "--", "test", "-c", str(device)
        )
        self.assertIn(("pct", "reboot", "230"), calls)
        state = json.loads((usb_export.STATE_DIR / "230.json").read_text())
        self.assertEqual(state["managed"], {"dev0": value})

    def test_unchanged_mapping_does_not_restart_when_device_is_present(self):
        parent = self.parent()
        device = self.add_tty(parent, "ttyUSB0")
        path = self.write_manifest()
        value = f"{device},uid=2200,gid=2200,mode=0660"
        calls = []

        def fake_run(*args):
            calls.append(args)
            if args[:2] == ("pct", "config"):
                return "\n".join(
                    [
                        "hostname: lab-printer-01",
                        "tags: boetticher;managed;module-printer",
                        "unprivileged: 1",
                        f"dev0: {value}",
                    ]
                )
            if args[:2] == ("pct", "status"):
                return "status: running\n"
            self.fail(f"unexpected command: {args}")

        present = mock.Mock(returncode=0, stderr="")
        with mock.patch.object(usb_export.stat, "S_ISCHR", return_value=True), mock.patch.object(
            usb_export, "run", side_effect=fake_run
        ), mock.patch.object(usb_export, "run_result", return_value=present) as run_result:
            usb_export.reconcile(path)

        run_result.assert_called_once_with(
            "pct", "exec", "230", "--", "test", "-c", str(device)
        )
        self.assertFalse(any(call[:2] == ("pct", "reboot") for call in calls))

    def test_failed_post_change_verification_never_restarts(self):
        parent = self.parent()
        device = self.add_tty(parent, "ttyUSB0")
        path = self.write_manifest()
        calls = []

        def fake_run(*args):
            calls.append(args)
            if args[:2] == ("pct", "config"):
                return "hostname: lab-printer-01\ntags: boetticher;managed;module-printer\nunprivileged: 1\n"
            if args[:2] == ("pct", "set"):
                return ""
            self.fail(f"command must not run after failed verification: {args}")

        with mock.patch.object(usb_export.stat, "S_ISCHR", return_value=True), mock.patch.object(
            usb_export, "run", side_effect=fake_run
        ):
            with self.assertRaisesRegex(usb_export.Hold, "post-change verification"):
                usb_export.reconcile(path)
        self.assertIn(
            ("pct", "set", "230", "--dev0", f"{device},uid=2200,gid=2200,mode=0660"),
            calls,
        )
        self.assertFalse(any(call[:2] == ("pct", "reboot") for call in calls))
        self.assertFalse((usb_export.STATE_DIR / "230.json").exists())

    def test_remove_manifest_removes_only_the_exact_vmid_state(self):
        self.write_manifest()
        (usb_export.STATE_DIR / "230.json").write_text(json.dumps({"vmid": 230, "managed": {}}))
        other_manifest = usb_export.MANIFEST_DIR / "231.json"
        other_manifest.write_text(json.dumps({"vmid": 231}))
        other_state = usb_export.STATE_DIR / "231.json"
        other_state.write_text(json.dumps({"vmid": 231, "managed": {}}))

        usb_export.remove_manifest(230)

        self.assertFalse((usb_export.MANIFEST_DIR / "230.json").exists())
        self.assertFalse((usb_export.STATE_DIR / "230.json").exists())
        self.assertTrue(other_manifest.exists())
        self.assertTrue(other_state.exists())

    def test_remove_manifest_rejects_filename_identity_mismatch(self):
        path = usb_export.MANIFEST_DIR / "230.json"
        path.write_text(json.dumps({"vmid": 231}))

        with self.assertRaisesRegex(usb_export.Hold, "does not match"):
            usb_export.remove_manifest(230)

        self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
