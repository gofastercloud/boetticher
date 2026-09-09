import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build-temp.py"


class BuildTempTest(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], text=True, capture_output=True)

    def test_cleanup_respects_lock_marker_age_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runs"
            active = subprocess.Popen([sys.executable, str(SCRIPT), "run", str(root), "--", sys.executable, "-c", "import time; time.sleep(30)"])
            for _ in range(30):
                if list(root.glob("run-*")):
                    break
                time.sleep(0.01)
            active_dir = next(root.glob("run-*"))
            os.utime(active_dir, (time.time() - 7200, time.time() - 7200))
            old = root / "run-old"
            old.mkdir(parents=True)
            (old / ".boetticher-build-owned").write_text('{"version":1}\n')
            (old / ".boetticher-build.lock").touch()
            os.utime(old, (time.time() - 7200, time.time() - 7200))
            young = root / "run-young"
            young.mkdir()
            (young / ".boetticher-build-owned").write_text('{"version":1}\n')
            (young / ".boetticher-build.lock").touch()
            symlink = root / "run-link"
            symlink.symlink_to(old, target_is_directory=True)
            try:
                result = self.run_tool("preview", str(root), "--grace", "3600")
                self.assertIn("active build lock", result.stdout)
                self.assertIn("younger than grace", result.stdout)
                self.assertIn("symlink or non-directory", result.stdout)
                self.assertIn("owned inactive build", result.stdout)
                self.assertEqual(self.run_tool("clean", str(root), "--grace", "3600", "--yes").returncode, 0)
                self.assertTrue(active_dir.exists())
                self.assertFalse(old.exists())
                self.assertTrue(young.exists())
            finally:
                active.send_signal(signal.SIGTERM)
                active.wait(timeout=3)

    def test_keep_build_files_preserves_owned_inactive_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runs"
            owned = root / "run-owned"
            owned.mkdir(parents=True)
            (owned / ".boetticher-build-owned").write_text('{"version":1}\n')
            (owned / ".boetticher-build.lock").touch()
            os.utime(owned, (time.time() - 7200, time.time() - 7200))
            result = self.run_tool("clean", str(root), "--grace", "3600", "--keep-build-files")
            self.assertEqual(result.returncode, 0)
            self.assertTrue(owned.exists())

    def test_run_wrapper_cleans_on_success_failure_and_keeps_requested_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runs"
            output = Path(tmp) / "final-output"
            code = "from pathlib import Path; Path(__import__('sys').argv[1]).write_text('final')"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "run", str(root), "--", sys.executable, "-c", code, str(output)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "final")
            self.assertEqual(list(root.glob("run-*")), [])
            failed = subprocess.run(
                [sys.executable, str(SCRIPT), "run", str(root), "--", sys.executable, "-c", "raise SystemExit(7)"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(failed.returncode, 7)
            self.assertEqual(list(root.glob("run-*")), [])
            kept = subprocess.run(
                [sys.executable, str(SCRIPT), "run", str(root), "--keep-build-files", "--", sys.executable, "-c", "pass"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(kept.returncode, 0)
            self.assertEqual(len(list(root.glob("run-*"))), 1)

    def test_run_lock_is_active_until_interrupted_child_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runs"
            runner = subprocess.Popen(
                [sys.executable, str(SCRIPT), "run", str(root), "--", sys.executable, "-c", "import time; time.sleep(30)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                for _ in range(30):
                    if list(root.glob("run-*")):
                        break
                    time.sleep(0.01)
                preview = self.run_tool("preview", str(root), "--grace", "0")
                self.assertIn("active build lock", preview.stdout)
            finally:
                runner.send_signal(signal.SIGTERM)
                runner.wait(timeout=3)

    def test_killed_wrapper_cannot_release_child_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runs"
            child_pid_file = Path(tmp) / "child.pid"
            code = "import os,time; open(__import__('sys').argv[1],'w').write(str(os.getpid())); time.sleep(30)"
            runner = subprocess.Popen([sys.executable, str(SCRIPT), "run", str(root), "--", sys.executable, "-c", code, str(child_pid_file)])
            child_pid = None
            try:
                for _ in range(100):
                    if child_pid_file.exists():
                        child_pid = int(child_pid_file.read_text())
                        break
                    time.sleep(0.01)
                self.assertIsNotNone(child_pid)
                runner.kill()
                runner.wait(timeout=3)
                preview = self.run_tool("preview", str(root), "--grace", "0")
                self.assertIn("active build lock", preview.stdout)
            finally:
                if child_pid:
                    os.kill(child_pid, signal.SIGTERM)
                    for _ in range(100):
                        if self.run_tool("clean", str(root), "--grace", "0", "--yes").returncode == 0 and not list(root.glob("run-*")):
                            break
                        time.sleep(0.01)

    def test_cleanup_handles_owned_outer_staging_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runs"
            abandoned = root / "boetticher-openwrt-build.abandoned"
            abandoned.mkdir(parents=True)
            (abandoned / ".boetticher-build-owned").write_text('{"version":1,"outer":true}\n')
            (abandoned / ".boetticher-build.lock").touch()
            os.utime(abandoned, (time.time() - 7200, time.time() - 7200))
            active = root / "boetticher-tailnet-builder.active"
            active.mkdir(parents=True)
            (active / ".boetticher-build-owned").write_text('{"version":1,"outer":true}\n')
            lock = active / ".boetticher-build.lock"
            lock.touch()
            code = "import fcntl,time; f=open(__import__('sys').argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX); time.sleep(30)"
            holder = subprocess.Popen([sys.executable, "-c", code, str(lock)])
            try:
                time.sleep(0.05)
                preview = self.run_tool("preview", str(root), "--grace", "0")
                self.assertIn("active build lock", preview.stdout)
                self.run_tool("clean", str(root), "--grace", "0", "--yes")
                self.assertFalse(abandoned.exists())
                self.assertTrue(active.exists())
            finally:
                holder.send_signal(signal.SIGTERM)
                holder.wait(timeout=3)
                self.run_tool("clean", str(root), "--grace", "0", "--yes")

if __name__ == "__main__":
    unittest.main()
