import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).parents[1] / "files" / "boetticher-network-probe-host"


class NetworkProbeHostTest(unittest.TestCase):
    def run_script(self, payload):
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            capture_output=True,
            check=False,
        )

    def test_rejects_invalid_request_before_invoking_proxmox(self):
        for payload in (b"{}", b"[]", b"null"):
            with self.subTest(payload=payload):
                result = self.run_script(payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout)["ok"], False)

    def test_rejects_oversized_request(self):
        result = self.run_script(b"x" * (64 * 1024 + 1))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("too large", json.loads(result.stdout)["error"])

    def test_host_boundary_is_fixed_and_restricted(self):
        source = SCRIPT.read_text()
        for text in (
            '"/usr/sbin/pct", "config"',
            '"/usr/sbin/pct", "exec"',
            '"/usr/local/libexec/boetticher-network-probe"',
            "VMID_MIN = 910",
            "VMID_MAX = 919",
        ):
            self.assertIn(text, source)
        self.assertNotIn("shell=True", source)

    def test_ssh_allow_list_preserves_root_recovery(self):
        tasks = (SCRIPT.parent / "../tasks/main.yml").resolve().read_text()
        self.assertIn("replace: 'AllowUsers root labadmin lab-jump lab-netprobe'", tasks)
        self.assertNotIn("replace: 'AllowUsers labadmin lab-jump lab-netprobe'", tasks)


if __name__ == "__main__":
    unittest.main()
