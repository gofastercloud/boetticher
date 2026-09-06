import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "controller" / "libexec" / "boetticher-bootstrap-led"


FAKE_LGPIO = r'''
import json
import os

events = []

def _record(name, *args):
    events.append([name, *args])

def gpiochip_open(chip):
    _record("open", chip)
    return 41

def gpio_claim_output(chip, pin, value):
    _record("claim", chip, pin, value)

def gpio_write(chip, pin, value):
    _record("write", chip, pin, value)

def gpio_free(chip, pin):
    _record("free", chip, pin)

def gpiochip_close(chip):
    _record("close", chip)

def flush():
    with open(os.environ["LGPIO_LOG"], "w", encoding="utf-8") as stream:
        json.dump(events, stream)
'''


class BootstrapLedTests(unittest.TestCase):
    def run_helper(self, state):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "lgpio.py"
            log = Path(directory) / "events.json"
            module.write_text(FAKE_LGPIO + "\nimport atexit\natexit.register(flush)\n", encoding="utf-8")
            environment = dict(os.environ, PYTHONPATH=directory, LGPIO_LOG=str(log))
            result = subprocess.run(
                [sys.executable, str(HELPER), "--chip", "3", state],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(log.read_text(encoding="utf-8"))

    def test_frame_claims_header_pins_and_cleans_up(self):
        events = self.run_helper("ready")
        self.assertEqual(events[:3], [["open", 3], ["claim", 41, 23, 0], ["claim", 41, 24, 0]])
        self.assertEqual(events[-3:], [["free", 41, 24], ["free", 41, 23], ["close", 41]])
        writes = [event for event in events if event[0] == "write"]
        self.assertGreater(len(writes), 8 * 4)


if __name__ == "__main__":
    unittest.main()
