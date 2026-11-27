import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_SCRIPT = REPO_ROOT / "scripts" / "package-controller.sh"
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install-controller.sh"
MAKEFILE = REPO_ROOT / "Makefile"


class BrokerPackagingContractTests(unittest.TestCase):
    def test_package_controller_cross_compiles_agent_broker(self):
        text = PACKAGE_SCRIPT.read_text()
        self.assertRegex(
            text,
            r'CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \\\s*\n\s*"\$go_bin" build -trimpath -o "\$stage/bin/boetticher-agent-broker" \./cmd/boetticher-agent-broker',
        )
        self.assertRegex(
            text,
            r'chmod 0755[^\n]*"\$stage/bin/boetticher-agent-broker"',
        )

    def test_install_controller_validates_and_symlinks_agent_broker(self):
        text = INSTALL_SCRIPT.read_text()
        self.assertIn('"$payload/bin/boetticher-agent-broker"', text)
        self.assertRegex(
            text,
            r'chmod 0755[^\n]*"\$install_stage/bin/boetticher-agent-broker"',
        )
        # Preserve symlink/ownership safety checks for /usr/local/libexec and the broker link.
        self.assertIn("/usr/local/libexec/boetticher-agent-broker already belongs to another installation", text)
        self.assertIn('readlink /usr/local/libexec/boetticher-agent-broker', text)
        self.assertIn('"$install_root/current/bin/boetticher-agent-broker"', text)
        self.assertRegex(text, r'mkdir -p /usr/local/libexec')
        self.assertRegex(text, r'chmod 0755 /usr/local/libexec')
        self.assertIn(
            'ln -sfn "$install_root/current/bin/boetticher-agent-broker" /usr/local/libexec/boetticher-agent-broker',
            text,
        )

    def test_makefile_build_includes_agent_lab_and_agent_broker(self):
        text = MAKEFILE.read_text()
        match = re.search(r"(?ms)^build:\n((?:\t[^\n]*\n)+)", text)
        self.assertIsNotNone(match, "build target not found in Makefile")
        recipe = match.group(1)
        self.assertIn("go build -o bin/agent-lab ./cmd/agent-lab", recipe)
        self.assertIn("go build -o bin/boetticher-agent-broker ./cmd/boetticher-agent-broker", recipe)


if __name__ == "__main__":
    unittest.main()
