from pathlib import Path
import unittest


TASKS = Path(__file__).parents[1] / "tasks" / "main.yml"


class KioskContractTest(unittest.TestCase):
    def test_configuration_directory_precedes_streamdeck_configuration(self):
        source = TASKS.read_text()
        directory_task = source.index("include_tasks: baseline.yml")
        streamdeck_config = source.index("include_tasks: streamdeck.yml")
        self.assertLess(directory_task, streamdeck_config)
        self.assertIn("path: /etc/boetticher", (TASKS.parent / 'baseline.yml').read_text())

    def test_companion_state_parent_is_traversable_by_services(self):
        source = (TASKS.parent / 'baseline.yml').read_text()
        self.assertIn("{path: /var/lib/boetticher, mode: '0751'}", source)

    def test_lab_route_keeps_wifi_as_default(self):
        source = (TASKS.parent / 'baseline.yml').read_text()
        self.assertIn("never-default=true", source)
        self.assertIn("ignore-auto-dns=true", source)
        self.assertIn("route1=10.10.0.0/16,{{ companion_config.gateway }}", source)
        self.assertIn("companion_config.ethernet_mac", source)
        self.assertNotIn("netplan-eth0", source)

    def test_streamdeck_allows_hidraw_and_retriggers_udev(self):
        source = (TASKS.parent / 'streamdeck.yml').read_text()
        self.assertIn("udevadm trigger --action=change --subsystem-match={{ item }}", source)
        self.assertIn("loop: [usb, hidraw]", source)
        service = (TASKS.parent.parent / "templates" / "boetticher-streamdeck.service.j2").read_text()
        self.assertIn("DeviceAllow=char-hidraw rw", service)


if __name__ == "__main__":
    unittest.main()
