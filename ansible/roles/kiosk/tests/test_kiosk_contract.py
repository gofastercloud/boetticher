from pathlib import Path
import unittest


TASKS = Path(__file__).parents[1] / "tasks" / "main.yml"


class KioskContractTest(unittest.TestCase):
    def test_configuration_directory_precedes_streamdeck_configuration(self):
        source = TASKS.read_text()
        directory_task = source.index("- name: Create the companion configuration directory")
        streamdeck_config = source.index("dest: /etc/boetticher/streamdeck.json")
        self.assertLess(directory_task, streamdeck_config)
        self.assertIn("path: /etc/boetticher\n    state: directory", source[directory_task:])

    def test_companion_state_parent_is_traversable_by_services(self):
        source = TASKS.read_text()
        parent_task = source.index("- name: Permit unprivileged companion services to traverse their state parent")
        self.assertIn("path: /var/lib/boetticher\n    state: directory", source[parent_task:])
        self.assertIn("mode: '0751'", source[parent_task:])

    def test_lab_route_keeps_wifi_as_default(self):
        source = TASKS.read_text()
        route_task = source.index("- name: Configure the dual-homed companion lab route")
        route_contract = source[route_task:]
        self.assertIn("ipv4.never-default", route_contract)
        self.assertIn("ipv4.dns-priority", route_contract)
        self.assertIn("'-50'", route_contract)
        self.assertIn("10.10.0.0/16 10.10.20.1", route_contract)
        self.assertIn("~lab.home.arpa", route_contract)

    def test_streamdeck_allows_hidraw_and_retriggers_udev(self):
        source = TASKS.read_text()
        self.assertIn("udevadm trigger --action=change --subsystem-match=hidraw", source)
        self.assertIn("udevadm trigger --action=change --subsystem-match=usb", source)
        service = (TASKS.parent.parent / "templates" / "boetticher-streamdeck.service.j2").read_text()
        self.assertIn("DeviceAllow=char-hidraw rw", service)


if __name__ == "__main__":
    unittest.main()
