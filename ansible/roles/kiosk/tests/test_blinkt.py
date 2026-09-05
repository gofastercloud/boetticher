from pathlib import Path
import runpy
import sys
import types
import unittest


class BlinktTest(unittest.TestCase):
    def test_missing_or_stale_data_cannot_stay_green(self):
        root = Path(__file__).parents[4]
        previous = sys.modules.get('lgpio')
        sys.modules['lgpio'] = types.ModuleType('lgpio')
        try:
            code = runpy.run_path(str(root / 'pi/kiosk/libexec/boetticher-blinkt'))
        finally:
            if previous is None:
                del sys.modules['lgpio']
            else:
                sys.modules['lgpio'] = previous
        frame = code['frame']
        waiting = frame({}, 100)
        self.assertEqual(len(waiting), 8)
        self.assertTrue(all(blue > green for _, green, blue in waiting))
        stale = {'updated_at': '1970-01-01T00:00:00Z', 'items': [{'status': 'healthy'}] * 8}
        self.assertEqual(frame(stale, 100), waiting)
        disabled = {'updated_at': '1970-01-01T00:01:40Z', 'items': [{'status': 'disabled'}] * 8}
        self.assertEqual(frame(disabled, 100), [(0, 0, 0)] * 8)
