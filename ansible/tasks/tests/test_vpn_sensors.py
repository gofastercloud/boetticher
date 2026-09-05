from pathlib import Path
import json
import runpy
import unittest

EVALUATE = runpy.run_path(str(Path(__file__).parents[1] / 'files/vpn-health'))['evaluate']


class VPNSensorTest(unittest.TestCase):
    def test_airvpn_requires_fresh_handshake_and_guard(self):
        outputs = {
            ('systemctl', 'is-active', 'boetticher-airvpn.service'): 'active',
            ('wg', 'show', 'airvpn0', 'latest-handshakes'): 'public-peer\t1000',
            ('sysctl', '-n', 'net.ipv4.ip_forward'): '1',
            ('ip', '-j', 'route', 'show', 'table', '51820'): '[{"dst":"default","dev":"airvpn0"}]',
            ('nft', '-j', 'list', 'table', 'inet', 'boetticher_airvpn'): json.dumps({'nftables': [
                {'chain': {'name': 'forward', 'policy': 'drop'}},
                {'rule': {'comment': 'boetticher:airvpn-no-direct-forward'}},
                {'rule': {'comment': 'boetticher:airvpn-no-internal-forward'}},
            ]}),
        }
        read = lambda *args: outputs[args]
        self.assertTrue(all(EVALUATE('airvpn', read, 1100)['checks'].values()))
        self.assertFalse(EVALUATE('airvpn', read, 2000)['checks']['handshake'])
        outputs[('sysctl', '-n', 'net.ipv4.ip_forward')] = '0'
        self.assertFalse(EVALUATE('airvpn', read, 1100)['checks']['forwarding'])

    def test_tailnet_requires_approved_route_and_online_backend(self):
        status = {'BackendState': 'Running', 'Self': {'Online': True, 'PrimaryRoutes': ['10.10.0.0/16']}}
        def read(*args):
            if args[0] == 'systemctl':
                return 'active'
            if args[1] == 'status':
                return json.dumps(status)
            return '{"AdvertiseRoutes":["10.10.0.0/16"]}'
        self.assertTrue(all(EVALUATE('tailnet-router', read, 1100)['checks'].values()))
        status['Self']['PrimaryRoutes'] = []
        self.assertFalse(EVALUATE('tailnet-router', read, 1100)['checks']['approved-route'])
        status['BackendState'] = 'NeedsLogin'
        self.assertFalse(EVALUATE('tailnet-router', read, 1100)['checks']['backend'])

    def test_selected_sensor_does_not_run_other_airvpn_commands(self):
        def read(*args):
            self.assertEqual(args, ('systemctl', 'is-active', 'boetticher-airvpn.service'))
            return 'active'
        self.assertEqual(EVALUATE('airvpn', read, 1100, 'service')['checks'], {'service': True})
