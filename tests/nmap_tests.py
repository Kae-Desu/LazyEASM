import subprocess
import unittest
from unittest.mock import patch

from modules.Nmap import PortScanner

HOST_DOWN = '<?xml version="1.0"?><nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>'
HOST_UP = '''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="45.33.32.156" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.7"/></port>
</ports></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def completed(stdout):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr='')


class HostDiscoveryRetryTests(unittest.TestCase):
    def setUp(self):
        self.scanner = PortScanner(cycle='initial')
        patcher = patch.object(PortScanner, 'check_nmap_installed', return_value=(True, '7.98'))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_live_host_missed_by_discovery_is_rescanned(self):
        with patch('modules.Nmap.subprocess.run', side_effect=[completed(HOST_DOWN), completed(HOST_UP)]) as run:
            ok, error, ports = self.scanner.run_nmap('45.33.32.156', 'initial')
        self.assertTrue(ok, error)
        self.assertEqual([(p['port_num'], p['banner']) for p in ports], [(80, 'Apache httpd 2.4.7')])
        first, second = (call.args[0] for call in run.call_args_list)
        self.assertNotIn('-Pn', first)
        self.assertEqual(second[:2], ['nmap', '-Pn'])

    def test_host_found_up_is_scanned_once(self):
        with patch('modules.Nmap.subprocess.run', return_value=completed(HOST_UP)) as run:
            ok, _, ports = self.scanner.run_nmap('45.33.32.156', 'initial')
        self.assertTrue(ok)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(ports), 1)


if __name__ == '__main__':
    unittest.main()
