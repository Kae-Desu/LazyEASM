import unittest
from unittest.mock import patch

from modules import ExpandAsset


class ProcessCidrTests(unittest.TestCase):
    def test_checks_all_hosts_and_stores_from_main_thread(self):
        expander = ExpandAsset.Phase1Expander.__new__(ExpandAsset.Phase1Expander)
        expander.max_ping_workers = 4
        expander.stats = {'ips_new': 0, 'errors': []}

        live = {"192.0.2.1", "192.0.2.2"}
        stored = []

        def fake_check(ip):
            if ip == "192.0.2.3":
                raise OSError("ping failed")
            return ip in live, False, None

        with patch.object(expander, "_check_ip", side_effect=fake_check), \
             patch.object(expander, "_store_ip", side_effect=lambda ip, *a: stored.append(ip)):
            stats = expander.process_cidr("192.0.2.0/29")

        self.assertEqual(stats["ips_processed"], 5)
        self.assertEqual(stats["ips_live"], 2)
        self.assertEqual(sorted(stored), ["192.0.2.1", "192.0.2.2", "192.0.2.4", "192.0.2.5", "192.0.2.6"])
        self.assertEqual(len(expander.stats["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
