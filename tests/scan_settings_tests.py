import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from tests.helpers import access_token
from utils import db_utils, phase3_worker, scan_settings


class ScanSettingsTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)


class SettingsTests(ScanSettingsTestCase):
    def test_defaults_and_out_of_range_values(self):
        schedule = {item['name']: item['value'] for item in scan_settings.get_schedule()}
        self.assertEqual(schedule['liveness'], 5)
        self.assertEqual(schedule['takeover'], 24)
        self.assertEqual(scan_settings.get_cve_min_cvss(), 5.0)

        db_utils.set_setting('liveness_interval_min', '0')      # bad value written outside the dashboard
        db_utils.set_setting('cve_min_cvss', 'abc')
        self.assertEqual(phase3_worker.interval_seconds('liveness'), 5 * 60)
        self.assertEqual(scan_settings.get_cve_min_cvss(), 5.0)

    def test_save_validates_everything_before_storing(self):
        errors, changed = scan_settings.save_scanning_settings(
            {'liveness_interval_min': '10', 'takeover_interval_hr': '9999', 'cve_min_cvss': '7'})
        self.assertEqual(changed, [])
        self.assertIn('between 1 and 720 hours', errors[0])
        self.assertEqual(phase3_worker.interval_seconds('liveness'), 5 * 60)   # nothing stored

        errors, changed = scan_settings.save_scanning_settings(
            {'liveness_interval_min': '10', 'takeover_interval_hr': '24', 'cve_min_cvss': '7'})
        self.assertEqual((errors, changed), ([], ['Liveness check', 'Minimum CVSS']))
        self.assertEqual(phase3_worker.interval_seconds('liveness'), 10 * 60)
        self.assertEqual(phase3_worker.interval_seconds('takeover'), 24 * 3600)
        self.assertEqual(scan_settings.get_cve_min_cvss(), 7.0)

        self.assertEqual(scan_settings.save_scanning_settings({'cve_min_cvss': '11'})[0],
                         ['Minimum CVSS: must be a number between 0 and 10'])
        self.assertEqual(scan_settings.save_scanning_settings({'liveness_interval_min': 'ten'})[0],
                         ['Liveness check: must be a whole number'])

    def test_scanner_uses_configured_minimum(self):
        db_utils.set_setting('cve_min_cvss', '7.5')
        dom_id = db_utils.upsert_domain('example.com')
        ip_id = db_utils.upsert_ip('203.0.113.5')
        db_utils.create_domain_resolution(dom_id, [ip_id])
        from modules import phase1_runner
        scanner = MagicMock()
        scanner.scan_target.return_value = {'technologies': [], 'cves': []}
        with patch('modules.Wappalyzer.WappalyzerScanner', return_value=scanner) as cls, \
             patch('modules.Nmap.PortScanner'), \
             patch('utils.threat_intel.refresh_quietly'), \
             patch('utils.misconfig_checker.check_quietly'):
            phase1_runner.run_phase1(asset_id=1, asset_type='domain', asset_name='example.com')
        self.assertEqual(cls.call_args.kwargs['cvss_min'], 7.5)


class DashboardTests(ScanSettingsTestCase):
    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)
        self.csrf = main.generate_csrf_token(token)

    def post(self, **form):
        self.client.post('/save_scanning_settings', data={'csrf_token': self.csrf, **form})
        with self.client.session_transaction() as session:
            return session.pop('_flashes', [])[0]

    def test_form_round_trip(self):
        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('name="liveness_interval_min" value="5"', html)
        self.assertIn('name="cve_min_cvss" value="5.0"', html)

        self.assertEqual(self.post(discovery_interval_hr='12'), ('success', 'Scanning settings updated: Subdomain discovery'))
        self.assertIn('name="discovery_interval_hr" value="12"', self.client.get('/').get_data(as_text=True))
        self.assertEqual(self.post(discovery_interval_hr='12'), ('warning', 'No changes submitted.'))
        self.assertEqual(self.post(discovery_interval_hr='0')[0], 'error')

    def test_requires_csrf(self):
        response = self.client.post('/save_scanning_settings', data={'discovery_interval_hr': '12'})
        self.assertEqual(response.status_code, 403)


if __name__ == '__main__':
    unittest.main()
