import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from tests.helpers import access_token
from utils import db_utils


class PagesTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()

        dom_id = db_utils.upsert_domain('example.com')
        self.sub_id = db_utils.upsert_subdomain('shop.example.com', dom_id)
        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO http_services (http_id, host, port_num, is_https) VALUES (1, 'shop.example.com', 443, 1)")
        conn.commit()
        conn.close()
        ids = db_utils.sync_technologies(1, 'shop.example.com', [('Apache', '2.4.49')])
        db_utils.upsert_vulnerability(ids['Apache'], 'CVE-2021-41773', 7.5, 'Path traversal')
        db_utils.upsert_finding('exposed_env', 'shop.example.com', 'Environment file exposed', 'high',
                                {'detail': 'A .env file is served.', 'urls': ['https://shop.example.com/.env']})

        import main
        self.main = main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)
        self.csrf = main.generate_csrf_token(token)

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)


class NavigationTests(PagesTestCase):
    def test_pages_require_login(self):
        anonymous = self.main.app.test_client()
        for url in ('/', '/assets', '/findings', f'/assets/subdomain/{self.sub_id}', '/settings'):
            response = anonymous.get(url)
            self.assertEqual(response.status_code, 302, url)
            self.assertIn('/login', response.headers['Location'])

    def test_sidebar_marks_the_current_page(self):
        for url, label in (('/', 'Overview'), ('/assets', 'Assets'), ('/findings', 'Findings'), ('/settings', 'Settings')):
            html = self.client.get(url).get_data(as_text=True)
            self.assertRegex(html, rf'aria-current="page">\s*<i class="fas [\w-]+ w-5 mr-3 text-center"></i>{label}')

    def test_overview_no_longer_renders_every_asset(self):
        html = self.client.get('/').get_data(as_text=True)
        # assets and CVEs may be named in Recent Changes, but no finding cards are rendered
        self.assertNotIn('Path traversal', html)
        self.assertNotIn('data-status-url', html)
        self.assertIn('id="queue-table-body"', html)


class AssetPageTests(PagesTestCase):
    def test_detail_page(self):
        html = self.client.get(f'/assets/subdomain/{self.sub_id}').get_data(as_text=True)
        self.assertIn('Environment file exposed', html)
        self.assertIn('CVE-2021-41773', html)
        self.assertIn(f'data-status-url="/api/vulnerabilities/', html)
        self.assertIn('data-action="deep_scan"', html)
        self.assertIn('data-redirect="/assets"', html)
        # actions are wired through data attributes, not inline JS built from asset data
        self.assertNotIn("openConfirmModal('", html)

    def test_unknown_asset_redirects_to_list(self):
        response = self.client.get('/assets/subdomain/9999')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/assets'))
        self.assertEqual(self.client.get('/assets/bogus/1').status_code, 302)

    def test_list_api_has_finding_counts(self):
        data = self.client.get('/api/assets?sort=finding_count&order=desc').get_json()
        top = data['items'][0]
        self.assertEqual((top['name'], top['finding_count'], top['max_finding_severity']), ('shop.example.com', 1, 'high'))


class SettingsPageTests(PagesTestCase):
    def test_forms_return_to_their_tab(self):
        response = self.client.post('/save_scanning_settings', data={'csrf_token': self.csrf, 'discovery_interval_hr': '12'})
        self.assertTrue(response.headers['Location'].endswith('/settings#schedule'))

        response = self.client.post('/change_password', data={'csrf_token': self.csrf, 'current_password': 'wrong',
                                                              'new_password': 'x' * 12, 'confirm_password': 'x' * 12})
        self.assertTrue(response.headers['Location'].endswith('/settings#account'))

        with patch.object(self.main, 'test_webhook', return_value=(True, 'ok')):
            response = self.client.post('/test_webhook')
        self.assertTrue(response.headers['Location'].endswith('/settings#notifications'))

    def test_submitting_the_untouched_form_changes_nothing(self):
        import re
        from pathlib import Path
        from utils import env_manager
        env_file = Path(tempfile.mkdtemp()) / '.env'
        env_file.write_text('')
        with patch.object(env_manager, 'ENV_FILE', env_file):
            html = self.client.get('/settings').get_data(as_text=True)
            form = html[html.index('action="/save_config"'):html.index('</form>', html.index('action="/save_config"'))]
            # every dropdown submits its displayed value, like a browser would
            data = {'csrf_token': self.csrf}
            for name, body in re.findall(r'<select[^>]*name="(\w+)"[^>]*>(.*?)</select>', form, re.S):
                data[name] = re.search(r'<option value="([^"]*)"\s+selected', body).group(1)
            self.client.post('/save_config', data=data)
            with self.client.session_transaction() as session:
                self.assertEqual(session.pop('_flashes'), [('warning', 'No changes submitted.')])
            self.assertEqual(env_file.read_text().strip(), '')

    def test_every_setting_is_on_the_page(self):
        from utils.env_manager import EDITABLE_KEYS
        html = self.client.get('/settings').get_data(as_text=True)
        for key in EDITABLE_KEYS:
            self.assertIn(f'name="{key}"', html, key)
            self.assertIn(f'name="CLEAR_{key}"', html, key)


if __name__ == '__main__':
    unittest.main()
