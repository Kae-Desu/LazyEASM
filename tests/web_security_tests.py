import contextlib
import io
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

import main
from modules import InitDB
from utils import db_utils


class HttpsBehaviorTests(unittest.TestCase):
    def setUp(self):
        # Own database: /login reads the account and /setup writes the setup
        # code next to the database, never into the install the tests run on
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db_path = os.path.join(tmp, 'test.db')
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        self.client = main.app.test_client()

    def test_plain_http_has_no_hsts_and_non_secure_cookies(self):
        with patch.object(main, 'FORCE_HTTPS', False):
            response = self.client.get('/login')
            self.assertNotIn('Strict-Transport-Security', response.headers)
            with main.app.test_request_context('/', base_url='http://lazyeasm.local'):
                self.assertFalse(main.get_secure_cookie_kwargs()['secure'])

    def test_https_request_gets_hsts_and_secure_cookies(self):
        with patch.object(main, 'FORCE_HTTPS', False):
            response = self.client.get('/login', base_url='https://lazyeasm.local')
            self.assertIn('Strict-Transport-Security', response.headers)
            with main.app.test_request_context('/', base_url='https://lazyeasm.local'):
                self.assertTrue(main.get_secure_cookie_kwargs()['secure'])

    def test_force_https_covers_tls_terminated_at_proxy(self):
        with patch.object(main, 'FORCE_HTTPS', True):
            response = self.client.get('/login')
            self.assertIn('Strict-Transport-Security', response.headers)
            with main.app.test_request_context('/', base_url='http://lazyeasm.local'):
                self.assertTrue(main.get_secure_cookie_kwargs()['secure'])

    def test_plain_http_warning_only_when_exposed(self):
        with patch.object(main, 'FORCE_HTTPS', False):
            for base_url, exposed in (('http://203.0.113.5:10001', True), ('http://easm.example.com', True),
                                      ('http://localhost:10001', False), ('http://127.0.0.1:10001', False),
                                      ('http://[::1]:10001', False), ('https://easm.example.com', False)):
                # Before the account exists this lands on /setup, which warns too
                html = self.client.get('/login', base_url=base_url, follow_redirects=True).get_data(as_text=True)
                self.assertEqual('Not encrypted.' in html, exposed, base_url)

    def test_behind_a_reverse_proxy(self):
        """TRUST_PROXY: HTTPS terminated at the proxy counts as HTTPS (Secure cookies, HSTS, no warning)."""
        from werkzeug.middleware.proxy_fix import ProxyFix
        with patch.object(main, 'FORCE_HTTPS', False), \
                patch.object(main.app, 'wsgi_app', ProxyFix(main.app.wsgi_app, x_for=1, x_proto=1, x_host=1)):
            response = self.client.get('/login', base_url='http://127.0.0.1:10001', headers={
                'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'easm.example.com', 'X-Forwarded-For': '198.51.100.9'})
        self.assertIn('Strict-Transport-Security', response.headers)
        self.assertNotIn('Not encrypted.', response.get_data(as_text=True))

    def test_startup_warning(self):
        settings = {'HOST': '0.0.0.0', 'PORT': '10001'}
        with patch.object(main, 'get_env', side_effect=lambda key, default=None: settings.get(key, default)), \
                patch('utils.tls.certificate_files', return_value=None), \
                patch.object(main, 'FORCE_HTTPS', False), patch('waitress.serve'), \
                patch.object(main.logger, 'warning') as warning:
            main.serve_web()
            self.assertIn('plain HTTP', warning.call_args.args[0])
            warning.reset_mock()
            settings['HOST'] = '127.0.0.1'
            main.serve_web()
            warning.assert_not_called()

    def test_debug_is_off_unless_explicitly_enabled(self):
        with patch.object(main, 'get_env', side_effect=lambda key, default=None: default):
            self.assertFalse(main.env_flag('FLASK_DEBUG'))
        with patch.object(main, 'get_env', side_effect=lambda key, default=None: 'true' if key == 'FLASK_DEBUG' else default):
            self.assertTrue(main.env_flag('FLASK_DEBUG'))


if __name__ == '__main__':
    unittest.main()
