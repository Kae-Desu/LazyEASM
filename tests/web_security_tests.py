import os
import unittest
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

import main


class HttpsBehaviorTests(unittest.TestCase):
    def setUp(self):
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

    def test_debug_is_off_unless_explicitly_enabled(self):
        with patch.object(main, 'get_env', side_effect=lambda key, default=None: default):
            self.assertFalse(main.env_flag('FLASK_DEBUG'))
        with patch.object(main, 'get_env', side_effect=lambda key, default=None: 'true' if key == 'FLASK_DEBUG' else default):
            self.assertTrue(main.env_flag('FLASK_DEBUG'))


if __name__ == '__main__':
    unittest.main()
