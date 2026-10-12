import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

import jwt

from modules import InitDB
from utils import auth, db_utils, env_manager


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.env_file = Path(tmp) / '.env'
        self.env_file.write_text('FLASK_SECRET_KEY=x\nADMIN_USER=lazymin\nADMIN_PASS=generated-by-install-1\n')
        db_path = os.path.join(tmp, 'test.db')
        for target, attr, value in ((env_manager, 'ENV_FILE', self.env_file),
                                    (InitDB, 'DB_NAME', db_path), (db_utils, 'DB_PATH', db_path)):
            patcher = patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        patcher = patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop('ADMIN_PASS', None)

        import main
        self.main = main
        self.client = main.app.test_client()
        main.login_attempts.clear()


class BootstrapTests(AuthTestCase):
    def test_env_password_is_hashed_and_removed(self):
        self.assertEqual(auth.bootstrap_admin_from_env(), 'created')
        admin = auth.get_admin()
        self.assertEqual(admin['username'], 'lazymin')
        self.assertTrue(admin['password_hash'].startswith('scrypt:'))
        self.assertNotIn('generated-by-install-1', admin['password_hash'])
        env = self.env_file.read_text()
        self.assertNotIn('ADMIN_PASS', env)
        self.assertIn('ADMIN_USER=lazymin', env)
        self.assertIn('FLASK_SECRET_KEY=x', env)

        self.assertEqual(auth.bootstrap_admin_from_env(), 'unchanged')   # normal restart

    def test_recovery_by_putting_a_new_password_in_env(self):
        auth.bootstrap_admin_from_env()
        version = auth.current_token_version()

        self.env_file.write_text(self.env_file.read_text() + 'ADMIN_PASS=recovered-password-2\n')
        self.assertEqual(auth.bootstrap_admin_from_env(), 'reset')
        self.assertTrue(auth.verify_login('lazymin', 'recovered-password-2'))
        self.assertEqual(auth.current_token_version(), version + 1)

        # the same password again does not sign everyone out
        self.env_file.write_text(self.env_file.read_text() + 'ADMIN_PASS=recovered-password-2\n')
        self.assertEqual(auth.bootstrap_admin_from_env(), 'unchanged')
        self.assertEqual(auth.current_token_version(), version + 1)

    def test_environment_variable_only_seeds_a_missing_account(self):
        self.env_file.write_text('ADMIN_USER=lazymin\n')
        os.environ['ADMIN_PASS'] = 'from-environment-123'
        self.assertEqual(auth.bootstrap_admin_from_env(), 'created')
        auth.set_admin_password('lazymin', 'changed-in-dashboard-1')
        self.assertEqual(auth.bootstrap_admin_from_env(), 'unchanged')
        self.assertTrue(auth.verify_login('lazymin', 'changed-in-dashboard-1'))

    def test_missing_password_disables_login(self):
        self.env_file.write_text('ADMIN_USER=lazymin\nADMIN_PASS=\n')
        self.assertEqual(auth.bootstrap_admin_from_env(), 'missing')
        self.assertIsNone(auth.get_admin())


class LoginTests(AuthTestCase):
    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password})

    def test_empty_password_never_logs_in(self):
        # .env.example ships ADMIN_PASS empty; this used to accept an empty password
        self.env_file.write_text('ADMIN_USER=lazymin\nADMIN_PASS=\n')
        auth.bootstrap_admin_from_env()
        response = self.login('lazymin', '')
        self.assertNotIn('access_token=', response.headers.get('Set-Cookie', ''))
        with self.client.session_transaction() as session:
            self.assertIn('ADMIN_PASS', session['_flashes'][0][1])

        # with an account, an empty password is still rejected
        self.env_file.write_text('ADMIN_PASS=generated-by-install-1\n')
        auth.bootstrap_admin_from_env()
        self.assertNotIn('access_token=', self.login('lazymin', '').headers.get('Set-Cookie', ''))

    def test_login_issues_versioned_tokens(self):
        auth.bootstrap_admin_from_env()
        self.assertNotIn('access_token=', self.login('lazymin', 'wrong').headers.get('Set-Cookie', ''))
        response = self.login('lazymin', 'generated-by-install-1')
        self.assertEqual(response.status_code, 302)
        token = self.client.get_cookie('access_token').value
        payload = jwt.decode(token, self.main.JWT_SECRET, algorithms=['HS256'])
        self.assertEqual(payload['pv'], auth.current_token_version())
        self.assertEqual(self.client.get('/api/changes').status_code, 200)


class CsrfSessionTests(AuthTestCase):
    def test_open_forms_survive_token_refresh(self):
        import re
        auth.bootstrap_admin_from_env()
        self.client.post('/login', data={'username': 'lazymin', 'password': 'generated-by-install-1'})
        page = self.client.get('/').get_data(as_text=True)
        csrf = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
        old_access = self.client.get_cookie('access_token').value

        # the dashboard rotates tokens every 14 minutes and when the tab regains focus
        self.assertEqual(self.client.post('/refresh-token').status_code, 200)
        self.assertNotEqual(self.client.get_cookie('access_token').value, old_access)

        response = self.client.post('/save_scanning_settings', data={'csrf_token': csrf, 'discovery_interval_hr': '12'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(db_utils.get_setting('discovery_interval_hr'), '12')

    def test_csrf_differs_between_login_sessions(self):
        auth.bootstrap_admin_from_env()
        tokens = []
        for _ in range(2):
            client = self.main.app.test_client()
            client.post('/login', data={'username': 'lazymin', 'password': 'generated-by-install-1'})
            tokens.append(self.main.generate_csrf_token(client.get_cookie('access_token').value))
        self.assertNotEqual(tokens[0], tokens[1])


class PasswordChangeTests(AuthTestCase):
    def setUp(self):
        super().setUp()
        auth.bootstrap_admin_from_env()
        self.client.post('/login', data={'username': 'lazymin', 'password': 'generated-by-install-1'})
        self.old_token = self.client.get_cookie('access_token').value
        self.other_session = self.main.app.test_client()
        self.other_session.set_cookie('access_token', self.old_token)

    def change(self, current, new, confirm=None):
        token = self.client.get_cookie('access_token').value
        self.client.post('/change_password', data={
            'csrf_token': self.main.generate_csrf_token(token),
            'current_password': current, 'new_password': new,
            'confirm_password': new if confirm is None else confirm,
        })
        with self.client.session_transaction() as session:
            return session.pop('_flashes', [])[0]

    def test_validation(self):
        self.assertEqual(self.change('wrong', 'a-brand-new-password'), ('error', 'Current password is incorrect.'))
        self.assertEqual(self.change('generated-by-install-1', 'a-brand-new-password', 'different')[1],
                         'New passwords do not match.')
        self.assertIn('at least 12', self.change('generated-by-install-1', 'short')[1])
        self.assertIn('different', self.change('generated-by-install-1', 'generated-by-install-1')[1])
        # a wrong current password counts toward the login rate limit
        self.assertEqual(self.main.login_attempts['127.0.0.1']['count'], 1)

    def test_change_signs_out_other_sessions(self):
        self.assertEqual(self.change('generated-by-install-1', 'a-brand-new-password')[0], 'success')
        self.assertTrue(auth.verify_login('lazymin', 'a-brand-new-password'))
        self.assertFalse(auth.verify_login('lazymin', 'generated-by-install-1'))

        self.assertEqual(self.client.get('/api/changes').status_code, 200)        # this session got new tokens
        self.assertEqual(self.other_session.get('/api/changes').status_code, 401)  # old tokens are revoked

    def test_refresh_token_reuse_revokes_every_session(self):
        refresh = self.client.get_cookie('refresh_token').value
        self.assertEqual(self.client.post('/refresh-token').status_code, 200)
        attacker = self.main.app.test_client()
        attacker.set_cookie('refresh_token', refresh)
        self.assertEqual(attacker.post('/refresh-token').status_code, 401)        # reuse detected
        self.assertEqual(self.client.get('/api/changes').status_code, 401)        # everyone signed out


if __name__ == '__main__':
    unittest.main()
