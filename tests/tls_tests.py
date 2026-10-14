import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
from datetime import timedelta
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from utils import tls


class TLSTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {}
        for attr, value in (('TLS_DIR', self.tmp), ('CERT_FILE', os.path.join(self.tmp, 'selfsigned.crt')),
                            ('KEY_FILE', os.path.join(self.tmp, 'selfsigned.key'))):
            p = patch.object(tls, attr, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(tls, 'get_env', side_effect=lambda key, default=None: self.env.get(key, default))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)


class ModeTests(TLSTestCase):
    def test_modes(self):
        self.assertEqual(tls.tls_mode(), 'off')                          # installs that predate the setting
        self.env['TLS_CERT_FILE'] = '/etc/ssl/x.pem'
        self.assertEqual(tls.tls_mode(), 'custom')
        self.env['TLS_MODE'] = 'Self-Signed'
        self.assertEqual(tls.tls_mode(), 'self-signed')
        self.env['TLS_MODE'] = 'letsencrypt'
        with self.assertRaises(tls.TLSConfigError):
            tls.tls_mode()

    def test_custom_needs_files(self):
        self.env.update(TLS_MODE='custom', TLS_CERT_FILE=os.path.join(self.tmp, 'missing.pem'), TLS_KEY_FILE='')
        with self.assertRaises(tls.TLSConfigError):
            tls.certificate_files()

    def test_off_means_no_certificate(self):
        self.assertIsNone(tls.certificate_files())
        self.assertEqual(tls.status()['mode'], 'off')


class SelfSignedTests(TLSTestCase):
    def test_generated_once_with_server_names(self):
        self.env['TLS_HOSTNAMES'] = '203.0.113.7, easm.example.com'
        cert, key, created = tls.ensure_self_signed()
        self.assertTrue(created)
        info = tls.describe(cert)
        self.assertIn('203.0.113.7', info['names'])
        self.assertIn('easm.example.com', info['names'])
        self.assertIn('127.0.0.1', info['names'])
        self.assertEqual(len(info['fingerprint'].split(':')), 32)
        if os.name == 'posix':
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        tls.ssl_context(cert, key)                                      # cert and key belong together
        self.assertFalse(tls.ensure_self_signed()[2])                   # reused

    def test_renewed_when_names_change_or_expiry_is_near(self):
        cert, _, _ = tls.ensure_self_signed()
        first = tls.describe(cert)['fingerprint']
        self.env['TLS_HOSTNAMES'] = '198.51.100.20'                     # server got a new address
        self.assertTrue(tls.ensure_self_signed()[2])
        second = tls.describe(cert)['fingerprint']
        self.assertNotEqual(first, second)
        later = tls.utc_now() + tls.VALIDITY - timedelta(days=10)
        with patch.object(tls, 'utc_now', return_value=later):
            self.assertTrue(tls.ensure_self_signed()[2])
        self.assertNotEqual(tls.describe(cert)['fingerprint'], second)

    def test_detected_names_do_not_force_a_new_certificate(self):
        # A recreated container has a new host name and internal address;
        # regenerating would change the fingerprint the user verified
        with patch.object(tls.socket, 'gethostname', return_value='1c81c7b57266'), \
                patch.object(tls, '_primary_ip', return_value='172.18.0.2'):
            cert, _, created = tls.ensure_self_signed()
        self.assertTrue(created)
        self.assertIn('1c81c7b57266', tls.describe(cert)['names'])
        with patch.object(tls.socket, 'gethostname', return_value='90c527ad9b6d'), \
                patch.object(tls, '_primary_ip', return_value='172.18.0.3'):
            self.assertFalse(tls.ensure_self_signed()[2])

    def test_status_for_settings(self):
        self.env['TLS_MODE'] = 'self-signed'
        tls.ensure_self_signed()
        status = tls.status()
        self.assertEqual(status['mode'], 'self-signed')
        self.assertTrue(status['fingerprint'] and status['not_after'])


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class ServeTests(TLSTestCase):
    def serve(self, **env):
        import main
        self.env.update(env)
        servers = []
        from cheroot import wsgi
        real_start = wsgi.Server.start

        def capture(server):
            servers.append(server)
            return real_start(server)

        patchers = [patch.object(main, 'get_env', side_effect=lambda key, default=None: self.env.get(key, default)),
                    patch.object(wsgi.Server, 'start', autospec=True, side_effect=capture)]
        for p in patchers:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patchers])
        thread = threading.Thread(target=main.serve_web, daemon=True)
        thread.start()
        for _ in range(100):
            if servers and servers[0].ready:
                break
            time.sleep(0.05)
        self.addCleanup(lambda: servers and servers[0].stop())
        return servers

    def test_serves_https_with_the_generated_certificate(self):
        import requests
        port = free_port()
        servers = self.serve(TLS_MODE='self-signed', HOST='127.0.0.1', PORT=str(port), WEB_THREADS='2')
        self.assertTrue(servers and servers[0].ready)
        response = requests.get(f'https://127.0.0.1:{port}/login', verify=False, timeout=10)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Strict-Transport-Security', response.headers)
        self.assertNotIn('Not encrypted.', response.text)

        # the browser sees the certificate whose fingerprint LazyEASM prints
        der = ssl.get_server_certificate(('127.0.0.1', port))
        self.assertIn('BEGIN CERTIFICATE', der)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        try:
            context.set_ciphers('DEFAULT:@SECLEVEL=0')
        except ssl.SSLError:
            pass
        with self.assertRaises((ssl.SSLError, OSError)):                # TLS 1.1 is refused
            with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
                with context.wrap_socket(sock):
                    pass

    def test_fails_closed_when_https_cannot_start(self):
        import main
        self.env.update(TLS_MODE='custom', TLS_CERT_FILE='', TLS_KEY_FILE='')
        with patch.object(main, 'get_env', side_effect=lambda key, default=None: self.env.get(key, default)), \
                patch('waitress.serve') as plain:
            with self.assertRaises(SystemExit):
                main.serve_web()
        plain.assert_not_called()                                      # never falls back to plain HTTP


if __name__ == '__main__':
    unittest.main()
