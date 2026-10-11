import contextlib
import io
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest.mock
from unittest.mock import patch

from modules import InitDB
from utils import db_utils, misconfig_checker as mc

SOFT_404 = b'<!doctype html><html><head><title>Not found</title></head><body>APP_KEY=not-really</body></html>'


class MisconfiguredSite(BaseHTTPRequestHandler):
    routes = {
        '/': (200, b'<html><head><title>Index of /</title></head><body>file.txt</body></html>'),
        '/.git/HEAD': (200, b'ref: refs/heads/main\n'),
        '/server-status': (302, b''),  # redirects to a login page: not an exposure
    }

    def do_GET(self):
        status, body = self.routes.get(self.path, (200, SOFT_404))  # soft-404 for everything else
        self.send_response(status)
        if status == 302:
            self.send_header('Location', '/login')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class MatcherTests(unittest.TestCase):
    def check(self, finding_type):
        return next(c for c in mc.FILE_CHECKS if c.finding_type == finding_type).matches

    def test_env(self):
        self.assertTrue(self.check('exposed_env')(b'APP_KEY=base64:abc\nDB_PASSWORD=secret\n'))
        self.assertTrue(self.check('exposed_env')(b'export AWS_SECRET_ACCESS_KEY=x\nexport REGION=y'))
        self.assertFalse(self.check('exposed_env')(SOFT_404))
        self.assertFalse(self.check('exposed_env')(b'ONLY_ONE=1'))

    def test_git_head(self):
        self.assertTrue(self.check('exposed_git')(b'ref: refs/heads/main\n'))
        self.assertTrue(self.check('exposed_git')(b'a' * 40))
        self.assertFalse(self.check('exposed_git')(SOFT_404))

    def test_htpasswd(self):
        self.assertTrue(self.check('exposed_htpasswd')(b'admin:$apr1$abc$def\n'))
        self.assertTrue(self.check('exposed_htpasswd')(b'bob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n'))
        self.assertFalse(self.check('exposed_htpasswd')(SOFT_404))

    def test_ds_store(self):
        self.assertTrue(self.check('exposed_ds_store')(b'\x00\x00\x00\x01Bud1\x00\x00'))
        self.assertFalse(self.check('exposed_ds_store')(SOFT_404))


class CheckWebLocalServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), MisconfiguredSite)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_real_exposures_found_and_soft_404_ignored(self):
        result = mc.check_web('127.0.0.1', [(self.port, False)])

        self.assertEqual(sorted(result.findings), ['directory_listing', 'exposed_git'])
        self.assertEqual(result.findings['exposed_git']['evidence']['urls'],
                         [f'http://127.0.0.1:{self.port}/.git/HEAD'])
        # every file check and directory listing reached a conclusion
        self.assertEqual(result.evaluated, {c.finding_type for c in mc.FILE_CHECKS} | {mc.DIRECTORY_LISTING})
        # no HTTPS service, so TLS/header/redirect checks were not evaluated
        self.assertFalse(result.evaluated & {mc.TLS_CERT, mc.TLS_LEGACY, mc.MISSING_HEADERS, mc.NO_HTTPS_REDIRECT})

    def test_refused_port_is_conclusive_and_clean(self):
        result = mc.check_web('127.0.0.1', [(free_port(), False)])
        self.assertEqual(result.findings, {})
        self.assertIn('exposed_env', result.evaluated)


class CheckWebHttpsTests(unittest.TestCase):
    """HTTPS branch with network calls replaced."""

    def run_https(self, responses, cert=(True, None), legacy=(), timeout_urls=()):
        def fake_get(url):
            if url in timeout_urls:
                return None
            return responses.get(url, (404, {}, b''))

        with patch.object(mc, 'http_get', side_effect=fake_get), \
             patch.object(mc, 'check_certificate', return_value=cert), \
             patch.object(mc, 'legacy_tls_versions', return_value=list(legacy) if legacy is not None else None):
            return mc.check_web('shop.example.com', [(443, True)])

    def test_tls_redirect_and_header_findings(self):
        result = self.run_https({
            'https://shop.example.com/': (200, {'Content-Security-Policy': "default-src 'self'"}, b'<html>'),
            'http://shop.example.com/': (200, {}, b'<html>'),
        }, cert=(False, 'certificate has expired'), legacy=['TLS 1.0'])

        self.assertEqual(result.findings[mc.TLS_CERT]['evidence']['reason'], 'certificate has expired')
        self.assertEqual(result.findings[mc.TLS_LEGACY]['evidence']['versions'], ['TLS 1.0'])
        self.assertIn(mc.NO_HTTPS_REDIRECT, result.findings)
        self.assertEqual(result.findings[mc.MISSING_HEADERS]['evidence']['missing'],
                         ['Strict-Transport-Security', 'X-Content-Type-Options'])

    def test_well_configured_https_is_clean(self):
        result = self.run_https({
            'https://shop.example.com/': (200, {'Strict-Transport-Security': 'max-age=63072000',
                                                'X-Content-Type-Options': 'nosniff',
                                                'X-Frame-Options': 'DENY'}, b'<html>'),
            'http://shop.example.com/': (301, {'Location': 'https://shop.example.com/'}, b''),
        })
        self.assertEqual(result.findings, {})
        self.assertTrue({mc.TLS_CERT, mc.TLS_LEGACY, mc.NO_HTTPS_REDIRECT, mc.MISSING_HEADERS} <= result.evaluated)

    def test_inconclusive_checks_are_not_evaluated(self):
        result = self.run_https({}, cert=(None, 'timed out'), legacy=None,
                                timeout_urls={'http://shop.example.com/', 'https://shop.example.com/'})
        self.assertFalse(result.evaluated & {mc.TLS_CERT, mc.TLS_LEGACY, mc.NO_HTTPS_REDIRECT,
                                             mc.MISSING_HEADERS, mc.DIRECTORY_LISTING})


class LegacyTlsTests(unittest.TestCase):
    def test_connection_reset_during_handshake_means_rejected(self):
        with patch.object(mc.socket, 'create_connection', return_value=unittest.mock.MagicMock()), \
             patch.object(mc.ssl.SSLContext, 'wrap_socket', side_effect=ConnectionResetError(10054, 'reset')):
            self.assertEqual(mc.legacy_tls_versions('shop.example.com', 443), [])

    def test_unreachable_host_is_inconclusive(self):
        with patch.object(mc.socket, 'create_connection', side_effect=TimeoutError()):
            self.assertIsNone(mc.legacy_tls_versions('shop.example.com', 443))


class CheckPortsTests(unittest.TestCase):
    def test_open_refused_and_timeout(self):
        states = {6379: True, 3306: False, 3389: None}
        with patch.object(mc, 'tcp_open', side_effect=lambda ip, port: states[port]):
            result = mc.check_ports('203.0.113.5', [6379, 3306, 3389, 8080])

        self.assertEqual(list(result.findings), ['exposed_port_6379'])
        finding = result.findings['exposed_port_6379']
        self.assertEqual((finding['severity'], finding['evidence']['service']), ('high', 'Redis'))
        # refused is a conclusive "closed"; timeouts and non-risky ports are not evaluated
        self.assertEqual(result.evaluated, {'exposed_port_6379', 'exposed_port_3306'})

    def test_tcp_open_against_real_sockets(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            self.assertTrue(mc.tcp_open('127.0.0.1', listener.getsockname()[1]))
        self.assertFalse(mc.tcp_open('127.0.0.1', free_port()))


class RunMisconfigCheckTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        conn = db_utils.get_db_connection()
        conn.executescript("""
            INSERT INTO http_services (host, port_num, is_https) VALUES
                ('shop.example.com', 443, 1), ('shop.example.com', 80, 0), ('blog.example.com', 80, 0);
            INSERT INTO ip_asset (ip_id, ip_value, is_private, is_shared) VALUES
                (1, '203.0.113.5', 0, 0), (2, '10.0.0.5', 1, 0), (3, '104.16.0.1', 0, 1);
            INSERT INTO ports (ip_id, port_num, protocol) VALUES
                (1, 6379, 'tcp'), (1, 443, 'tcp'), (2, 6379, 'tcp'), (3, 3306, 'tcp');
        """)
        conn.commit()
        conn.close()

    def tearDown(self):
        os.remove(self.db_path)

    def test_target_selection(self):
        self.assertEqual(db_utils.get_http_services_by_host(),
                         {'blog.example.com': [(80, False)], 'shop.example.com': [(80, False), (443, True)]})
        self.assertEqual(db_utils.get_http_services_by_host([]), {})
        # private and CDN IPs are skipped; only risky ports are returned
        self.assertEqual(db_utils.get_risky_ports_by_ip(list(mc.RISKY_PORTS)), {'203.0.113.5': [6379]})
        self.assertEqual(db_utils.get_risky_ports_by_ip(list(mc.RISKY_PORTS), []), {})

    def run_with(self, web=None, ports=None, **kwargs):
        def fake_web(host, services):
            return (web or {}).get(host) or mc.HostResult(host, evaluated=set(mc.WEB_FINDING_TYPES))

        def fake_ports(ip, port_list):
            return (ports or {}).get(ip) or mc.HostResult(ip, evaluated={mc.port_finding_type(p) for p in port_list})

        with patch.object(mc, 'check_web', side_effect=fake_web), patch.object(mc, 'check_ports', side_effect=fake_ports):
            return mc.run_misconfig_check(**kwargs)

    def statuses(self):
        conn = db_utils.get_db_connection()
        try:
            return {(r['host'], r['finding_type']): r['status'] for r in conn.execute('SELECT * FROM findings')}
        finally:
            conn.close()

    def exposed(self, host, finding_type, severity, evaluated=None):
        result = mc.HostResult(host, evaluated=set(evaluated or {finding_type}))
        result.add(finding_type, 'title', severity, 'detail', f'https://{host}/x')
        return result

    def test_lifecycle_and_alerting(self):
        web = {'shop.example.com': self.exposed('shop.example.com', 'exposed_env', 'high', mc.WEB_FINDING_TYPES),
               'blog.example.com': self.exposed('blog.example.com', mc.MISSING_HEADERS, 'low', mc.WEB_FINDING_TYPES)}
        ports = {'203.0.113.5': self.exposed('203.0.113.5', 'exposed_port_6379', 'high')}

        first = self.run_with(web, ports)
        self.assertEqual(first['hosts_checked'], 3)
        # low-severity findings are stored but not alerted
        self.assertEqual(sorted(f['host'] for f in first['new_findings']), ['203.0.113.5', 'shop.example.com'])
        self.assertEqual(len(first['open_findings']), 3)
        self.assertIsNotNone(db_utils.get_setting('last_misconfig_check'))

        # .env no longer served; Redis check timed out (not evaluated) so it stays open
        timed_out = mc.HostResult('203.0.113.5')
        second = self.run_with(web={'blog.example.com': web['blog.example.com']}, ports={'203.0.113.5': timed_out})
        self.assertEqual(second['closed'], 1)
        self.assertEqual(self.statuses(), {
            ('shop.example.com', 'exposed_env'): 'fixed',
            ('blog.example.com', mc.MISSING_HEADERS): 'open',
            ('203.0.113.5', 'exposed_port_6379'): 'open',
        })

    def test_targeted_run_only_checks_given_assets(self):
        calls = []
        with patch.object(mc, 'check_web', side_effect=lambda h, s: calls.append(h) or mc.HostResult(h)), \
             patch.object(mc, 'check_ports', side_effect=lambda i, p: calls.append(i) or mc.HostResult(i)):
            mc.run_misconfig_check(hosts=['blog.example.com'], ips=[])
        self.assertEqual(calls, ['blog.example.com'])
        self.assertFalse(db_utils.get_setting('last_misconfig_check'))

    def test_check_quietly_alerts_and_never_raises(self):
        with patch.object(mc, 'run_misconfig_check', return_value={'new_findings': [{'host': 'h'}]}), \
             patch('utils.phase3_worker.send_misconfig_notification') as notify:
            mc.check_quietly(hosts=['h'])
        notify.assert_called_once()
        with patch.object(mc, 'run_misconfig_check', side_effect=RuntimeError('boom')):
            mc.check_quietly(hosts=['h'])


if __name__ == '__main__':
    unittest.main()
