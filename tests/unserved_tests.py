import contextlib
import io
import os
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from modules import InitDB
from tests.certificates_tests import make_cert
from utils import db_utils, misconfig_checker as mc


class CandidateTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()

        dom = db_utils.upsert_domain('example.com')
        own = db_utils.upsert_ip('198.51.100.7')
        cdn = db_utils.upsert_ip('104.21.0.1', is_shared=1, shared_provider='Cloudflare')
        for name, ip, status in (('stale.example.com', own, 'up'), ('www.example.com', own, 'up'),
                                 ('proxied.example.com', cdn, 'up'), ('gone.example.com', own, 'down')):
            sub = db_utils.upsert_subdomain(name, dom, status=status)
            db_utils.create_subdomain_resolution(sub, [ip])
        container = db_utils.add_container_domain('other.org')
        db_utils.create_domain_resolution(container, [own])
        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO http_services (host, port_num, is_https) VALUES ('www.example.com', 443, 1)")
        conn.commit()
        conn.close()

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def test_candidates(self):
        # served, behind a CDN, down, and container domains are left out
        self.assertEqual(db_utils.get_unserved_candidates(), {'stale.example.com': ['198.51.100.7']})
        self.assertEqual(db_utils.get_unserved_candidates(['www.example.com']), {})
        self.assertEqual(db_utils.get_unserved_candidates([]), {})

    def test_open_finding_keeps_a_host_checked(self):
        db_utils.upsert_finding(mc.UNSERVED, 'gone.example.com', 'x', 'low', {})
        self.assertIn('gone.example.com', db_utils.get_unserved_candidates())

    def run_check(self, tls, http):
        with patch.object(mc, '_tls_state', return_value=tls), patch.object(mc, '_http_state', return_value=http), \
                patch.object(mc.socket, 'getaddrinfo', return_value=[]), \
                patch('utils.db_utils.get_risky_ports_by_ip', return_value={}):
            return mc.run_misconfig_check()

    def status(self):
        conn = db_utils.get_db_connection()
        try:
            row = conn.execute('SELECT status FROM findings WHERE finding_type = ? AND host = ?',
                               (mc.UNSERVED, 'stale.example.com')).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def test_confirmed_on_the_second_check_and_closed_when_served(self):
        with patch('utils.db_utils.get_http_services_by_host', return_value={}):
            self.run_check('rejected', 'to_https')
            self.assertIsNone(self.status())                 # one detection is not enough
            self.run_check('rejected', 'to_https')
            self.assertEqual(self.status(), 'open')
            self.run_check(None, None)                       # inconclusive: unchanged
            self.assertEqual(self.status(), 'open')
            self.run_check('ok', 'to_https')                 # the site is configured now
            self.assertEqual(self.status(), 'fixed')
            self.run_check('rejected', 'closed')             # starts counting again
            self.assertEqual(self.status(), 'fixed')

    def test_detection_starts_over_after_a_good_check(self):
        with patch('utils.db_utils.get_http_services_by_host', return_value={}):
            self.run_check('rejected', 'ok')                 # http serves content: not unserved
            self.run_check('rejected', 'to_https')
            self.assertIsNone(self.status())


class ClassificationTests(unittest.TestCase):
    def check(self, tls, http, resolves=True):
        resolver = (lambda *a: []) if resolves else (lambda *a: (_ for _ in ()).throw(socket.gaierror('NXDOMAIN')))
        with patch.object(mc, '_tls_state', return_value=tls), patch.object(mc, '_http_state', return_value=http), \
                patch.object(mc.socket, 'getaddrinfo', side_effect=resolver):
            return mc.check_unserved('stale.example.com', ['198.51.100.7'])

    def test_cases(self):
        for tls, http, found, evaluated in (
                ('rejected', 'to_https', True, True), ('rejected', None, True, True),
                ('closed', 'to_https', True, True), ('ok', 'to_https', False, True),
                (None, 'ok', False, True), ('closed', 'closed', False, True),   # no web server at all
                (None, None, False, False), (None, 'to_https', False, False)):
            result = self.check(tls, http)
            self.assertEqual((mc.UNSERVED in result.findings, mc.UNSERVED in result.evaluated), (found, evaluated),
                             (tls, http))
        self.assertIn('198.51.100.7', self.check('rejected', 'to_https').findings[mc.UNSERVED]['evidence']['detail'])

    def test_removed_record_closes(self):
        result = self.check('rejected', 'to_https', resolves=False)
        self.assertEqual((result.findings, mc.UNSERVED in result.evaluated), ({}, True))


class TlsProbeTests(unittest.TestCase):
    def serve(self, sni_names):
        """TLS server that only accepts the given SNI names (like Caddy without a site for a name)."""
        cert_pem, key_pem, _ = make_cert('known.test')
        tmp = tempfile.mkdtemp()
        open(os.path.join(tmp, 'c.pem'), 'wb').write(cert_pem)
        open(os.path.join(tmp, 'k.pem'), 'wb').write(key_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(os.path.join(tmp, 'c.pem'), os.path.join(tmp, 'k.pem'))
        context.sni_callback = lambda sock, name, ctx: None if name in sni_names else ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
        listener = socket.create_server(('127.0.0.1', 0))
        self.addCleanup(listener.close)

        def run():
            for _ in range(2):
                conn, _ = listener.accept()
                try:
                    with context.wrap_socket(conn, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass
        threading.Thread(target=run, daemon=True).start()
        return listener.getsockname()[1]

    def test_rejected_and_served_names(self):
        port = self.serve({'known.test'})
        connect = socket.create_connection   # names resolve to the local test server
        with patch.object(mc.socket, 'create_connection',
                          side_effect=lambda addr, timeout=None: connect(('127.0.0.1', port), timeout)):
            self.assertEqual(mc._tls_state('unknown.test', port), 'rejected')
            self.assertEqual(mc._tls_state('known.test', port), 'ok')

    def test_closed_port(self):
        with socket.create_server(('127.0.0.1', 0)) as probe:
            port = probe.getsockname()[1]
        self.assertEqual(mc._tls_state('127.0.0.1', port), 'closed')


if __name__ == '__main__':
    unittest.main()
