import contextlib
import datetime
import io
import os
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules import InitDB
from utils import ct_monitor, db_utils, subdomain_discovery as sd, tls_certs


def make_cert(cn='shop.example.com', issuer='Test CA', days=90, sans=('shop.example.com',)):
    """Self-signed certificate (PEM cert, PEM key, DER cert)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=max(1, 1 - days)))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.DER))


def served(host='shop.example.com', port=443, days=90, issuer='Test CA'):
    return {'hostname': host, 'port': port, **tls_certs.parse_certificate(make_cert(host, issuer, days)[2])}


class DatabaseTestCase(unittest.TestCase):
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
        db_utils.upsert_subdomain('shop.example.com', dom_id)

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def sql(self, query, params=()):
        conn = db_utils.get_db_connection()
        try:
            rows = [tuple(r) for r in conn.execute(query, params)]
            conn.commit()
            return rows
        finally:
            conn.close()


class ParseAndFetchTests(unittest.TestCase):
    def test_parse(self):
        cert = tls_certs.parse_certificate(make_cert('shop.example.com', "Let's Encrypt R11", 30,
                                                     ('shop.example.com', 'www.shop.example.com'))[2])
        self.assertEqual(cert['issuer'], "Let's Encrypt R11")
        self.assertEqual(cert['dns_names'], ['shop.example.com', 'www.shop.example.com'])
        self.assertEqual(len(cert['fingerprint']), 64)
        expires = datetime.datetime.strptime(cert['not_after'], '%Y-%m-%d %H:%M:%S')
        self.assertAlmostEqual((expires - datetime.datetime.utcnow()).days, 29, delta=1)

    def test_reads_an_untrusted_certificate_from_a_live_server(self):
        cert_pem, key_pem, der = make_cert('localhost', 'Self Signed', 5)
        tmp = tempfile.mkdtemp()
        cert_file, key_file = os.path.join(tmp, 'c.pem'), os.path.join(tmp, 'k.pem')
        open(cert_file, 'wb').write(cert_pem)
        open(key_file, 'wb').write(key_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        listener = socket.create_server(('127.0.0.1', 0))
        self.addCleanup(listener.close)

        def serve():
            conn, _ = listener.accept()
            try:
                with context.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass
        threading.Thread(target=serve, daemon=True).start()

        cert = tls_certs.fetch_served_certificate('127.0.0.1', listener.getsockname()[1], timeout=5)
        self.assertEqual((cert['issuer'], cert['port']), ('Self Signed', listener.getsockname()[1]))
        self.assertEqual(cert['fingerprint'], tls_certs.parse_certificate(der)['fingerprint'])


class RecordTests(DatabaseTestCase):
    def test_new_same_changed(self):
        first = served(days=60)
        self.assertEqual(db_utils.record_served_certificate(first), ('new', None))
        self.assertEqual(db_utils.record_served_certificate(first), ('same', None))

        status, change = db_utils.record_served_certificate(served(days=90, issuer='Other CA'))
        self.assertEqual(status, 'changed')
        self.assertIn('now issued by Other CA (was Test CA)', change['summary'])
        events = [c for c in db_utils.get_changes(host='shop.example.com') if c['change_type'] == 'certificate_changed']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['details']['old_fingerprint'], first['fingerprint'])

        conn = db_utils.get_db_connection()
        try:
            current = db_utils._get_cert_expiry(conn.cursor(), 'shop.example.com')
        finally:
            conn.close()
        self.assertEqual((current['issuer'], current['days_until_expiry']), ('Other CA', 89))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM certificates WHERE replaced_at IS NOT NULL")[0][0], 1)

    def test_ports_are_tracked_separately(self):
        db_utils.record_served_certificate(served(port=443))
        self.assertEqual(db_utils.record_served_certificate(served(port=8443))[0], 'new')

    def test_retire_services_that_stopped_serving(self):
        db_utils.record_served_certificate(served('shop.example.com'))
        db_utils.record_served_certificate(served('old.example.com'))
        self.assertEqual(db_utils.retire_served_certificates([('shop.example.com', 443)]), 1)
        self.assertEqual(self.sql(f"SELECT hostname FROM certificates WHERE {db_utils.SERVED_CERT}"), [('shop.example.com',)])


class ExpiryTests(DatabaseTestCase):
    def test_renewed_certificate_raises_no_alert(self):
        """The old certificate stays in CT logs after a renewal; only the served one counts."""
        db_utils.record_served_certificate(served(days=7.04))          # 7 days left
        db_utils.record_served_certificate(served(days=90))            # renewed
        self.assertEqual(ct_monitor.check_certificate_expiry_thresholds(), {7: [], 5: [], 3: [], 1: []})

    def test_alert_for_the_served_certificate(self):
        db_utils.record_served_certificate(served(days=7.04))          # 7 days left
        alerts = ct_monitor.check_certificate_expiry_thresholds()
        self.assertEqual([a['hostname'] for a in alerts[7]], ['shop.example.com'])
        db_utils.mark_cert_notified(alerts[7][0]['cert_id'], 'shop.example.com', 7)
        self.assertEqual(ct_monitor.check_certificate_expiry_thresholds()[7], [])   # notified once

    def test_summary_buckets(self):
        for host, days in (('a.example.com', -2), ('b.example.com', 2), ('c.example.com', 6), ('d.example.com', 20),
                           ('e.example.com', 80)):
            db_utils.record_served_certificate(served(host, days=days))
        self.assertEqual(ct_monitor.get_cert_expiry_summary(),
                         {'expired': 1, 'expiring_3_days': 1, 'expiring_7_days': 2, 'expiring_30_days': 3, 'total_certs': 5})

    def test_asset_list_uses_the_served_certificate(self):
        from utils.asset_repository import list_assets
        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO certificates (hostname, issuer, not_after, source) VALUES "
                     "('shop.example.com', 'CT', datetime('now', '+3 days'), 'ctlogs')")   # ignored
        conn.commit()
        conn.close()
        db_utils.record_served_certificate(served(days=80))
        item = list_assets(query='shop')['items'][0]
        self.assertEqual((item['certificate']['state'], item['certificate']['days_remaining']), ('valid', 79))


class RefreshTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.sql("INSERT INTO http_services (host, port_num, is_https) VALUES "
                 "('shop.example.com', 443, 1), ('down.example.com', 443, 1), ('shop.example.com', 80, 0)")

    def test_refresh(self):
        def fetch(host, port, timeout=None):
            if host == 'down.example.com':
                raise ConnectionRefusedError('refused')
            return served(host, port)
        with patch.object(tls_certs, 'fetch_served_certificate', side_effect=fetch):
            result = tls_certs.refresh_served_certificates()
        self.assertEqual((result['checked'], result['new'], result['errors']), (2, 1, 1))

    def test_only_requested_hosts(self):
        with patch.object(tls_certs, 'fetch_served_certificate', side_effect=lambda h, p, timeout=None: served(h, p)) as fetch:
            tls_certs.refresh_served_certificates(['shop.example.com'])
        self.assertEqual([c.args[:2] for c in fetch.call_args_list], [('shop.example.com', 443)])


class Response:
    def __init__(self, status=200, data=None):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return self._data


class CTSourceTests(DatabaseTestCase):
    def test_certspotter_first(self):
        with patch.object(sd.requests, 'get', side_effect=[Response(data=[{'id': '1', 'dns_names': ['a.example.com']}]),
                                                           Response(data=[])]) as get:
            self.assertEqual(sd.from_ct_logs('example.com'), {'a.example.com'})
        self.assertTrue(all('certspotter' in c.args[0] for c in get.call_args_list))

    def test_crtsh_fallback_and_cooldown(self):
        with patch.object(sd.requests, 'get', side_effect=[Response(429), Response(data=[
                {'common_name': 'b.example.com', 'name_value': 'b.example.com\nc.example.com'}])]) as get:
            self.assertEqual(sd.from_ct_logs('example.com'), {'b.example.com', 'c.example.com'})
        self.assertEqual(get.call_args_list[1].kwargs['params']['exclude'], 'expired')

        with patch.object(sd.requests, 'get', side_effect=[Response(429), Response(502)]):
            with self.assertRaisesRegex(sd.SourceError, 'crt.sh: HTTP 502'):
                sd.from_ct_logs('example.com')
        # crt.sh is now left alone; only CertSpotter is asked
        with patch.object(sd.requests, 'get', side_effect=[Response(429)]) as get:
            with self.assertRaisesRegex(sd.SourceError, 'cooling down'):
                sd.from_ct_logs('example.com')
        self.assertEqual(get.call_count, 1)

    def test_certspotter_keeps_pages_before_a_rate_limit(self):
        with patch.object(sd.requests, 'get', side_effect=[Response(data=[{'id': '1', 'dns_names': ['a.example.com']}]),
                                                           Response(429)]):
            self.assertEqual(sd.from_certspotter('example.com'), {'a.example.com'})

    def test_api_key_is_sent(self):
        with patch.object(sd, 'get_env', return_value='secret-key'), \
                patch.object(sd.requests, 'get', return_value=Response(data=[])) as get:
            sd.from_certspotter('example.com')
        self.assertEqual(get.call_args.kwargs['headers']['Authorization'], 'Bearer secret-key')


class MonitorTests(DatabaseTestCase):
    def test_one_failing_domain_does_not_stop_the_rest(self):
        db_utils.upsert_domain('other.net')

        def ct(domain):
            if domain == 'example.com':
                raise sd.SourceError('CertSpotter: rate limited; crt.sh: HTTP 502')
            return {'new.other.net', '*.other.net'}
        with patch.object(sd, 'from_ct_logs', side_effect=ct), patch.object(ct_monitor.time, 'sleep'), \
                patch.object(tls_certs, 'refresh_served_certificates', return_value={'changed': []}):
            result = ct_monitor.poll_all_domains()
        self.assertEqual(result['new_subdomains'], [('other.net', 'new.other.net')])
        self.assertIn('example.com', result['ct_errors'])
        self.assertTrue(db_utils.get_setting('last_ctlogs_check'))


class MigrationTests(DatabaseTestCase):
    def test_ct_rows_removed_and_interval_moved_once(self):
        self.sql("INSERT INTO certificates (hostname, not_after, source) VALUES ('x.example.com', '2030-01-01', 'ctlogs')")
        self.sql("UPDATE settings SET value = '1' WHERE key = 'ctlogs_interval_hr'")
        self.sql("DELETE FROM settings WHERE key = 'ctlogs_default_moved_to_6h'")
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        self.assertEqual(self.sql("SELECT COUNT(*) FROM certificates WHERE source = 'ctlogs'")[0][0], 0)
        self.assertEqual(db_utils.get_setting('ctlogs_interval_hr'), '6')

        db_utils.set_setting('ctlogs_interval_hr', '1')       # chosen in the dashboard afterwards
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        self.assertEqual(db_utils.get_setting('ctlogs_interval_hr'), '1')


if __name__ == '__main__':
    unittest.main()
