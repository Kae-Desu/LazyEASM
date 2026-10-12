import contextlib
import datetime
import io
import logging
import os
import tempfile
import unittest

from tests.helpers import access_token
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from utils import db_utils


class ChangeTrackingTestCase(unittest.TestCase):
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

    def events(self, host=None):
        return [(c['change_type'], c['summary']) for c in reversed(db_utils.get_changes(host=host, limit=500))]

    def types(self, host=None):
        return [t for t, _ in self.events(host)]


class AssetChangeTests(ChangeTrackingTestCase):
    def test_new_assets_and_status_transitions(self):
        dom_id = db_utils.upsert_domain('example.com')
        db_utils.upsert_subdomain('api.example.com', dom_id)
        db_utils.upsert_subdomain('api.example.com', dom_id, status='down')
        db_utils.upsert_subdomain('api.example.com', dom_id, status='down')   # no change, no event
        db_utils.upsert_subdomain('api.example.com', dom_id, status='up')
        db_utils.upsert_ip('203.0.113.5')

        # returned IDs are the asset rows, not the change-history rows
        conn = db_utils.get_db_connection()
        try:
            self.assertEqual(conn.execute("SELECT dom_id FROM domain_asset WHERE domain_name = 'example.com'").fetchone()[0], dom_id)
            self.assertEqual(conn.execute("SELECT sub_id FROM subdomain_asset").fetchone()[0],
                             db_utils.upsert_subdomain('api.example.com', dom_id))
            self.assertEqual(conn.execute("SELECT ip_id FROM ip_asset").fetchone()[0], db_utils.upsert_ip('203.0.113.5'))
            new_sub = db_utils.upsert_subdomain('www.example.com', dom_id)
            self.assertEqual(conn.execute("SELECT sub_id FROM subdomain_asset WHERE subdomain_name = 'www.example.com'").fetchone()[0], new_sub)
        finally:
            conn.close()

        self.assertEqual(self.types('example.com'), ['asset_added'])
        self.assertEqual(self.types('api.example.com'), ['asset_added', 'asset_down', 'asset_up'])
        self.assertEqual(self.types('203.0.113.5'), ['asset_added'])

    def test_liveness_records_confirmed_transitions_only(self):
        from utils import liveness_checker
        dom_id = db_utils.upsert_domain('example.com')
        db_utils.upsert_subdomain('new.example.com', dom_id)
        sub_id = db_utils.upsert_subdomain('old.example.com', dom_id)
        conn = db_utils.get_db_connection()
        conn.execute("UPDATE subdomain_asset SET last_liveness_check = '2026-01-01 00:00:00' WHERE sub_id = ?", (sub_id,))
        conn.commit()
        conn.close()

        with patch.object(liveness_checker, 'check_single_asset', return_value='down'):
            liveness_checker.check_all_liveness()

        self.assertIn('asset_down', self.types('old.example.com'))
        self.assertNotIn('asset_down', self.types('new.example.com'))  # first check is not a transition


class TechnologyChangeTests(ChangeTrackingTestCase):
    def setUp(self):
        super().setUp()
        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO http_services (http_id, host, port_num, is_https) VALUES (1, 'shop.example.com', 443, 1)")
        conn.commit()
        conn.close()

    def current(self):
        conn = db_utils.get_db_connection()
        try:
            return sorted((t['name'], t['version']) for t in db_utils._get_technologies_for_host(conn.cursor(), 'shop.example.com'))
        finally:
            conn.close()

    def test_first_scan_is_quiet_then_changes_are_recorded(self):
        first = db_utils.sync_technologies(1, 'shop.example.com', [('Nginx', '1.20.1'), ('jQuery', '1.12.4')])
        self.assertEqual(self.events('shop.example.com'), [])

        second = db_utils.sync_technologies(1, 'shop.example.com', [('Nginx', '1.25.3'), ('PHP', '8.2')])
        self.assertEqual(self.events('shop.example.com'), [
            ('tech_added', 'PHP 8.2 detected'),
            ('tech_removed', 'jQuery 1.12.4 no longer detected'),
            ('tech_version_changed', 'Nginx changed from 1.20.1 to 1.25.3'),
        ])
        self.assertEqual(self.current(), [('Nginx', '1.25.3'), ('PHP', '8.2')])
        self.assertNotEqual(first['Nginx'], second['Nginx'])

        # re-detected technology reuses its row
        third = db_utils.sync_technologies(1, 'shop.example.com', [('Nginx', '1.25.3'), ('PHP', '8.2'), ('jQuery', '1.12.4')])
        self.assertEqual(third['jQuery'], first['jQuery'])
        self.assertEqual(self.types('shop.example.com')[-1], 'tech_added')


class FindingChangeTests(ChangeTrackingTestCase):
    def setUp(self):
        super().setUp()
        conn = db_utils.get_db_connection()
        conn.executescript("""
            INSERT INTO http_services (http_id, host, port_num, is_https) VALUES (1, 'shop.example.com', 443, 1);
            INSERT INTO technologies (tech_id, http_id, tech_name, tech_version) VALUES (1, 1, 'Nginx', '1.20.1');
        """)
        conn.commit()
        conn.close()

    def test_vulnerability_lifecycle_events(self):
        vuln = db_utils.upsert_vulnerability(1, 'CVE-2021-23017', 7.7, 'resolver bug')
        db_utils.upsert_vulnerability(1, 'CVE-2021-23017', 7.7, 'resolver bug')   # still open: no event
        db_utils.reconcile_vulnerabilities(1, [])
        db_utils.upsert_vulnerability(1, 'CVE-2021-23017', 7.7, 'resolver bug')
        db_utils.set_vulnerability_status(vuln, 'accepted', 'behind WAF')

        self.assertEqual(self.events('shop.example.com'), [
            ('vulnerability_found', 'CVE-2021-23017 found in Nginx 1.20.1'),
            ('vulnerability_fixed', 'CVE-2021-23017 no longer detected'),
            ('vulnerability_reopened', 'CVE-2021-23017 detected again on Nginx'),
            ('status_changed', 'CVE-2021-23017 marked accepted: behind WAF'),
        ])

    def test_finding_lifecycle_events(self):
        finding_id, _ = db_utils.upsert_finding('exposed_env', 'shop.example.com', 'Environment file exposed', 'high', {})
        db_utils.reconcile_findings('shop.example.com', ['exposed_env'], [])
        db_utils.upsert_finding('exposed_env', 'shop.example.com', 'Environment file exposed', 'high', {})
        db_utils.set_finding_status(finding_id, 'false_positive')

        self.assertEqual(self.types('shop.example.com'),
                         ['finding_opened', 'finding_fixed', 'finding_reopened', 'status_changed'])


class PortChangeTests(ChangeTrackingTestCase):
    def scanner(self, cycle):
        from modules.Nmap import PortScanner
        scanner = PortScanner.__new__(PortScanner)
        scanner.cycle = cycle
        scanner.logger = logging.getLogger('test')
        return scanner

    def test_opened_ports_and_closure_on_full_scans_only(self):
        ip_id = db_utils.upsert_ip('203.0.113.5')
        port = lambda n, svc: {'port_num': n, 'protocol': 'tcp', 'service': svc, 'banner': ''}

        self.scanner('initial').save_ports(ip_id, [port(22, 'ssh'), port(443, 'https')], ip_value='203.0.113.5')
        self.scanner('initial').save_ports(ip_id, [port(443, 'https')], ip_value='203.0.113.5')   # top-N: no closure
        self.scanner('long').save_ports(ip_id, [port(443, 'https'), port(6379, 'redis')], ip_value='203.0.113.5')

        self.assertEqual(self.events('203.0.113.5'), [
            ('asset_added', 'New IP address discovered'),
            ('port_opened', 'Port 22/tcp opened (ssh)'),
            ('port_opened', 'Port 443/tcp opened (https)'),
            ('port_opened', 'Port 6379/tcp opened (redis)'),
            ('port_closed', 'Port 22/tcp closed'),
        ])
        conn = db_utils.get_db_connection()
        try:
            ports = sorted(r['port_num'] for r in conn.execute('SELECT port_num FROM ports WHERE ip_id = ?', (ip_id,)))
        finally:
            conn.close()
        self.assertEqual(ports, [443, 6379])


class QueryAndApiTests(ChangeTrackingTestCase):
    def test_filters_pruning_and_api(self):
        db_utils.record_change('a.example.com', 'port_opened', 'Port 80/tcp opened', {'port': 80})
        db_utils.record_change('b.example.com', 'asset_down', 'Went down')
        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO asset_changes (host, change_type, summary, detected_at) "
                     "VALUES ('old.example.com', 'asset_added', 'old', '2020-01-01 00:00:00')")
        conn.commit()
        conn.close()

        self.assertEqual([c['host'] for c in db_utils.get_changes(change_type='asset_down')], ['b.example.com'])
        self.assertEqual(db_utils.get_changes(host='a.example.com')[0]['details'], {'port': 80})
        self.assertEqual(len(db_utils.get_changes(since='2025-01-01')), 2)
        self.assertEqual(db_utils.prune_changes(days=365), 1)

        import jwt
        import main
        client = main.app.test_client()
        token = access_token(main)
        self.assertEqual(client.get('/api/changes').status_code, 401)
        client.set_cookie('access_token', token)
        body = client.get('/api/changes?host=a.example.com').get_json()
        self.assertEqual([c['summary'] for c in body['changes']], ['Port 80/tcp opened'])
        self.assertEqual(client.get('/api/changes?limit=abc').status_code, 400)
        html = client.get('/update_changes').get_data(as_text=True)
        self.assertIn('b.example.com', html)
        self.assertIn('fa-arrow-down', html)


if __name__ == '__main__':
    unittest.main()
