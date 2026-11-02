"""Deleting an asset removes everything recorded about it, and only that."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from tests.helpers import access_token
from utils import asset_deletion, db_utils, screenshots
from utils.misconfig_checker import UNSERVED_STRIKES_KEY

MARKER = 'client-secret-marker-7f3a9c'


class DeletionTestCase(unittest.TestCase):
    """
    example.com: www and shop (both on 203.0.113.10; shop also on
    203.0.113.50) and old.example.com, left without a domain by an earlier
    delete. example.org: blog (on 203.0.113.50 and 198.51.100.7).
    192.0.2.9: an IP submitted on its own.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db_path = os.path.join(self.tmp, 'test.db')
        self.shot_dir = os.path.join(self.tmp, 'screenshots')
        os.makedirs(self.shot_dir)
        for target, attr, value in ((InitDB, 'DB_NAME', self.db_path), (db_utils, 'DB_PATH', self.db_path),
                                    (screenshots, 'SCREENSHOT_DIR', self.shot_dir)):
            p = patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        self.ids = self.seed()

    def seed(self) -> dict:
        ids = {}
        conn = db_utils.get_db_connection()
        try:
            c = conn.cursor()
            for name in ('example.com', 'example.org'):
                c.execute('INSERT INTO domain_asset (domain_name) VALUES (?)', (name,))
                ids[name] = c.lastrowid
            for ip in ('203.0.113.10', '203.0.113.50', '198.51.100.7', '192.0.2.9'):
                c.execute('INSERT INTO ip_asset (ip_value) VALUES (?)', (ip,))
                ids[ip] = c.lastrowid
                c.execute('INSERT INTO ports (ip_id, port_num, service_name) VALUES (?, 443, ?)', (ids[ip], 'https'))
            subs = {'www.example.com': ('example.com', ['203.0.113.10']),
                    'shop.example.com': ('example.com', ['203.0.113.10', '203.0.113.50']),
                    'old.example.com': (None, []),
                    'blog.example.org': ('example.org', ['203.0.113.50', '198.51.100.7'])}
            for name, (domain, ips) in subs.items():
                c.execute('INSERT INTO subdomain_asset (dom_id, subdomain_name) VALUES (?, ?)',
                          (ids.get(domain), name))
                ids[name] = c.lastrowid
                for ip in ips:
                    c.execute('INSERT INTO subdomain_ip (sub_id, ip_id) VALUES (?, ?)', (ids[name], ids[ip]))

            for host, ip in (('www.example.com', '203.0.113.10'), ('shop.example.com', '203.0.113.10'),
                             ('blog.example.org', '198.51.100.7'), ('192.0.2.9', '192.0.2.9')):
                c.execute('INSERT INTO http_services (host, ip_id, port_num, is_https) VALUES (?, ?, 443, 1)',
                          (host, ids[ip]))
                http_id = c.lastrowid
                c.execute('INSERT INTO technologies (http_id, tech_name, tech_version) VALUES (?, ?, ?)',
                          (http_id, 'Nginx', '1.20.0'))
                c.execute('INSERT INTO vulnerabilities (tech_id, cve_id, cve_score) VALUES (?, ?, 7.7)',
                          (c.lastrowid, 'CVE-2021-23017'))
                c.execute('INSERT INTO directories (http_id, path, status_code) VALUES (?, ?, 200)',
                          (http_id, '/admin'))
                token = host.replace('.', '-')
                for name in (f'{token}.jpg', f'{token}_thumb.jpg'):
                    with open(os.path.join(self.shot_dir, name), 'wb') as f:
                        f.write(b'jpeg')
                c.execute('INSERT INTO screenshots (http_id, host, url, image_file, thumb_file, captured_at) '
                          "VALUES (?, ?, ?, ?, ?, '2026-11-01 00:00:00')",
                          (http_id, host, f'https://{host}/', f'{token}.jpg', f'{token}_thumb.jpg'))

            for host in ('www.example.com', 'old.example.com', '203.0.113.10', 'blog.example.org', '192.0.2.9'):
                evidence = {'detail': MARKER if host == 'www.example.com' else 'x', 'urls': [f'https://{host}/']}
                c.execute('INSERT INTO findings (finding_type, host, title, severity, evidence) VALUES (?, ?, ?, ?, ?)',
                          ('exposed_git', host, 'Git repository exposed', 'high', json.dumps(evidence)))
                c.execute("INSERT INTO asset_changes (host, change_type, summary, detected_at) "
                          "VALUES (?, 'asset_added', 'New', '2026-11-01 00:00:00')", (host,))
            for host in ('www.example.com', 'blog.example.org'):
                c.execute("INSERT INTO certificates (sub_id, hostname, not_after, source, port) "
                          "VALUES (?, ?, '2027-01-01 00:00:00', 'tls', 443)", (ids[host], host))
                c.execute('INSERT INTO cert_notifications (cert_id, hostname, days_threshold) VALUES (?, ?, 30)',
                          (c.lastrowid, host))
            for target in ('www.example.com', 'blog.example.org'):
                c.execute("INSERT INTO scan_queue (scan_type, cycle, target, status) VALUES ('phase1', 'standard', ?, "
                          "'completed')", (target,))
                c.execute("INSERT INTO scan_hints (target, hint_type, hint_value) VALUES (?, 'port', '8443')", (target,))
                c.execute("INSERT INTO scan_history (scan_type, target) VALUES ('phase1', ?)", (target,))
            for domain in ('example.com', 'example.org'):
                c.execute("INSERT INTO scan_queue (scan_type, cycle, target, status) VALUES "
                          "('input_discovery', 'standard', ?, 'completed')", (json.dumps({'domains': [domain]}),))
            c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                      (UNSERVED_STRIKES_KEY, json.dumps({'old.example.com': 1, 'blog.example.org': 1})))
            conn.commit()
        finally:
            conn.close()
        return ids

    def rows_mentioning(self, text: str) -> list:
        """Every row of every table that contains text anywhere."""
        conn = db_utils.get_db_connection()
        try:
            found = []
            for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
                for row in conn.execute(f'SELECT * FROM "{table}"'):
                    if any(text in str(value) for value in tuple(row)):
                        found.append((table, tuple(row)))
            return found
        finally:
            conn.close()

    def count(self, sql: str, params=()) -> int:
        conn = db_utils.get_db_connection()
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    def ip_exists(self, ip: str) -> bool:
        return bool(self.count('SELECT COUNT(*) FROM ip_asset WHERE ip_value = ?', (ip,)))


class DeleteDomainTests(DeletionTestCase):
    def test_removes_the_domain_its_subdomains_and_all_their_data(self):
        removed = asset_deletion.delete_asset('domain', self.ids['example.com'])

        self.assertEqual(self.rows_mentioning('example.com'), [])
        self.assertEqual(removed['hosts'], 4)            # the domain, www, shop and the orphaned old.example.com
        self.assertEqual(self.count('SELECT COUNT(*) FROM vulnerabilities WHERE tech_id IS NULL'), 0)
        self.assertFalse(any(name.startswith(('www-example-com', 'shop-example-com'))
                             for name in os.listdir(self.shot_dir)))

    def test_keeps_other_assets_and_shared_ips(self):
        asset_deletion.delete_asset('domain', self.ids['example.com'])

        self.assertFalse(self.ip_exists('203.0.113.10'))                    # only example.com used it
        self.assertEqual(self.rows_mentioning('203.0.113.10'), [])
        self.assertTrue(self.ip_exists('203.0.113.50'))                     # blog.example.org still uses it
        self.assertTrue(self.ip_exists('192.0.2.9'))                        # submitted on its own
        for host in ('blog.example.org', '192.0.2.9'):
            self.assertEqual(self.count('SELECT COUNT(*) FROM http_services WHERE host = ?', (host,)), 1)
            self.assertEqual(self.count('SELECT COUNT(*) FROM findings WHERE host = ?', (host,)), 1)
        self.assertEqual(self.count('SELECT COUNT(*) FROM vulnerabilities'), 2)
        self.assertEqual(self.count('SELECT COUNT(*) FROM scan_queue WHERE target LIKE ?', ('%example.org%',)), 2)
        self.assertEqual(json.loads(db_utils.get_setting(UNSERVED_STRIKES_KEY)), {'blog.example.org': 1})
        self.assertTrue(os.path.exists(os.path.join(self.shot_dir, 'blog-example-org.jpg')))

    def test_deleted_content_is_not_left_in_the_database_file(self):
        self.assertTrue(self.rows_mentioning(MARKER))
        asset_deletion.delete_asset('domain', self.ids['example.com'])
        for path in (self.db_path, self.db_path + '-wal'):
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    self.assertFalse(MARKER.encode() in f.read(), f"deleted content still in {path}")


class DeleteSubdomainAndIpTests(DeletionTestCase):
    def test_subdomain_and_the_ips_only_it_used(self):
        asset_deletion.delete_asset('subdomain', self.ids['blog.example.org'])

        self.assertEqual(self.rows_mentioning('blog.example.org'), [])
        self.assertFalse(self.ip_exists('198.51.100.7'))
        self.assertTrue(self.ip_exists('203.0.113.50'))                     # shop.example.com still uses it
        self.assertTrue(self.count('SELECT COUNT(*) FROM domain_asset WHERE domain_name = ?', ('example.org',)))
        self.assertEqual(json.loads(db_utils.get_setting(UNSERVED_STRIKES_KEY)), {'old.example.com': 1})

    def test_ip_keeps_web_services_of_hostnames_that_pointed_to_it(self):
        asset_deletion.delete_asset('ip', self.ids['203.0.113.10'])

        self.assertEqual(self.rows_mentioning('203.0.113.10'), [])
        self.assertEqual(self.count('SELECT COUNT(*) FROM http_services WHERE host = ? AND ip_id IS NULL',
                                    ('www.example.com',)), 1)
        self.assertEqual(self.count('SELECT COUNT(*) FROM subdomain_ip WHERE sub_id = ?',
                                    (self.ids['www.example.com'],)), 0)

    def test_ip_submitted_on_its_own(self):
        asset_deletion.delete_asset('ip', self.ids['192.0.2.9'])
        self.assertEqual(self.rows_mentioning('192.0.2.9'), [])
        self.assertFalse(os.path.exists(os.path.join(self.shot_dir, '192-0-2-9.jpg')))

    def test_missing_asset_and_bad_type(self):
        self.assertIsNone(asset_deletion.delete_asset('subdomain', 999999))
        with self.assertRaises(ValueError):
            asset_deletion.delete_asset('cidr', 1)


class DeleteRouteTests(DeletionTestCase):
    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)
        self.headers = {'X-CSRF-Token': main.generate_csrf_token(token)}

    def test_route_deletes_everything_and_reports_counts(self):
        response = self.client.delete(f"/delete_asset/domain/{self.ids['example.com']}", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['removed']['hosts'], 4)
        self.assertEqual(self.rows_mentioning('example.com'), [])

    def test_route_errors(self):
        self.assertEqual(self.client.delete('/delete_asset/domain/999999', headers=self.headers).status_code, 404)
        self.assertEqual(self.client.delete('/delete_asset/cidr/1', headers=self.headers).status_code, 400)
        self.assertEqual(self.client.delete(f"/delete_asset/domain/{self.ids['example.com']}").status_code, 403)
        self.assertTrue(self.rows_mentioning('example.com'))


if __name__ == '__main__':
    unittest.main()
