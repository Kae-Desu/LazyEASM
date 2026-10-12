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
from utils.findings_repository import FindingQueryError, get_overview, list_findings


class FindingsTestCase(unittest.TestCase):
    """
    shop.example.com  Apache 2.4.49 on 80 and 443 -> CVE-2021-41773 (KEV), exposed .env (high)
    blog.example.com  jQuery -> CVE-2019-11358 (EPSS 30%), missing headers (low), takeover (critical)
    203.0.113.7       nginx  -> CVE-2021-23017 (CVSS 7.7, no exploitation signal)
    """

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
        self.shop_id = db_utils.upsert_subdomain('shop.example.com', dom_id)
        db_utils.upsert_subdomain('blog.example.com', dom_id)
        self.ip_id = db_utils.upsert_ip('203.0.113.7')
        conn = db_utils.get_db_connection()
        conn.executescript("""
            INSERT INTO http_services (http_id, host, port_num, is_https) VALUES
                (1, 'shop.example.com', 443, 1), (2, 'shop.example.com', 80, 0),
                (3, 'blog.example.com', 443, 1), (4, '203.0.113.7', 443, 1);
            INSERT INTO cve_intel (cve_id, epss, in_kev, kev_due_date) VALUES
                ('CVE-2021-41773', 0.94, 1, '2021-11-17'), ('CVE-2019-11358', 0.30, 0, NULL),
                ('CVE-2021-23017', 0.02, 0, NULL);
        """)
        conn.commit()
        conn.close()
        for http_id, host, tech, cve, score in ((1, 'shop.example.com', ('Apache', '2.4.49'), 'CVE-2021-41773', 7.5),
                                                (2, 'shop.example.com', ('Apache', '2.4.49'), 'CVE-2021-41773', 7.5),
                                                (3, 'blog.example.com', ('jQuery', '1.12.4'), 'CVE-2019-11358', 6.1),
                                                (4, '203.0.113.7', ('nginx', '1.20.1'), 'CVE-2021-23017', 7.7)):
            ids = db_utils.sync_technologies(http_id, host, [tech])
            db_utils.upsert_vulnerability(ids[tech[0]], cve, score, 'description')
        db_utils.upsert_finding('exposed_env', 'shop.example.com', 'Environment file exposed', 'high',
                                {'detail': 'A .env file is served.', 'port': 443})
        db_utils.upsert_finding('missing_security_headers', 'blog.example.com', 'Missing security headers', 'low', {})
        db_utils.upsert_finding('subdomain_takeover', 'blog.example.com', 'Subdomain takeover possible', 'critical', {})

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def find(self, **filters):
        return list_findings(page_size=100, **filters)['items']


class ListTests(FindingsTestCase):
    def test_most_urgent_first(self):
        order = [(f['host'], f['identifier']) for f in self.find()]
        self.assertEqual(order, [
            ('blog.example.com', 'subdomain_takeover'),      # critical finding  } both most urgent,
            ('shop.example.com', 'CVE-2021-41773'),          # P1: known exploited } then by severity
            ('shop.example.com', 'exposed_env'),             # high finding
            ('blog.example.com', 'CVE-2019-11358'),          # P2: EPSS >= 10%
            ('203.0.113.7', 'CVE-2021-23017'),               # P3: CVSS >= 7
            ('blog.example.com', 'missing_security_headers'),
        ])

    def test_cve_rows_are_grouped_per_host(self):
        cve = self.find(identifier='CVE-2021-41773')
        self.assertEqual(len(cve), 1)
        self.assertEqual((cve[0]['ports'], cve[0]['priority'], cve[0]['in_kev'], cve[0]['severity']),
                         ([80, 443], 'P1', True, 'high'))
        self.assertEqual(cve[0]['title'], 'CVE-2021-41773 in Apache 2.4.49')

    def test_rows_link_to_their_asset(self):
        links = {f['host']: (f['asset_type'], f['asset_id']) for f in self.find()}
        self.assertEqual(links['shop.example.com'], ('subdomain', self.shop_id))
        self.assertEqual(links['203.0.113.7'], ('ip', self.ip_id))

    def test_finding_rows(self):
        env = self.find(identifier='exposed_env')[0]
        self.assertEqual((env['kind'], env['priority'], env['detail'], env['ports'], env['evidence']),
                         ('finding', None, 'A .env file is served.', [443], None))

    def test_filters(self):
        self.assertEqual(len(self.find(kind='cve')), 3)
        self.assertEqual([f['identifier'] for f in self.find(kev_only='1')], ['CVE-2021-41773'])
        self.assertEqual({f['identifier'] for f in self.find(severity='high')}, {'CVE-2021-41773', 'exposed_env', 'CVE-2021-23017'})
        self.assertEqual(len(self.find(host='blog.example.com')), 3)
        self.assertEqual([f['identifier'] for f in self.find(query='jquery')], ['CVE-2019-11358'])

    def test_status_filter_defaults_to_open(self):
        db_utils.set_finding_status(self.find(identifier='exposed_env')[0]['id'], 'accepted')
        self.assertNotIn('exposed_env', [f['identifier'] for f in self.find()])
        self.assertEqual([f['identifier'] for f in self.find(status='accepted')], ['exposed_env'])
        self.assertEqual(len(self.find(status='all')), 6)

    def test_pagination(self):
        page = list_findings(page=2, page_size=4)
        self.assertEqual((len(page['items']), page['pagination']['total'], page['pagination']['has_next']), (2, 6, False))

    def test_invalid_values(self):
        for kwargs in ({'kind': 'x'}, {'severity': 'x'}, {'status': 'x'}, {'sort': 'x'}, {'page': 0}, {'page_size': 'a'}):
            with self.assertRaises(FindingQueryError, msg=kwargs):
                list_findings(**kwargs)


class BulkStatusTests(FindingsTestCase):
    def test_all_or_nothing(self):
        cve = self.find(identifier='CVE-2021-41773')[0]
        with self.assertRaises(ValueError):
            db_utils.set_statuses([('cve', cve['id']), ('bogus', 1)], 'fixed')
        self.assertEqual(self.find(identifier='CVE-2021-41773')[0]['status'], 'open')


class OverviewTests(FindingsTestCase):
    def test_numbers(self):
        o = get_overview()
        self.assertEqual(o['issues']['by_severity'], {'critical': 1, 'high': 3, 'medium': 1, 'low': 1})
        self.assertEqual((o['issues']['open_total'], o['issues']['kev'], o['issues']['kev_hosts'], o['issues']['urgent']), (6, 1, 1, 2))
        self.assertEqual((o['assets']['total'], o['assets']['up']), (4, 4))
        self.assertEqual(o['riskiest_assets'][0]['name'], 'shop.example.com')
        self.assertEqual([(w['identifier'], w['host_count']) for w in o['widespread_issues']][:2],
                         [('subdomain_takeover', 1), ('CVE-2021-41773', 1)])

    def test_closed_findings_are_not_counted(self):
        for f in self.find():
            db_utils.set_statuses([(f['kind'], f['id'])], 'fixed')
        o = get_overview()
        self.assertEqual((o['issues']['open_total'], o['riskiest_assets'], o['widespread_issues']), (0, [], []))


class WebTests(FindingsTestCase):
    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)
        self.csrf = main.generate_csrf_token(token)

    def bulk(self, body):
        return self.client.post('/api/findings/bulk_status', json={'csrf_token': self.csrf, **body})

    def test_api(self):
        data = self.client.get('/api/findings?kind=cve&page_size=2').get_json()
        self.assertTrue(data['success'])
        self.assertEqual((len(data['items']), data['pagination']['total']), (2, 3))
        self.assertEqual(self.client.get('/api/findings?status=bogus').status_code, 400)
        self.assertEqual(self.main.app.test_client().get('/api/findings').status_code, 401)

    def test_bulk_status(self):
        targets = [{'kind': f['kind'], 'id': f['id']} for f in self.find(host='shop.example.com')]
        response = self.bulk({'items': targets, 'status': 'accepted', 'note': 'behind VPN'})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()['updated'], 3)          # 2 CVE rows (ports 80, 443) + 1 finding
        self.assertEqual(self.find(host='shop.example.com'), [])
        accepted = self.find(host='shop.example.com', status='accepted')
        self.assertEqual({f['status_note'] for f in accepted}, {'behind VPN'})
        changes = db_utils.get_changes(host='shop.example.com', change_type='status_changed')
        self.assertEqual(len(changes), 2)

    def test_bulk_status_validation(self):
        good = {'kind': 'finding', 'id': 1}
        self.assertEqual(self.client.post('/api/findings/bulk_status', json={'items': [good], 'status': 'fixed'}).status_code, 403)
        for body in ({'items': [good], 'status': 'gone'}, {'items': [], 'status': 'fixed'},
                     {'items': [{'kind': 'host', 'id': 1}], 'status': 'fixed'},
                     {'items': [{'kind': 'cve', 'id': '1'}], 'status': 'fixed'},
                     {'items': [{'kind': 'cve', 'id': True}], 'status': 'fixed'},
                     {'items': [good] * 501, 'status': 'fixed'}):
            self.assertEqual(self.bulk(body).status_code, 400, body)

    def test_pages(self):
        html = self.client.get('/findings').get_data(as_text=True)
        self.assertIn('id="finding-rows"', html)
        self.assertRegex(html, r'aria-current="page">\s*<i class="fas [\w-]+ w-5 mr-3 text-center"></i>Findings')

        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('/findings?kev=1', html)
        self.assertIn('/findings?identifier=CVE-2021-41773', html)
        self.assertIn('/assets/subdomain/%d' % self.shop_id, html)
        partial = self.client.get('/update_overview').get_data(as_text=True)
        self.assertIn('Most widespread issues', partial)
        self.assertNotIn('<html', partial)


if __name__ == '__main__':
    unittest.main()
