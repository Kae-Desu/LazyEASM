import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import ExpandAsset, InitDB
from tests.helpers import access_token
from utils import db_utils


def dns(names, ip='198.51.100.7'):
    return {n: {'ips': [ip], 'live_ips': [ip], 'status': 'up'} for n in names}


class ScopeTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        for target, attr, value in (
                (ExpandAsset, 'resolve_and_ping_batch', lambda names, **kw: dns(names)),
                (ExpandAsset.Phase1Expander, 'discover_subdomains', lambda self, domain: [f'www.{domain}', f'dev.{domain}']),
                (ExpandAsset.time, 'sleep', lambda s: None)):
            patcher = patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def submit(self, **targets):
        expander = ExpandAsset.Phase1Expander(securitytrails_api_key='')
        with patch.object(ExpandAsset.Phase1Expander, 'get_securitytrails_subdomains', return_value=[]):
            expander.run_phase1({'domains': [], 'subdomains': [], 'ips': [], 'cidrs': [], **targets})

    def names(self, table, column):
        conn = db_utils.get_db_connection()
        try:
            return sorted(r[0] for r in conn.execute(f'SELECT {column} FROM {table}'))
        finally:
            conn.close()


class SingleHostTests(ScopeTestCase):
    def test_submitted_subdomain_is_scanned_alone(self):
        self.submit(subdomains=['shop.example.com'])
        self.assertEqual(self.names('subdomain_asset', 'subdomain_name'), ['shop.example.com'])   # no siblings
        self.assertFalse(db_utils.is_domain_expanded('example.com'))

        # the parent is not discovered, monitored, checked or scanned
        self.assertEqual(db_utils.get_all_monitored_domains(), [])
        self.assertEqual(db_utils.get_hostnames_for_takeover_check(), ['shop.example.com'])
        self.assertEqual([a['name'] for a in db_utils.get_all_assets_for_liveness()], ['shop.example.com'])
        from utils import pipeline
        with patch.object(pipeline.task_queue, 'enqueue') as enqueue:
            pipeline.enqueue_assets_for_phase1()
        self.assertEqual([c.args[2] for c in enqueue.call_args_list], ['shop.example.com'])

        from utils.asset_repository import get_asset_detail, list_assets
        self.assertEqual([a['name'] for a in list_assets()['items']], ['shop.example.com'])
        detail = get_asset_detail('subdomain', list_assets()['items'][0]['id'])
        self.assertEqual((detail['root_domain'], detail['root_expanded']), ('example.com', 0))

    def test_subdomain_typed_as_domain(self):
        with patch('modules.ExpandAsset.normalize_hostname', side_effect=lambda h: h):
            self.submit(domains=['shop.example.com'])
        self.assertEqual(self.names('subdomain_asset', 'subdomain_name'), ['shop.example.com'])
        self.assertFalse(db_utils.is_domain_expanded('example.com'))

    def test_submitting_the_domain_expands_it(self):
        self.submit(subdomains=['shop.example.com'])
        self.submit(domains=['example.com'])
        self.assertTrue(db_utils.is_domain_expanded('example.com'))
        self.assertEqual(self.names('subdomain_asset', 'subdomain_name'), ['dev.example.com', 'shop.example.com', 'www.example.com'])
        self.assertEqual(db_utils.get_all_monitored_domains(), ['example.com'])

    def test_domain_input_expands_as_before(self):
        self.submit(domains=['example.com'])
        self.assertTrue(db_utils.is_domain_expanded('example.com'))
        self.assertEqual(len(self.names('subdomain_asset', 'subdomain_name')), 2)

    def test_subdomain_of_an_expanded_domain(self):
        self.submit(domains=['example.com'])
        self.submit(subdomains=['api.example.com'])
        self.assertTrue(db_utils.is_domain_expanded('example.com'))
        self.assertIn('api.example.com', self.names('subdomain_asset', 'subdomain_name'))


class ExpandEndpointTests(ScopeTestCase):
    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)
        self.csrf = main.generate_csrf_token(token)
        self.submit(subdomains=['shop.example.com'])
        self.dom_id = db_utils.get_domain_id('example.com')

    def test_page_offers_expansion(self):
        sub_id = db_utils.get_subdomain_id('shop.example.com')
        html = self.client.get(f'/assets/subdomain/{sub_id}').get_data(as_text=True)
        self.assertIn('Only this host is in scope', html)
        self.assertIn(f'data-action="expand_domain" data-domain-id="{self.dom_id}"', html)
        self.assertEqual(self.client.get(f'/assets/domain/{self.dom_id}').status_code, 302)   # container is not an asset

    def test_expand_queues_discovery(self):
        self.assertEqual(self.client.post(f'/api/domains/{self.dom_id}/expand', json={}).status_code, 403)
        response = self.client.post(f'/api/domains/{self.dom_id}/expand', json={'csrf_token': self.csrf})
        self.assertEqual(response.status_code, 202)
        conn = db_utils.get_db_connection()
        target = conn.execute("SELECT target FROM scan_queue WHERE scan_type = 'input_discovery'").fetchone()[0]
        conn.close()
        self.assertIn('"domains": ["example.com"]', target)

        db_utils.set_domain_expanded(self.dom_id)
        self.assertEqual(self.client.post(f'/api/domains/{self.dom_id}/expand', json={'csrf_token': self.csrf}).status_code, 409)
        self.assertEqual(self.client.post('/api/domains/999/expand', json={'csrf_token': self.csrf}).status_code, 404)


if __name__ == '__main__':
    unittest.main()
