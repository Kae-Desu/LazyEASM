import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from tests.helpers import access_token
from utils import db_utils
from utils.activity_repository import ActivityQueryError, _duration, list_changes, list_scans


def ago(**delta) -> str:
    from utils.timeutil import utc_ago
    return utc_ago(**delta)


class ActivityTestCase(unittest.TestCase):
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
        self.sub_id = db_utils.upsert_subdomain('shop.example.com', dom_id)
        conn = db_utils.get_db_connection()
        conn.execute('DELETE FROM asset_changes')   # only the rows below
        conn.executemany('INSERT INTO asset_changes (host, change_type, summary, details, detected_at) VALUES (?, ?, ?, ?, ?)', [
            ('shop.example.com', 'port_opened', 'Port 8080 opened', '{"port": 8080}', ago(hours=1)),
            ('shop.example.com', 'appearance_changed', 'Page looks different', None, ago(days=2)),
            ('gone.example.com', 'asset_down', 'Host went down', None, ago(days=10)),
            ('example.com', 'status_changed', 'CVE-2021-41773 marked accepted', None, ago(days=40)),
        ])
        conn.executemany('''INSERT INTO scan_queue (scan_type, cycle, target, target_type, status, queued_at, started_at, completed_at,
                                                    ports_found, dirs_found, error_message)
                            VALUES (?, 'standard', ?, ?, ?, ?, ?, ?, ?, ?, ?)''', [
            ('phase2_deep_scan', 'shop.example.com', 'subdomain', 'completed', ago(hours=3), ago(hours=3), ago(hours=2, minutes=56), 4, 12, None),
            ('phase1', 'example.com', 'domain', 'running', ago(minutes=5), ago(minutes=4), None, 0, 0, None),
            ('phase2_deep_scan', 'example.com', 'domain', 'pending', ago(minutes=2), None, None, 0, 0, None),
            ('monitor_run', 'takeover', 'monitor', 'failed', ago(hours=1), ago(hours=1), ago(hours=1), 0, 0, 'DNS timeout'),
            ('input_discovery', json.dumps({'domains': ['a.com', 'b.com'], 'ips': ['10.0.0.1', '10.0.0.2']}), 'input', 'processing',
             ago(minutes=1), ago(minutes=1), None, 0, 0, None),
        ])
        conn.commit()
        conn.close()

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)


class ChangeListTests(ActivityTestCase):
    def test_newest_first_with_asset_links(self):
        items = list_changes()['items']
        self.assertEqual([c['change_type'] for c in items], ['port_opened', 'appearance_changed', 'asset_down', 'status_changed'])
        self.assertEqual((items[0]['asset_type'], items[0]['asset_id'], items[0]['details']), ('subdomain', self.sub_id, {'port': 8080}))
        self.assertIsNone(items[2]['asset_type'])           # host no longer tracked

    def test_filters(self):
        types = lambda **kw: [c['change_type'] for c in list_changes(**kw)['items']]
        self.assertEqual(types(category='appearance'), ['appearance_changed'])
        self.assertEqual(types(category='triage'), ['status_changed'])
        self.assertEqual(types(period='24h'), ['port_opened'])
        self.assertEqual(types(period='30d'), ['port_opened', 'appearance_changed', 'asset_down'])
        self.assertEqual(types(host='shop.example.com'), ['port_opened', 'appearance_changed'])
        self.assertEqual(types(query='CVE-2021'), ['status_changed'])

    def test_pagination_and_validation(self):
        page = list_changes(page=2, page_size=3)
        self.assertEqual((len(page['items']), page['pagination']['total'], page['pagination']['has_previous']), (1, 4, True))
        for kwargs in ({'category': 'x'}, {'period': '1y'}, {'page': 0}):
            with self.assertRaises(ActivityQueryError):
                list_changes(**kwargs)


class ScanListTests(ActivityTestCase):
    def test_active_first_then_newest(self):
        result = list_scans()
        self.assertEqual([(s['kind'], s['status']) for s in result['items']], [
            ('scan', 'running'), ('discovery', 'running'),          # running, oldest first
            ('deep_scan', 'pending'),
            ('monitor', 'failed'), ('deep_scan', 'completed'),     # finished, newest first
        ])
        self.assertEqual(result['active'], {'pending': 1, 'running': 2})

    def test_readable_rows(self):
        items = {(s['scan_type'], s['status']): s for s in list_scans()['items']}
        self.assertEqual(items[('input_discovery', 'running')]['target'], 'a.com, b.com, 10.0.0.1 (+1 more)')
        self.assertEqual(items[('phase2_deep_scan', 'completed')]['duration'], '4m 0s')
        self.assertIsNone(items[('phase2_deep_scan', 'pending')]['duration'])
        self.assertEqual((items[('phase1', 'running')]['asset_type'], items[('monitor_run', 'failed')]['asset_type']), ('domain', None))

    def test_filters(self):
        self.assertEqual(len(list_scans(kind='deep_scan')['items']), 2)
        self.assertEqual([s['target'] for s in list_scans(status='failed')['items']], ['takeover'])
        self.assertEqual(len(list_scans(status='running')['items']), 2)    # 'running' and 'processing'
        self.assertEqual(len(list_scans(query='shop')['items']), 1)
        for kwargs in ({'kind': 'x'}, {'status': 'x'}):
            with self.assertRaises(ActivityQueryError):
                list_scans(**kwargs)

    def test_manual_jobs_are_stamped_in_utc(self):
        from utils.pipeline import enqueue_input_discovery, enqueue_monitor_run
        before = ago(seconds=5)
        for job_id in (enqueue_input_discovery({'domains': ['c.com']}), enqueue_monitor_run('intel')[0]):
            conn = db_utils.get_db_connection()
            queued_at = conn.execute('SELECT queued_at FROM scan_queue WHERE queue_id = ?', (job_id,)).fetchone()[0]
            conn.close()
            self.assertGreaterEqual(queued_at, before)
            self.assertLessEqual(queued_at, ago(seconds=-5))

    def test_old_finished_items_are_pruned(self):
        conn = db_utils.get_db_connection()
        conn.executemany("INSERT INTO scan_queue (scan_type, cycle, target, status, queued_at, completed_at) VALUES (?, 'standard', ?, ?, ?, ?)", [
            ('phase1', 'old-done.example.com', 'completed', ago(days=120), ago(days=120)),
            ('phase1', 'old-failed.example.com', 'failed', ago(days=100), ago(days=100)),
            ('phase2_deep_scan', 'old-pending.example.com', 'pending', ago(days=200), None),   # still waiting: kept
        ])
        conn.commit()
        conn.close()
        self.assertEqual(db_utils.prune_scan_queue(days=90), 2)
        targets = [s['target'] for s in list_scans(page_size=50)['items']]
        self.assertIn('old-pending.example.com', targets)
        self.assertEqual(len(targets), 6)                                  # the 5 recent ones + the pending one

    def test_duration(self):
        self.assertEqual(_duration('2026-01-01 10:00:00', '2026-01-01 11:04:30'), '1h 4m')
        self.assertEqual(_duration('2026-01-01T10:00:00', '2026-01-01 10:00:08'), '8s')
        self.assertIsNone(_duration('2026-01-01 10:00:00', None))
        self.assertIsNone(_duration('garbage', '2026-01-01 10:00:00'))


class WebTests(ActivityTestCase):
    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.client = main.app.test_client()
        self.client.set_cookie('access_token', access_token(main))

    def test_changes_page(self):
        html = self.client.get('/changes?category=ports').get_data(as_text=True)
        self.assertIn('Port 8080 opened', html)
        self.assertNotIn('Host went down', html)
        self.assertIn(f'href="/assets/subdomain/{self.sub_id}"', html)

        html = self.client.get('/changes?host=shop.example.com').get_data(as_text=True)
        self.assertIn('Host: <span class="font-mono">shop.example.com</span>', html)
        self.assertNotIn('Host went down', html)

        response = self.client.get('/changes?period=forever')
        self.assertEqual(response.status_code, 302)

    def test_changes_pagination_keeps_filters(self):
        conn = db_utils.get_db_connection()
        conn.executemany('INSERT INTO asset_changes (host, change_type, summary, detected_at) VALUES (?, ?, ?, ?)',
                         [('shop.example.com', 'tech_added', f'Tech {n}', ago(hours=2)) for n in range(60)])
        conn.commit()
        conn.close()
        html = self.client.get('/changes?period=30d').get_data(as_text=True)
        self.assertIn('/changes?period=30d&amp;page=2', html)

    def test_scans_page(self):
        html = self.client.get('/scans').get_data(as_text=True)
        self.assertIn('action="/process_assets"', html)
        self.assertIn('data-run-check="takeover"', html)
        self.assertIn('DNS timeout', html)
        self.assertIn('data-action="cancel_scan" data-asset-name="example.com"', html)
        self.assertIn('Worker not running', html)

        partial = self.client.get('/scans/queue?status=failed').get_data(as_text=True)
        self.assertIn('DNS timeout', partial)
        self.assertNotIn('<html', partial)
        self.assertEqual(self.client.get('/scans/queue?kind=x').status_code, 400)

    def test_submitting_targets_returns_to_scans(self):
        token = access_token(self.main)
        self.client.set_cookie('access_token', token)
        response = self.client.post('/process_assets', data={'asset_input': 'example.org',
                                                              'csrf_token': self.main.generate_csrf_token(token)})
        self.assertTrue(response.headers['Location'].endswith('/scans'))

    def test_asset_history_links_to_full_history(self):
        html = self.client.get(f'/assets/subdomain/{self.sub_id}').get_data(as_text=True)
        self.assertIn('href="/changes?host=shop.example.com"', html)


if __name__ == '__main__':
    unittest.main()
