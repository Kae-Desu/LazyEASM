import contextlib
import io
import json
import os
import tempfile
import threading
import time
import unittest

from tests.helpers import access_token
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from utils import db_utils, pipeline, queue_manager, worker_runtime, phase3_worker


def wait_for(condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


class TempDbTestCase(unittest.TestCase):
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

    def rows(self, scan_type):
        conn = db_utils.get_db_connection()
        try:
            return [dict(r) for r in conn.execute(
                'SELECT target, status FROM scan_queue WHERE scan_type = ? ORDER BY queue_id', (scan_type,))]
        finally:
            conn.close()


class DatabaseModeTests(TempDbTestCase):
    def test_wal_mode_enabled(self):
        conn = db_utils.get_db_connection()
        try:
            self.assertEqual(conn.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        finally:
            conn.close()


class TaskQueueTests(TempDbTestCase):
    def test_enqueue_dedupes_pending_and_running(self):
        q = queue_manager.TaskQueue()
        first = q.enqueue(1, 'domain', 'example.com')
        self.assertEqual(q.enqueue(1, 'domain', 'example.com'), first)
        self.assertEqual(len(self.rows('phase1')), 1)

    def test_status_counts_current_batch(self):
        q = queue_manager.TaskQueue()
        self.assertEqual(q.get_status()['active'], False)
        q.enqueue(1, 'domain', 'a.example.com')
        q.enqueue(2, 'domain', 'b.example.com')
        task = queue_manager.Phase1Worker.claim_next()
        self.assertEqual(task['target'], 'a.example.com')

        status = q.get_status()
        self.assertEqual((status['pending'], status['running'], status['active']), (1, 1, True))

    def test_claim_is_exclusive(self):
        q = queue_manager.TaskQueue()
        for i in range(20):
            q.enqueue(i, 'domain', f'h{i}.example.com')
        claimed = []
        threads = [threading.Thread(target=lambda: claimed.extend(
            iter(queue_manager.Phase1Worker.claim_next, None))) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(c['target'] for c in claimed), sorted(f'h{i}.example.com' for i in range(20)))

    def test_recover_interrupted(self):
        q = queue_manager.TaskQueue()
        q.enqueue(1, 'domain', 'example.com')
        queue_manager.Phase1Worker.claim_next()
        self.assertEqual(queue_manager.Phase1Worker.recover_interrupted(), 1)
        self.assertEqual(self.rows('phase1'), [{'target': 'example.com', 'status': 'pending'}])


class Phase1WorkerTests(TempDbTestCase):
    def test_processes_queue_and_notifies_once_per_batch(self):
        def fake_run(asset_id, asset_type, asset_name):
            if asset_name == 'bad.example.com':
                raise RuntimeError('scan failed')
            return {'ports_found': 2, 'tech_found': 3, 'cve_found': 1}

        worker = queue_manager.Phase1Worker(max_workers=2, poll_seconds=0.05)
        q = queue_manager.TaskQueue()
        for name in ('a.example.com', 'b.example.com', 'bad.example.com'):
            q.enqueue(None, 'domain', name)

        with patch('modules.phase1_runner.run_phase1', side_effect=fake_run), \
             patch.object(queue_manager.Phase1Worker, '_send_completion_notification') as notify:
            worker.start()
            try:
                self.assertTrue(wait_for(lambda: notify.called))
            finally:
                worker.stop()

        notify.assert_called_once_with(2, 1)
        self.assertEqual({r['target']: r['status'] for r in self.rows('phase1')}, {
            'a.example.com': 'completed', 'b.example.com': 'completed', 'bad.example.com': 'failed'})


class PipelineTests(TempDbTestCase):
    def test_submitted_assets_become_a_worker_job(self):
        pipeline.enqueue_input_discovery({'domains': ['example.com'], 'invalid': ['x'], 'ips': []})
        job = worker_runtime._claim_input_job()
        self.assertEqual(json.loads(job['target']), {'domains': ['example.com'], 'ips': []})
        self.assertIsNone(worker_runtime._claim_input_job())

    def test_discovery_loop_runs_and_records_outcome(self):
        pipeline.enqueue_input_discovery({'domains': ['ok.example.com']})
        pipeline.enqueue_input_discovery({'domains': ['boom.example.com']})

        def fake_discovery(targets):
            if targets['domains'] == ['boom.example.com']:
                raise RuntimeError('discovery failed')

        with patch.object(pipeline, 'run_input_discovery', side_effect=fake_discovery), \
             patch.object(worker_runtime, 'JOB_POLL_SECONDS', 0.05), \
             patch.object(worker_runtime, '_running', True):
            thread = threading.Thread(target=worker_runtime._input_discovery_loop, daemon=True)
            thread.start()
            self.assertTrue(wait_for(lambda: all(r['status'] != 'pending' for r in self.rows('input_discovery'))
                                     and all(r['status'] != 'processing' for r in self.rows('input_discovery'))))
            worker_runtime._running = False
        thread.join(timeout=2)
        self.assertEqual([r['status'] for r in self.rows('input_discovery')], ['completed', 'failed'])

    def test_phase0_discoveries_reach_the_phase1_queue(self):
        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO domain_asset (dom_id, domain_name) VALUES (1, 'example.com')")
        conn.execute("INSERT INTO subdomain_asset (sub_id, dom_id, subdomain_name) VALUES (7, 1, 'new.example.com')")
        conn.commit()
        conn.close()

        pipeline.enqueue_single_asset_for_phase1('new.example.com', 'subdomain')
        task = queue_manager.Phase1Worker.claim_next()
        self.assertEqual((task['target'], task['target_id']), ('new.example.com', 7))

    def test_recover_interrupted_jobs(self):
        conn = db_utils.get_db_connection()
        conn.executescript("""
            INSERT INTO scan_queue (scan_type, cycle, target, status) VALUES
                ('input_discovery', 'standard', '{}', 'processing'),
                ('phase2_deep_scan', 'standard', 'a.example.com', 'processing'),
                ('phase2_deep_scan', 'standard', 'b.example.com', 'completed'),
                ('phase1', 'standard', 'c.example.com', 'running');
        """)
        conn.commit()
        conn.close()
        self.assertEqual(worker_runtime.recover_interrupted_jobs(), 3)
        self.assertEqual(self.rows('phase2_deep_scan')[1]['status'], 'completed')


class HeartbeatTests(TempDbTestCase):
    def test_fresh_stale_and_missing(self):
        self.assertFalse(worker_runtime.get_worker_status()['alive'])

        with patch.object(worker_runtime, '_component_status', return_value={'phase1': True}):
            worker_runtime.write_heartbeat()
        status = worker_runtime.get_worker_status()
        self.assertTrue(status['alive'])
        self.assertEqual(status['components'], {'phase1': True})

        db_utils.set_setting(worker_runtime.HEARTBEAT_KEY,
                             json.dumps({'ts': '2020-01-01T00:00:00Z', 'components': {}}))
        self.assertFalse(worker_runtime.get_worker_status()['alive'])

    def test_clean_stop_clears_the_heartbeat_at_once(self):
        with patch.object(worker_runtime, '_component_status', return_value={'phase1': True}):
            worker_runtime.write_heartbeat()
        self.assertTrue(worker_runtime.get_worker_status()['alive'])
        with patch('utils.queue_manager.phase1_worker.stop'), patch('utils.phase0_worker.stop_phase0_worker'), \
                patch('utils.phase3_worker.stop_phase3_workers'):
            worker_runtime.stop_background_workers()
        self.assertFalse(worker_runtime.get_worker_status()['alive'])     # not 60 seconds later


class MonitorLoopTests(unittest.TestCase):
    def test_follows_enabled_flag_and_live_interval_changes(self):
        settings = {'phase3_enabled': '0', 'test_interval': '3600'}
        calls = []
        monitors = {'testcheck': ('test_interval', 3600, 1, lambda: calls.append(1))}
        with patch.object(phase3_worker, 'POLL_SECONDS', 0.02),              patch.object(phase3_worker, 'MONITORS', monitors),              patch.object(phase3_worker, '_phase3_running', True),              patch('utils.db_utils.get_setting', side_effect=lambda key: settings.get(key)),              patch('utils.db_utils.set_setting', side_effect=settings.__setitem__):
            thread = threading.Thread(target=phase3_worker._monitor_loop, args=('test', 'testcheck'), daemon=True)
            thread.start()
            time.sleep(0.2)
            self.assertEqual(calls, [])           # disabled: never runs

            settings['phase3_enabled'] = '1'
            self.assertTrue(wait_for(lambda: len(calls) == 1, timeout=2))  # enabling runs promptly
            time.sleep(0.2)
            self.assertEqual(len(calls), 1)       # not again before the 3600s interval

            settings['test_interval'] = '1'       # changed in the dashboard
            self.assertTrue(wait_for(lambda: len(calls) == 2, timeout=3))  # new interval applies live
            phase3_worker._phase3_running = False
        thread.join(timeout=2)

    def test_restart_does_not_rerun_checks_that_ran_recently(self):
        settings = {'phase3_enabled': '1', 'test_interval': '3600',
                    'monitor_last_run_testcheck': str(int(time.time()) - 60)}   # ran a minute ago
        calls = []
        monitors = {'testcheck': ('test_interval', 3600, 1, lambda: calls.append(1))}
        with patch.object(phase3_worker, 'POLL_SECONDS', 0.02), patch.object(phase3_worker, 'MONITORS', monitors),              patch.object(phase3_worker, '_phase3_running', True),              patch('utils.db_utils.get_setting', side_effect=lambda key: settings.get(key)),              patch('utils.db_utils.set_setting', side_effect=settings.__setitem__):
            thread = threading.Thread(target=phase3_worker._monitor_loop, args=('test', 'testcheck'), daemon=True)
            thread.start()
            time.sleep(0.2)
            self.assertEqual(calls, [])           # a fresh worker waits for the interval

            settings['monitor_last_run_testcheck'] = str(int(time.time()) - 4000)
            self.assertTrue(wait_for(lambda: len(calls) == 1, timeout=2))
            self.assertGreater(float(settings['monitor_last_run_testcheck']), time.time() - 5)
            phase3_worker._phase3_running = False
        thread.join(timeout=2)


class WebIntegrationTests(TempDbTestCase):
    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.client = main.app.test_client()

    def test_health_reflects_worker_heartbeat(self):
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()['checks']['worker'], 'error: no heartbeat')

        components = {name: True for name in ('phase0', 'discovery', 'phase1', 'phase2', 'phase3')}
        with patch.object(worker_runtime, '_component_status', return_value=components):
            worker_runtime.write_heartbeat()
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200, response.get_json())

    def test_submitting_assets_queues_a_job_instead_of_a_thread(self):
        import jwt
        import datetime
        token = access_token(self.main)
        self.client.set_cookie('access_token', token)
        with patch('threading.Thread') as thread:
            self.client.post('/process_assets', data={'asset_input': 'example.com',
                                                      'csrf_token': self.main.generate_csrf_token(token)})
        thread.assert_not_called()
        self.assertEqual([r['status'] for r in self.rows('input_discovery')], ['pending'])

    def test_toggle_only_flips_the_setting(self):
        import jwt
        import datetime
        token = access_token(self.main)
        self.client.set_cookie('access_token', token)
        with patch.object(phase3_worker, 'start_phase3_workers') as start:
            response = self.client.post('/api/phase3/toggle', json={'enabled': True, 'csrf_token': self.main.generate_csrf_token(token)})
        start.assert_not_called()
        self.assertTrue(response.get_json()['enabled'])
        self.assertEqual(db_utils.get_setting('phase3_enabled'), '1')


if __name__ == '__main__':
    unittest.main()
