import contextlib
import datetime
import io
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
from utils import db_utils, phase3_worker, phase_lock, pipeline, worker_runtime


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


class ManualCheckTests(TempDbTestCase):
    def setUp(self):
        super().setUp()
        import jwt
        import main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)
        self.headers = {'X-CSRF-Token': main.generate_csrf_token(token)}

    def test_route_queues_instead_of_running_in_the_request(self):
        with patch.object(phase3_worker, 'run_monitor') as run:
            first = self.client.post('/api/phase3/takeover/check', headers=self.headers)
            second = self.client.post('/api/phase3/takeover/check', headers=self.headers)
        run.assert_not_called()
        self.assertEqual(first.status_code, 202)
        self.assertTrue(first.get_json()['queued'])
        self.assertFalse(second.get_json()['queued'])                  # deduplicated
        self.assertEqual(first.get_json()['job_id'], second.get_json()['job_id'])

        job = self.client.get(f"/api/jobs/{first.get_json()['job_id']}").get_json()['job']
        self.assertEqual((job['target'], job['status']), ('takeover', 'pending'))
        self.assertEqual(self.client.post('/api/phase3/bogus/check', headers=self.headers).status_code, 404)
        self.assertEqual(self.client.get('/api/jobs/9999').status_code, 404)

    def test_worker_runs_queued_checks_and_records_failures(self):
        ok_id, _ = pipeline.enqueue_monitor_run('intel')
        bad_id, _ = pipeline.enqueue_monitor_run('misconfig')
        ran = []

        def fake_run(name):
            ran.append(name)
            if name == 'misconfig':
                raise RuntimeError('boom')

        with patch.object(phase3_worker, 'run_monitor', side_effect=fake_run), \
             patch.object(worker_runtime, 'JOB_POLL_SECONDS', 0.05), \
             patch.object(worker_runtime, '_running', True):
            thread = threading.Thread(target=worker_runtime._input_discovery_loop, daemon=True)
            thread.start()
            self.assertTrue(wait_for(lambda: pipeline.get_job(bad_id)['status'] == 'failed'))
            worker_runtime._running = False
        thread.join(timeout=2)

        self.assertEqual(ran, ['intel', 'misconfig'])
        self.assertEqual(pipeline.get_job(ok_id)['status'], 'completed')
        self.assertEqual(pipeline.get_job(bad_id)['error_message'], 'boom')


class MonitorLockTests(unittest.TestCase):
    def test_manual_and_scheduled_runs_do_not_overlap(self):
        active, overlaps, runs = [0], [], []

        def slow():
            active[0] += 1
            runs.append(1)
            if active[0] > 1:
                overlaps.append(True)
            time.sleep(0.1)
            active[0] -= 1

        monitors = {'intel': ('intel_interval_hr', 24, 3600, slow)}
        with patch.object(phase3_worker, 'MONITORS', monitors), patch('utils.db_utils.set_setting'):
            threads = [threading.Thread(target=phase3_worker.run_monitor, args=('intel',)) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual((len(runs), overlaps), (3, []))
        with self.assertRaises(ValueError):
            phase3_worker.run_monitor('bogus')


class StaleLockTests(TempDbTestCase):
    def set_lock(self, started_at):
        conn = db_utils.get_db_connection()
        conn.execute('UPDATE phase_status SET current_phase = ?, started_at = ? WHERE id = 1',
                     (phase_lock.PHASE_2_RUNNING, started_at))
        conn.commit()
        conn.close()

    def test_fresh_lock_is_kept_and_stale_lock_cleared(self):
        self.set_lock(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.assertTrue(phase_lock.is_phase2_running())

        self.set_lock((datetime.datetime.now() - datetime.timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S'))
        self.assertFalse(phase_lock.is_phase2_running())
        self.assertEqual(phase_lock.get_current_phase(), phase_lock.PHASE_NONE)


if __name__ == '__main__':
    unittest.main()
