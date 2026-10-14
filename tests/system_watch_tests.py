import contextlib
import io
import json
import os
import tempfile
import unittest
from collections import namedtuple
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from tests.helpers import access_token
from utils import db_utils, scan_settings, system_watch, worker_runtime

GB = 1024 ** 3
Usage = namedtuple('Usage', 'total used free')


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


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

    def disk(self, used_percent, total=100 * GB):
        free = total * (100 - used_percent) / 100
        return patch.object(system_watch.shutil, 'disk_usage', return_value=Usage(total, total - free, free))

    def heartbeat(self, components=None, age=0):
        from datetime import datetime, timedelta, timezone
        ts = (datetime.now(timezone.utc) - timedelta(seconds=age)).strftime('%Y-%m-%dT%H:%M:%SZ')
        db_utils.set_setting(worker_runtime.HEARTBEAT_KEY, json.dumps({
            'ts': ts, 'pid': 1,
            'components': components or {n: True for n in ('phase0', 'discovery', 'phase1', 'phase2', 'phase3')}}))


class AlertStateTests(unittest.TestCase):
    def test_alert_after_delay_once_then_daily_reminder_then_recovery(self):
        clock = Clock()
        alert = system_watch.Alert(clock)
        self.assertIsNone(alert.update(True, 300))
        clock.now += 299
        self.assertIsNone(alert.update(True, 300))
        clock.now += 1
        self.assertEqual(alert.update(True, 300), 'alert')
        alert.sent()
        clock.now += 3600
        self.assertIsNone(alert.update(True, 300))                 # no repeat within a day
        clock.now += system_watch.REMIND_AFTER
        self.assertEqual(alert.update(True, 300), 'remind')
        alert.sent()
        self.assertEqual(alert.update(False, 300), 'recovered')
        self.assertIsNone(alert.update(False, 300))

    def test_problem_that_started_earlier_alerts_immediately(self):
        alert = system_watch.Alert(Clock())
        self.assertEqual(alert.update(True, 300, started_ago=400), 'alert')   # heartbeat already 400 s old

    def test_unsent_problem_clears_silently(self):
        alert = system_watch.Alert(Clock())
        alert.update(True, 300)
        self.assertIsNone(alert.update(False, 300))


class WatchdogTests(TempDbTestCase):
    def watchdog(self, results=None):
        self.sent = []
        results = iter(results or [])

        def send(message):
            self.sent.append(message)
            return next(results, (True, 'Sent via discord'))
        self.clock = Clock()
        return system_watch.Watchdog(send=send, clock=self.clock)

    def test_worker_stopped_alert_and_recovery(self):
        watchdog = self.watchdog()
        with self.disk(50):
            self.heartbeat(age=600)                                # stale for 10 minutes
            watchdog.check()
            self.assertEqual(len(self.sent), 1)
            self.assertIn('LazyEASM worker stopped', self.sent[0])
            self.assertIn('last heartbeat 10 min ago', self.sent[0])
            watchdog.check()
            self.assertEqual(len(self.sent), 1)                    # not repeated

            self.heartbeat()
            watchdog.check()
            self.assertIn('worker running again', self.sent[1])

    def test_worker_alert_waits_for_the_setting_and_can_be_off(self):
        watchdog = self.watchdog()
        with self.disk(50):
            self.heartbeat(age=120)                                # e.g. a restart in progress
            watchdog.check()
            self.assertEqual(self.sent, [])

            db_utils.set_setting('worker_alert_minutes', '0')
            self.heartbeat(age=3600)
            watchdog.check()
            self.assertEqual(self.sent, [])

    def test_stopped_component_counts_as_worker_problem(self):
        watchdog = self.watchdog()
        self.heartbeat(components={'phase0': True, 'discovery': True, 'phase1': True, 'phase2': True,
                                   'phase3': False})
        with self.disk(50):
            watchdog.check()
            self.assertEqual(self.sent, [])
            self.clock.now += 5 * 60
            watchdog.check()
        self.assertIn('phase3 not running', self.sent[0])

    def test_disk_alert_threshold_free_space_floor_and_recovery(self):
        watchdog = self.watchdog()
        self.heartbeat()
        with self.disk(85):
            watchdog.check()
        self.assertEqual(self.sent, [])
        with self.disk(93):
            watchdog.check()
            watchdog.check()
        self.assertEqual(len(self.sent), 1)
        self.assertIn('Disk almost full', self.sent[0])
        self.assertIn('93% used, 7.0 GB free', self.sent[0])
        with self.disk(60):
            watchdog.check()
        self.assertIn('Disk space back to normal', self.sent[1])

        # A small disk below 1 GB free alerts even under the percentage
        with patch.object(system_watch.shutil, 'disk_usage', return_value=Usage(5 * GB, 4.2 * GB, 0.8 * GB)):
            self.assertTrue(system_watch.disk_status()['low'])
        db_utils.set_setting('disk_alert_percent', '0')
        with self.disk(99):
            self.assertFalse(system_watch.disk_status()['low'])

    def test_failed_send_is_retried_and_no_channel_is_not(self):
        watchdog = self.watchdog(results=[(False, 'All channels failed'), (True, 'Sent via slack')])
        self.heartbeat()
        with self.disk(95):
            watchdog.check()
            watchdog.check()
            watchdog.check()
        self.assertEqual(len(self.sent), 2)                        # failed, then retried once successfully

        watchdog = self.watchdog(results=[(False, 'No notification channel configured')])
        with self.disk(95):
            watchdog.check()
            watchdog.check()
        self.assertEqual(len(self.sent), 1)

    def test_database_unreadable_still_alerts_with_defaults(self):
        watchdog = self.watchdog()
        with self.disk(95), patch('utils.db_utils.get_setting', side_effect=Exception('disk I/O error')):
            watchdog.check()
            self.clock.now += 5 * 60                               # default worker delay
            watchdog.check()
        self.assertTrue(any('worker stopped' in m and 'unreadable' in m for m in self.sent))
        self.assertTrue(any('Disk almost full' in m for m in self.sent))


class SettingsAndPageTests(TempDbTestCase):
    def test_system_alert_settings_are_validated_and_saved(self):
        self.assertEqual({a['name']: a['value'] for a in scan_settings.get_system_alerts()},
                         {'worker': 5, 'disk': 90})
        errors, _ = scan_settings.save_scanning_settings({'disk_alert_percent': '100'})
        self.assertIn('between 0 and 99', errors[0])
        errors, changed = scan_settings.save_scanning_settings({'disk_alert_percent': '80',
                                                                'worker_alert_minutes': '0'})
        self.assertEqual(errors, [])
        self.assertEqual(scan_settings.system_alert_value('disk'), 80)
        self.assertEqual(scan_settings.system_alert_value('worker'), 0)

    def test_banner_and_health(self):
        import main
        client = main.app.test_client()
        client.set_cookie('access_token', access_token(main))
        self.heartbeat()
        with self.disk(50):
            page = client.get('/scans').get_data(as_text=True)
            self.assertNotIn('background worker is not running', page)
            self.assertEqual(client.get('/health').get_json()['checks']['disk'], 'ok')

        self.heartbeat(age=600)
        with self.disk(95):
            page = client.get('/scans').get_data(as_text=True)
            self.assertIn('background worker is not running', page)
            self.assertIn('disk is almost full', page)
            self.assertIn('warning: 95% used', client.get('/health').get_json()['checks']['disk'])

        with patch.object(system_watch.shutil, 'disk_usage', return_value=Usage(100 * GB, 100 * GB, 50 * 1024 ** 2)):
            health = client.get('/health')
        self.assertEqual(health.status_code, 503)
        self.assertIn('error: full', health.get_json()['checks']['disk'])


if __name__ == '__main__':
    unittest.main()
