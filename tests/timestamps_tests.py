import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from utils import db_utils
from utils.timeutil import parse_utc, utc_ago, utc_now


class TimestampTestCase(unittest.TestCase):
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

    def one(self, query, params=()):
        conn = db_utils.get_db_connection()
        try:
            return conn.execute(query, params).fetchone()[0]
        finally:
            conn.close()


class WritesTests(TimestampTestCase):
    def test_new_rows_are_utc(self):
        dom_id = db_utils.upsert_domain('example.com')
        db_utils.upsert_subdomain('shop.example.com', dom_id)
        for query in ("SELECT first_seen FROM subdomain_asset", "SELECT detected_at FROM asset_changes ORDER BY change_id DESC"):
            stored = parse_utc(self.one(query))
            self.assertLess(abs((stored - utc_now()).total_seconds()), 60, query)


class MigrationTests(TimestampTestCase):
    def setUp(self):
        super().setUp()
        conn = db_utils.get_db_connection()
        conn.execute("DELETE FROM settings WHERE key = 'timestamps_in_utc'")   # as before the migration existed
        conn.executescript("""
            INSERT INTO domain_asset (domain_name, first_seen, status, last_liveness_check)
                VALUES ('example.com', '2026-10-01 15:00:00', 'up', '2026-10-01 08:00:00');
            INSERT INTO asset_changes (host, change_type, summary, detected_at)
                VALUES ('example.com', 'asset_added', 'x', '2026-10-01 15:00:05');
            INSERT INTO cve_intel (cve_id, kev_due_date, updated_at) VALUES ('CVE-1', '2026-11-01', '2026-10-01 15:00:00');
            INSERT INTO certificates (hostname, not_after, first_seen, source)
                VALUES ('example.com', '2026-12-01 00:00:00', '2026-10-01 15:00:00', 'tls');
        """)
        conn.commit()
        self.conn = conn

    def tearDown(self):
        self.conn.close()      # before the file is removed (Windows locks open files)
        super().tearDown()

    def migrate(self, offset):
        cursor = self.conn.cursor()
        done = InitDB.migrate_timestamps_to_utc(cursor, offset_seconds=offset)
        self.conn.commit()
        return done

    def test_local_columns_shift_once(self):
        self.assertTrue(self.migrate(7 * 3600))          # server was UTC+7
        self.assertFalse(self.migrate(7 * 3600))         # marker claimed: never twice
        self.assertEqual(self.one("SELECT first_seen FROM domain_asset"), '2026-10-01 08:00:00')
        self.assertEqual(self.one("SELECT detected_at FROM asset_changes"), '2026-10-01 08:00:05')
        self.assertEqual(self.one("SELECT updated_at FROM cve_intel"), '2026-10-01 08:00:00')
        self.assertEqual(self.one("SELECT first_seen FROM certificates"), '2026-10-01 08:00:00')
        # already UTC, or dates only: untouched
        self.assertEqual(self.one("SELECT last_liveness_check FROM domain_asset"), '2026-10-01 08:00:00')
        self.assertEqual(self.one("SELECT not_after FROM certificates"), '2026-12-01 00:00:00')
        self.assertEqual(self.one("SELECT kev_due_date FROM cve_intel"), '2026-11-01')
        self.assertEqual(self.one("SELECT value FROM settings WHERE key = 'timestamps_in_utc'"), '-25200')

    def test_negative_offset(self):
        self.migrate(-5 * 3600)                          # UTC-5
        self.assertEqual(self.one("SELECT first_seen FROM domain_asset"), '2026-10-01 20:00:00')

    def test_utc_server_changes_nothing(self):
        self.assertTrue(self.migrate(0))
        self.assertEqual(self.one("SELECT first_seen FROM domain_asset"), '2026-10-01 15:00:00')


class DisplayTests(TimestampTestCase):
    def test_filter(self):
        import main
        f = main.app.jinja_env.filters['localtime']
        self.assertEqual(str(f('2026-10-01 08:00:05')),
                         '<time datetime="2026-10-01T08:00:05Z" data-local="datetime" title="2026-10-01 08:00:05 UTC">'
                         '2026-10-01 08:00 UTC</time>')
        self.assertIn('>2026-10-01 UTC</time>', str(f('2026-10-01 08:00:05', 'date')))
        self.assertEqual(f(None), '-')
        self.assertIn('&lt;b&gt;', str(f('<b>')))             # escaped

    def test_period_filters_use_utc(self):
        from utils.activity_repository import list_changes
        conn = db_utils.get_db_connection()
        conn.executemany("INSERT INTO asset_changes (host, change_type, summary, detected_at) VALUES ('h', 'asset_up', ?, ?)",
                         [('recent', utc_ago(hours=23)), ('old', utc_ago(hours=25))])
        conn.commit()
        conn.close()
        self.assertEqual([c['summary'] for c in list_changes(period='24h')['items']], ['recent'])


if __name__ == '__main__':
    unittest.main()
