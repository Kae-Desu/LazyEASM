import contextlib
import io
import os
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from tests.helpers import TEST_PASSWORD, access_token
from utils import backup, db_utils, env_manager, screenshots


class BackupTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, 'db', 'lazyeasm.db')
        os.makedirs(os.path.dirname(self.db_path))
        self.env_file = Path(self.tmp) / '.env'
        self.env_file.write_text('JWT_SECRET=original\n')
        self.shots = os.path.join(self.tmp, 'shots')
        for target, attr, value in ((InitDB, 'DB_NAME', self.db_path), (db_utils, 'DB_PATH', self.db_path),
                                    (backup, 'BACKUP_DIR', os.path.join(self.tmp, 'backups')),
                                    (env_manager, 'ENV_FILE', self.env_file),
                                    (screenshots, 'SCREENSHOT_DIR', self.shots)):
            p = patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        db_utils.upsert_domain('example.com')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def domains(self, path=None):
        conn = sqlite3.connect(path or self.db_path)
        try:
            return [r[0] for r in conn.execute('SELECT domain_name FROM domain_asset ORDER BY 1')]
        finally:
            conn.close()


class SnapshotTests(BackupTestCase):
    def test_snapshot_is_a_consistent_copy(self):
        path = backup.create_backup('manual')
        self.assertRegex(os.path.basename(path), r'^lazyeasm-\d{8}-\d{6}-manual\.db$')
        self.assertEqual(self.domains(path), ['example.com'])
        backup.validate_database(path)
        if os.name == 'posix':
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_listing_and_retention_per_kind(self):
        names = [f'lazyeasm-2026010{d}-120000-daily.db' for d in range(1, 6)] + ['lazyeasm-20260101-090000-pre-upgrade.db']
        os.makedirs(backup.BACKUP_DIR)
        for name in names + ['notes.txt']:
            open(os.path.join(backup.BACKUP_DIR, name), 'w').close()
        listed = backup.list_backups()
        self.assertEqual(listed[0]['name'], 'lazyeasm-20260105-120000-daily.db')
        self.assertEqual(listed[0]['created_at'], '2026-01-05 12:00:00')
        self.assertEqual(len(listed), 6)                                   # unrelated files ignored
        self.assertEqual(backup.prune('daily', 2), 3)
        self.assertEqual(sorted(b['name'] for b in backup.list_backups()),
                         ['lazyeasm-20260101-090000-pre-upgrade.db', 'lazyeasm-20260104-120000-daily.db',
                          'lazyeasm-20260105-120000-daily.db'])


class DailyTests(BackupTestCase):
    def test_daily_once_and_respects_settings(self):
        self.assertIsNotNone(backup.run_daily()['created'])
        self.assertEqual(backup.run_daily()['skipped'], 'recent')
        db_utils.set_setting(backup.LAST_KEY, '2020-01-01 00:00:00')
        self.assertIsNotNone(backup.run_daily()['created'])
        self.assertEqual(backup.save_settings({'backup_keep': '3'}), [])   # checkbox unticked: off
        self.assertEqual(backup.run_daily()['skipped'], 'disabled')
        self.assertEqual(backup.get_settings()['keep'], 3)

    def test_settings_validation(self):
        self.assertTrue(backup.save_settings({'backup_keep': '0'}))
        self.assertTrue(backup.save_settings({'backup_keep': 'many'}))
        self.assertTrue(backup.get_settings()['enabled'])                  # nothing stored


class UpgradeTests(BackupTestCase):
    def test_backup_only_when_the_schema_code_changed(self):
        backup.record_schema_signature()
        self.assertIsNone(backup.backup_before_upgrade())
        db_utils.set_setting(backup.SCHEMA_KEY, 'older-version')
        path = backup.backup_before_upgrade()
        self.assertIn('pre-upgrade', path)

    def test_no_database_yet(self):
        os.remove(self.db_path)
        self.assertIsNone(backup.backup_before_upgrade())


class ArchiveAndRestoreTests(BackupTestCase):
    def setUp(self):
        super().setUp()
        os.makedirs(self.shots)
        Path(self.shots, 'a' * 32 + '.jpg').write_bytes(b'jpg')
        Path(self.shots, 'notes.txt').write_text('not a screenshot')
        p = patch.object(backup, '_is_running', return_value=False)
        p.start()
        self.addCleanup(p.stop)

    def test_archive_contents(self):
        plain = backup.build_archive()
        self.addCleanup(os.remove, plain)
        self.assertEqual(sorted(zipfile.ZipFile(plain).namelist()), ['lazyeasm.db', 'manifest.json'])
        full = backup.build_archive(include_screenshots=True, include_env=True)
        self.addCleanup(os.remove, full)
        self.assertEqual(sorted(zipfile.ZipFile(full).namelist()),
                         ['.env', 'lazyeasm.db', 'manifest.json', f"screenshots/{'a' * 32}.jpg"])

    def test_restore_from_zip(self):
        archive = backup.build_archive(include_screenshots=True, include_env=True)
        self.addCleanup(os.remove, archive)
        db_utils.upsert_domain('added-after-backup.com')
        self.env_file.write_text('JWT_SECRET=changed\n')
        shutil.rmtree(self.shots)

        result = backup.restore(archive)
        self.assertEqual(self.domains(), ['example.com'])
        self.assertEqual(self.domains(result['previous']), ['added-after-backup.com', 'example.com'])
        self.assertEqual((result['screenshots'], result['env']), (1, False))
        self.assertEqual(self.env_file.read_text(), 'JWT_SECRET=changed\n')   # .env only with --with-env

        backup.restore(archive, with_env=True)
        self.assertEqual(self.env_file.read_text(), 'JWT_SECRET=original\n')
        self.assertEqual(Path(str(self.env_file) + '.pre-restore').read_text(), 'JWT_SECRET=changed\n')

    def test_restore_refuses_bad_input(self):
        with patch.object(backup, '_is_running', return_value=True):
            with self.assertRaisesRegex(backup.BackupError, 'running'):
                backup.restore(backup.create_backup('manual'))
        not_db = os.path.join(self.tmp, 'notes.db')
        Path(not_db).write_text('hello')
        with self.assertRaisesRegex(backup.BackupError, 'not a LazyEASM database'):
            backup.restore(not_db)
        other = os.path.join(self.tmp, 'other.db')
        sqlite3.connect(other).execute('CREATE TABLE x (a)').connection.commit()
        with self.assertRaisesRegex(backup.BackupError, 'missing tables'):
            backup.restore(other)
        self.assertEqual(self.domains(), ['example.com'])                  # untouched

    def test_crafted_archive_cannot_write_outside(self):
        crafted = os.path.join(self.tmp, 'crafted.zip')
        with zipfile.ZipFile(crafted, 'w') as zf:
            zf.write(backup.create_backup('manual'), 'lazyeasm.db')
            zf.writestr('screenshots/../../evil.jpg', 'x')
            zf.writestr('../outside.txt', 'x')
        backup.restore(crafted)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'evil.jpg')))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.tmp), 'outside.txt')))


class WebTests(BackupTestCase):
    def setUp(self):
        super().setUp()
        import main
        self.main = main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)
        self.csrf = main.generate_csrf_token(token)
        main.login_attempts.clear()

    def test_download_needs_the_password(self):
        response = self.client.post('/backup/download', data={'csrf_token': self.csrf, 'password': 'wrong'})
        self.assertEqual(response.status_code, 302)
        response = self.client.post('/backup/download', data={'csrf_token': self.csrf, 'password': TEST_PASSWORD})
        self.assertEqual((response.status_code, response.mimetype), (200, 'application/zip'))
        self.assertIn('attachment; filename=lazyeasm-backup-', response.headers['Content-Disposition'])
        self.assertIn('lazyeasm.db', zipfile.ZipFile(io.BytesIO(response.get_data())).namelist())
        response.close()

    def test_tab_create_and_settings(self):
        self.client.post('/backup/create', data={'csrf_token': self.csrf})
        html = self.client.get('/settings').get_data(as_text=True)
        self.assertIn('id="panel-backup"', html)
        self.assertRegex(html, r'lazyeasm-\d{8}-\d{6}-manual\.db')
        self.client.post('/save_backup_settings', data={'csrf_token': self.csrf, 'backup_keep': '14', 'backup_enabled': '1'})
        self.assertEqual(backup.get_settings()['keep'], 14)


if __name__ == '__main__':
    unittest.main()
