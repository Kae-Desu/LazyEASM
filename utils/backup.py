"""
Backups of the LazyEASM database (and optionally screenshots and .env).

    - Daily automatic snapshot in db/backups/ (maintenance check), keeping the
      newest N (Settings > Backup, default 7)
    - Snapshot before an upgrade changes the database (run.py, before the
      schema migrations), keeping the newest 3
    - "Back up now" and "Download backup" in Settings > Backup
    - Restore from the command line, with LazyEASM stopped:

        python -m utils.backup list
        python -m utils.backup create
        python -m utils.backup restore FILE [--with-env] [--force]

Snapshots use SQLite's online backup API, so they are consistent while scans
keep writing (copying the file of a live database can produce a corrupt copy).
"""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import timedelta
from typing import List, Optional

from utils.timeutil import parse_utc, utc_now, utc_now_str

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUP_DIR = os.path.join(PROJECT_ROOT, 'db', 'backups')
INITDB_FILE = os.path.join(PROJECT_ROOT, 'modules', 'InitDB.py')

ENABLED_KEY, KEEP_KEY, LAST_KEY = 'backup_enabled', 'backup_keep', 'last_backup_at'
SCHEMA_KEY = 'schema_signature'
DEFAULT_KEEP, MIN_KEEP, MAX_KEEP = 7, 1, 60
KEEP_PER_KIND = {'pre-upgrade': 3, 'manual': 5, 'pre-restore': 3}
DAILY_INTERVAL = timedelta(hours=20)      # maintenance runs every 24h; tolerate drift
KINDS = ('daily', 'pre-upgrade', 'manual', 'pre-restore')
NAME = re.compile(r'^lazyeasm-(\d{8}-\d{6})-(' + '|'.join(KINDS) + r')\.db$')
SCREENSHOT_NAME = re.compile(r'^[0-9a-f]{32}(_thumb)?\.jpg$')
REQUIRED_TABLES = {'settings', 'admin_user', 'domain_asset', 'subdomain_asset', 'findings'}


class BackupError(Exception):
    """A backup could not be made or restored."""


def _db_path() -> str:
    from utils import db_utils
    return db_utils.DB_PATH


def snapshot(destination: str) -> str:
    """Consistent copy of the live database to destination (0600)."""
    source_path = _db_path()
    if not os.path.exists(source_path):
        raise BackupError('there is no database to back up yet')
    os.makedirs(os.path.dirname(destination) or '.', exist_ok=True)
    tmp = destination + '.tmp'
    source = sqlite3.connect(source_path, timeout=30)
    target = sqlite3.connect(tmp)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(tmp, 0o600)
    os.replace(tmp, destination)
    return destination


def create_backup(kind: str = 'manual') -> str:
    if kind not in KINDS:
        raise ValueError(f'unknown backup kind: {kind}')
    name = f"lazyeasm-{utc_now().strftime('%Y%m%d-%H%M%S')}-{kind}.db"
    path = snapshot(os.path.join(BACKUP_DIR, name))
    prune(kind, KEEP_PER_KIND.get(kind) or get_settings()['keep'])
    return path


def list_backups() -> List[dict]:
    """Local backups, newest first: [{'name', 'kind', 'created_at' (UTC), 'size'}]"""
    try:
        names = os.listdir(BACKUP_DIR)
    except OSError:
        return []
    backups = []
    for name in names:
        m = NAME.match(name)
        if m:
            stamp = m.group(1)
            backups.append({'name': name, 'kind': m.group(2), 'size': os.path.getsize(os.path.join(BACKUP_DIR, name)),
                            'created_at': f'{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}'})
    return sorted(backups, key=lambda b: b['name'][9:24], reverse=True)


def prune(kind: str, keep: int) -> int:
    old = [b for b in list_backups() if b['kind'] == kind][keep:]
    for backup in old:
        try:
            os.remove(os.path.join(BACKUP_DIR, backup['name']))
        except OSError:
            pass
    return len(old)


# ---------------------------------------------------------------------------
# Settings and the daily backup
# ---------------------------------------------------------------------------

def get_settings() -> dict:
    from utils.db_utils import get_setting
    try:
        keep = int(get_setting(KEEP_KEY) or DEFAULT_KEEP)
    except ValueError:
        keep = DEFAULT_KEEP
    return {'enabled': (get_setting(ENABLED_KEY) or '1') == '1',
            'keep': keep if MIN_KEEP <= keep <= MAX_KEEP else DEFAULT_KEEP,
            'last': get_setting(LAST_KEY)}


def save_settings(form) -> List[str]:
    """Validate and store the Settings > Backup form. Returns errors (nothing stored if any)."""
    from utils.db_utils import set_setting
    try:
        keep = int((form.get('backup_keep') or '').strip())
    except ValueError:
        return ['Backups to keep: must be a whole number']
    if not MIN_KEEP <= keep <= MAX_KEEP:
        return [f'Backups to keep: must be between {MIN_KEEP} and {MAX_KEEP}']
    set_setting(ENABLED_KEY, '1' if form.get('backup_enabled') else '0')
    set_setting(KEEP_KEY, str(keep))
    return []


def run_daily() -> dict:
    """Daily snapshot (maintenance check). Returns {'created': path | None, 'skipped': reason | None}."""
    from utils.db_utils import set_setting
    settings = get_settings()
    if not settings['enabled']:
        return {'created': None, 'skipped': 'disabled'}
    if settings['last']:
        try:
            if utc_now() - parse_utc(settings['last']) < DAILY_INTERVAL:
                return {'created': None, 'skipped': 'recent'}
        except ValueError:
            pass
    path = create_backup('daily')
    set_setting(LAST_KEY, utc_now_str())
    return {'created': path, 'skipped': None}


# ---------------------------------------------------------------------------
# Before upgrades
# ---------------------------------------------------------------------------

def schema_signature() -> str:
    """Changes whenever the database setup and migrations change."""
    with open(INITDB_FILE, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def _stored_signature(path: str) -> Optional[str]:
    conn = sqlite3.connect(path, timeout=30)
    try:
        row = conn.execute('SELECT value FROM settings WHERE key = ?', (SCHEMA_KEY,)).fetchone()
        return row[0] if row else ''
    except sqlite3.OperationalError:
        return ''          # no settings table: a very old database
    finally:
        conn.close()


def backup_before_upgrade() -> Optional[str]:
    """Snapshot an existing database before migrations it has not seen run (run.py)."""
    path = _db_path()
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    if _stored_signature(path) == schema_signature():
        return None
    return create_backup('pre-upgrade')


def record_schema_signature() -> None:
    from utils.db_utils import set_setting
    set_setting(SCHEMA_KEY, schema_signature())


# ---------------------------------------------------------------------------
# Download archive
# ---------------------------------------------------------------------------

def _env_file() -> str:
    from utils import env_manager
    return str(env_manager.ENV_FILE)


def build_archive(include_screenshots: bool = False, include_env: bool = False) -> str:
    """Zip for download: database snapshot, manifest, optionally screenshots and .env. Caller deletes it."""
    from utils.screenshots import SCREENSHOT_DIR

    workdir = tempfile.mkdtemp(prefix='lazyeasm-backup-')
    try:
        db_copy = snapshot(os.path.join(workdir, 'lazyeasm.db'))
        fd, archive = tempfile.mkstemp(prefix='lazyeasm-backup-', suffix='.zip')
        os.close(fd)
        contents = ['lazyeasm.db']
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(db_copy, 'lazyeasm.db')
            if include_screenshots and os.path.isdir(SCREENSHOT_DIR):
                for name in sorted(os.listdir(SCREENSHOT_DIR)):
                    if SCREENSHOT_NAME.match(name):
                        zf.write(os.path.join(SCREENSHOT_DIR, name), f'screenshots/{name}', zipfile.ZIP_STORED)
                contents.append('screenshots/')
            if include_env and os.path.exists(_env_file()):
                zf.write(_env_file(), '.env')
                contents.append('.env')
            zf.writestr('manifest.json', json.dumps({'created_at': utc_now_str(), 'contents': contents,
                                                     'schema_signature': schema_signature()}, indent=1))
        os.chmod(archive, 0o600)
        return archive
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Restore (command line, LazyEASM stopped)
# ---------------------------------------------------------------------------

def validate_database(path: str) -> None:
    try:
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        try:
            if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise BackupError('the database in the backup is damaged')
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        raise BackupError(f'not a LazyEASM database: {e}') from e
    missing = REQUIRED_TABLES - tables
    if missing:
        raise BackupError(f"not a LazyEASM database (missing tables: {', '.join(sorted(missing))})")


def _is_running() -> bool:
    try:
        from utils.worker_runtime import get_worker_status
        return get_worker_status()['alive']
    except Exception:
        return False


def restore(source: str, with_env: bool = False, force: bool = False) -> dict:
    """
    Replace the database with a backup (.db snapshot or downloaded .zip). The
    current database is kept as a 'pre-restore' backup first.

    Returns:
        {'database': True, 'screenshots': int, 'env': bool, 'previous': path | None}
    """
    from utils.screenshots import SCREENSHOT_DIR

    if _is_running() and not force:
        raise BackupError('LazyEASM is running; stop it first (or pass --force)')
    if not os.path.exists(source):
        raise BackupError(f'{source} not found')

    workdir = tempfile.mkdtemp(prefix='lazyeasm-restore-')
    try:
        result = {'database': False, 'screenshots': 0, 'env': False, 'previous': None}
        archive = zipfile.ZipFile(source) if zipfile.is_zipfile(source) else None
        candidate = os.path.join(workdir, 'lazyeasm.db')
        if archive:
            if 'lazyeasm.db' not in archive.namelist():
                raise BackupError('the archive has no lazyeasm.db')
            with archive.open('lazyeasm.db') as src, open(candidate, 'wb') as dst:
                shutil.copyfileobj(src, dst)
        else:
            shutil.copyfile(source, candidate)
        validate_database(candidate)

        target = _db_path()
        if os.path.exists(target):
            result['previous'] = create_backup('pre-restore')
        for suffix in ('-wal', '-shm'):
            if os.path.exists(target + suffix):
                os.remove(target + suffix)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(candidate, target + '.restoring')
        os.chmod(target + '.restoring', 0o600)
        os.replace(target + '.restoring', target)
        result['database'] = True

        if archive:
            # only known file names: a crafted archive cannot write elsewhere
            for member in archive.namelist():
                name = member[len('screenshots/'):] if member.startswith('screenshots/') else None
                if name and SCREENSHOT_NAME.match(name):
                    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
                    with archive.open(member) as src, open(os.path.join(SCREENSHOT_DIR, name), 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                    result['screenshots'] += 1
            if with_env and '.env' in archive.namelist():
                env_file = _env_file()
                if os.path.exists(env_file):
                    shutil.copyfile(env_file, env_file + '.pre-restore')
                with archive.open('.env') as src, open(env_file, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(env_file, 0o600)
                result['env'] = True
            archive.close()
        return result
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description='LazyEASM backups')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help='local backups in db/backups/')
    sub.add_parser('create', help='make a backup now')
    restore_cmd = sub.add_parser('restore', help='replace the database with a backup (stop LazyEASM first)')
    restore_cmd.add_argument('file', help='a db/backups/*.db snapshot or a downloaded .zip')
    restore_cmd.add_argument('--with-env', action='store_true', help='also restore .env from a .zip that has one')
    restore_cmd.add_argument('--force', action='store_true', help='restore even if LazyEASM looks running')
    args = parser.parse_args()

    try:
        if args.command == 'list':
            for b in list_backups():
                print(f"{b['created_at']} UTC  {b['kind']:<12} {b['size'] / 1024 / 1024:7.1f} MB  {b['name']}")
        elif args.command == 'create':
            print(create_backup('manual'))
        else:
            result = restore(args.file, with_env=args.with_env, force=args.force)
            print('Database restored.' + (f" {result['screenshots']} screenshots restored." if result['screenshots'] else '')
                  + (' .env restored (previous one kept as .env.pre-restore).' if result['env'] else ''))
            if result['previous']:
                print(f"The database it replaced was saved as {result['previous']}.")
            print('Start LazyEASM again.')
    except BackupError as e:
        print(f'Error: {e}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
