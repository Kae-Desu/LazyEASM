"""
Admin account: hashed password in the database.

The password is never stored in plain text. On first start there is no
account: LazyEASM prints a one-time setup code, and the account is created in
the browser (/setup) by someone who has that code, so whoever reaches a fresh
install first cannot claim it. ADMIN_PASS=... in .env still works (scripted
installs, and to reset a lost password): on startup it is hashed into the
admin_user table and removed from .env.

Every login token carries the account's token_version. Changing the
password (or detecting refresh-token reuse) bumps the version, which
invalidates every token issued before.
"""

import hmac
import logging
import os
import re
import secrets
from datetime import datetime
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

DEFAULT_USERNAME = 'lazymin'
MIN_PASSWORD_LENGTH = 12
USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9._@-]{1,64}$')

# Setup code: 3 groups of 4 characters without look-alikes (0/O, 1/I), ~60 bits
SETUP_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
SETUP_CODE_FILE = 'setup_code'

# Compared against when no account exists, so a failed login takes the same
# time whether or not the username is right
_DUMMY_HASH = generate_password_hash('lazyeasm-timing-equalizer')


def _db():
    from utils.db_utils import get_db_connection
    return get_db_connection()


def get_admin() -> Optional[dict]:
    """The admin account, or None if no password has been set yet."""
    import sqlite3
    conn = _db()
    try:
        row = conn.execute(
            'SELECT username, password_hash, token_version, password_changed_at FROM admin_user WHERE id = 1'
        ).fetchone()
        return dict(row) if row else None
    except sqlite3.OperationalError:
        return None  # database not initialized yet
    finally:
        conn.close()


def set_admin_password(username: str, password: str) -> int:
    """
    Store a new password hash (and username) and invalidate all sessions.

    Returns:
        the new token_version
    """
    now = utc_now_str()
    conn = _db()
    try:
        conn.execute('''
            INSERT INTO admin_user (id, username, password_hash, token_version, password_changed_at)
            VALUES (1, ?, ?, 1, ?)
            ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                password_hash = excluded.password_hash,
                token_version = admin_user.token_version + 1,
                password_changed_at = excluded.password_changed_at
        ''', (username, generate_password_hash(password), now))
        conn.commit()
        return conn.execute('SELECT token_version FROM admin_user WHERE id = 1').fetchone()[0]
    finally:
        conn.close()


def create_admin(username: str, password: str) -> bool:
    """Create the account if none exists yet; False if one already does."""
    import sqlite3
    conn = _db()
    try:
        conn.execute(
            'INSERT INTO admin_user (id, username, password_hash, token_version, password_changed_at) '
            'VALUES (1, ?, ?, 1, ?)', (username, generate_password_hash(password), utc_now_str()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# First-run setup in the browser
# ---------------------------------------------------------------------------

def _setup_code_path() -> str:
    from utils import db_utils
    return os.path.join(os.path.dirname(db_utils.DB_PATH), SETUP_CODE_FILE)


def _normalize_code(code: str) -> str:
    return ''.join(c for c in (code or '').upper() if c.isalnum())


def _read_setup_code() -> Optional[str]:
    try:
        with open(_setup_code_path(), encoding='utf-8') as f:
            code = f.read().strip()
    except OSError:
        return None
    return code if len(_normalize_code(code)) == 12 else None


def _remove_setup_code():
    try:
        os.remove(_setup_code_path())
    except FileNotFoundError:
        pass


def ensure_setup_code() -> Optional[str]:
    """
    The one-time setup code while no account exists, created if missing
    (file db/setup_code, mode 0600). None once an account exists.
    """
    if get_admin():
        _remove_setup_code()
        return None
    code = _read_setup_code()
    if code:
        return code
    code = '-'.join(''.join(secrets.choice(SETUP_CODE_ALPHABET) for _ in range(4)) for _ in range(3))
    path = _setup_code_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(code + '\n')
    os.replace(tmp, path)
    logger.warning(f"No account yet. Open LazyEASM in the browser and create it with the setup code {code}")
    return code


def setup_pending() -> bool:
    return get_admin() is None


def complete_setup(code: str, username: str, password: str, confirm: str) -> tuple:
    """
    Create the account from the setup page.

    Returns:
        (error message or None, whether the setup code was wrong)
    """
    if not setup_pending():
        return 'The account already exists. Sign in instead.', False
    expected = _read_setup_code()
    if not expected or not hmac.compare_digest(_normalize_code(expected).encode(),
                                               _normalize_code(code).encode()):
        return 'Wrong setup code. It is printed when LazyEASM starts (start output or service log).', True
    username = (username or '').strip()
    if not USERNAME_PATTERN.match(username):
        return 'Username: 1-64 letters, digits or . _ @ -', False
    if password != confirm:
        return 'The passwords do not match', False
    error = validate_new_password(password, username)
    if error:
        return error, False
    if not create_admin(username, password):
        return 'The account already exists. Sign in instead.', False
    _remove_setup_code()
    logger.info(f"Account {username} created in the browser; setup code removed")
    return None, False


def verify_login(username: str, password: str) -> Optional[dict]:
    """The admin account if the credentials match, else None (also when no account exists)."""
    admin = get_admin()
    if not admin or not password:
        check_password_hash(_DUMMY_HASH, password or '')
        return None
    name_ok = hmac.compare_digest(username.encode('utf-8'), admin['username'].encode('utf-8'))
    password_ok = check_password_hash(admin['password_hash'], password)
    return admin if name_ok and password_ok else None


def current_token_version() -> Optional[int]:
    """Version every valid token must carry; None when no account exists."""
    admin = get_admin()
    return admin['token_version'] if admin else None


def revoke_all_sessions() -> None:
    """Invalidate every issued token (password unchanged)."""
    conn = _db()
    try:
        conn.execute('UPDATE admin_user SET token_version = token_version + 1 WHERE id = 1')
        conn.commit()
    finally:
        conn.close()


def validate_new_password(password: str, username: str) -> Optional[str]:
    """Error message if the password is not acceptable, else None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f'Password must be at least {MIN_PASSWORD_LENGTH} characters'
    if password.strip().lower() == (username or '').strip().lower():
        return 'Password must not be the same as the username'
    if '\n' in password or '\r' in password:
        return 'Password must be a single line'
    return None


def bootstrap_admin_from_env() -> str:
    """
    Move ADMIN_PASS from .env into the database (hashed) and remove it from .env.

    Runs at startup. ADMIN_PASS in the .env file always wins, so it doubles
    as password recovery. ADMIN_PASS set only as a real environment variable
    cannot be removed, so it is used only when no account exists yet.

    Returns:
        'created' | 'reset' | 'unchanged' | 'missing'
    """
    from utils.env_manager import delete_env_key, read_env_file

    file_config = read_env_file()
    file_password = (file_config.get('ADMIN_PASS') or '').strip()
    admin = get_admin()
    # Without ADMIN_USER a reset keeps the username chosen at setup
    username = (file_config.get('ADMIN_USER') or os.environ.get('ADMIN_USER')
                or (admin or {}).get('username') or DEFAULT_USERNAME).strip()

    if file_password:
        if admin and admin['username'] == username and check_password_hash(admin['password_hash'], file_password):
            action = 'unchanged'
        else:
            set_admin_password(username, file_password)
            action = 'reset' if admin else 'created'
        if len(file_password) < MIN_PASSWORD_LENGTH:
            logger.warning(f"Admin password from .env is shorter than {MIN_PASSWORD_LENGTH} characters")
        if delete_env_key('ADMIN_PASS'):
            logger.info(f"Admin password {action}; stored hashed and removed from .env")
        else:
            logger.error("Admin password stored hashed, but ADMIN_PASS could not be removed from .env")
        return action

    env_password = (os.environ.get('ADMIN_PASS') or '').strip()
    if not admin and env_password:
        set_admin_password(username, env_password)
        logger.info("Admin account created from the ADMIN_PASS environment variable")
        return 'created'

    if not admin:
        logger.info("No account yet: it is created in the browser with the setup code (or ADMIN_PASS in .env)")
        return 'missing'
    return 'unchanged'
