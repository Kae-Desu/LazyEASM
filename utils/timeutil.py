"""
Timestamps: stored in UTC everywhere as 'YYYY-MM-DD HH:MM:SS' (the format
SQLite's CURRENT_TIMESTAMP and julianday('now') use), shown in the viewer's
local time by the browser (static/js/app.js, the `localtime` template filter).
"""

from datetime import datetime, timedelta, timezone

FORMAT = '%Y-%m-%d %H:%M:%S'


def utc_now() -> datetime:
    """Current UTC time as a naive datetime, comparable with stored timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_now_str() -> str:
    return utc_now().strftime(FORMAT)


def utc_ago(**delta) -> str:
    """UTC timestamp `delta` ago, e.g. utc_ago(days=7), for 'newer than' queries."""
    return (utc_now() - timedelta(**delta)).strftime(FORMAT)


def utc_in(**delta) -> str:
    """UTC timestamp `delta` from now."""
    return (utc_now() + timedelta(**delta)).strftime(FORMAT)


def parse_utc(value: str) -> datetime:
    """Stored timestamp ('YYYY-MM-DD HH:MM:SS', optionally with 'T') as a naive UTC datetime."""
    return datetime.strptime(value[:19].replace('T', ' '), FORMAT)
