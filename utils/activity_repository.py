"""Paginated change history and scan queue for the Changes and Scans pages."""

import json
import math
from datetime import datetime, timedelta
from typing import Optional

from utils.db_utils import get_db_connection
from utils.timeutil import utc_now

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

CHANGE_CATEGORIES = {
    'assets': ('asset_added', 'asset_up', 'asset_down'),
    'ports': ('port_opened', 'port_closed'),
    'technologies': ('tech_added', 'tech_removed', 'tech_version_changed'),
    'certificates': ('certificate_changed',),
    'vulnerabilities': ('vulnerability_found', 'vulnerability_reopened', 'vulnerability_fixed', 'vulnerability_closed',
                        'finding_opened', 'finding_reopened', 'finding_fixed'),
    'appearance': ('appearance_changed',),
    'triage': ('status_changed',),
}
PERIODS = {'24h': timedelta(hours=24), '7d': timedelta(days=7), '30d': timedelta(days=30)}

# scan_queue.scan_type values, grouped the way the Scans page shows them
SCAN_KINDS = {
    'discovery': ('input_discovery', 'phase0_discovery'),
    'scan': ('phase1',),
    'deep_scan': ('phase2_deep_scan',),
    'monitor': ('monitor_run',),
}
KIND_OF_TYPE = {scan_type: kind for kind, types in SCAN_KINDS.items() for scan_type in types}
# phase1 uses 'running', the other queues 'processing'
SCAN_STATUSES = {'pending': ('pending',), 'running': ('running', 'processing'),
                 'completed': ('completed',), 'failed': ('failed',), 'cancelled': ('cancelled',)}

# Resolves a hostname or IP to its asset page
ASSET_LOOKUP = """
    LEFT JOIN subdomain_asset s ON s.subdomain_name = {col}
    LEFT JOIN domain_asset d ON d.domain_name = {col}
    LEFT JOIN ip_asset i ON i.ip_value = {col}
"""
ASSET_COLUMNS = """
    CASE WHEN s.sub_id IS NOT NULL THEN 'subdomain' WHEN d.dom_id IS NOT NULL THEN 'domain'
         WHEN i.ip_id IS NOT NULL THEN 'ip' END AS asset_type,
    COALESCE(s.sub_id, d.dom_id, i.ip_id) AS asset_id
"""


class ActivityQueryError(ValueError):
    """Raised when a Changes or Scans query contains an unsupported value."""


def _page_number(value, default: int, field: str) -> int:
    if value in (None, ''):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ActivityQueryError(f"{field} must be an integer") from exc
    if number < 1:
        raise ActivityQueryError(f"{field} must be at least 1")
    return number


def _pagination(page: int, page_size: int, total: int) -> dict:
    total_pages = math.ceil(total / page_size) if total else 0
    return {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages,
            'has_next': page < total_pages, 'has_previous': page > 1 and total_pages > 0}


def list_changes(*, page=1, page_size=DEFAULT_PAGE_SIZE, query: Optional[str] = None,
                 host: Optional[str] = None, category: Optional[str] = None,
                 period: Optional[str] = None) -> dict:
    """
    One page of the change history, newest first.

    category: one of CHANGE_CATEGORIES; period: 24h, 7d or 30d (default: all)
    """
    page = _page_number(page, 1, 'page')
    page_size = min(_page_number(page_size, DEFAULT_PAGE_SIZE, 'page_size'), MAX_PAGE_SIZE)
    if category and category not in CHANGE_CATEGORIES:
        raise ActivityQueryError(f"category must be one of: {', '.join(CHANGE_CATEGORIES)}")
    if period and period not in PERIODS:
        raise ActivityQueryError(f"period must be one of: {', '.join(PERIODS)}")

    where, params = [], []
    if category:
        types = CHANGE_CATEGORIES[category]
        where.append(f"c.change_type IN ({','.join('?' * len(types))})")
        params.extend(types)
    if period:
        where.append('c.detected_at >= ?')
        params.append((utc_now() - PERIODS[period]).strftime('%Y-%m-%d %H:%M:%S'))
    if host:
        where.append('c.host = ?')
        params.append(host.strip().lower())
    if query and query.strip():
        pattern = f"%{query.strip().lower()}%"
        where.append('(LOWER(c.host) LIKE ? OR LOWER(c.summary) LIKE ?)')
        params.extend([pattern, pattern])
    where_sql = f"WHERE {' AND '.join(where)}" if where else ''

    conn = get_db_connection()
    try:
        total = conn.execute(f'SELECT COUNT(*) FROM asset_changes c {where_sql}', params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT c.change_id, c.host, c.change_type, c.summary, c.details, c.detected_at, {ASSET_COLUMNS}
            FROM asset_changes c {ASSET_LOOKUP.format(col='c.host')}
            {where_sql}
            ORDER BY c.detected_at DESC, c.change_id DESC LIMIT ? OFFSET ?
        ''', [*params, page_size, (page - 1) * page_size]).fetchall()
    finally:
        conn.close()

    items = []
    for row in rows:
        item = dict(row)
        try:
            item['details'] = json.loads(item['details']) if item['details'] else {}
        except ValueError:
            item['details'] = {}
        items.append(item)
    return {'items': items, 'pagination': _pagination(page, page_size, total)}


def _scan_target(scan_type: str, target: str) -> str:
    """Readable target: input discovery rows store the parsed input as JSON."""
    if scan_type != 'input_discovery':
        return target
    try:
        payload = json.loads(target)
    except ValueError:
        return target
    names = [name for values in payload.values() if isinstance(values, list) for name in values]
    if not names:
        return 'input'
    return ', '.join(map(str, names[:3])) + (f" (+{len(names) - 3} more)" if len(names) > 3 else '')


def _duration(started_at: Optional[str], completed_at: Optional[str]) -> Optional[str]:
    """'1h 4m', '3m 12s' or '8s' between two 'YYYY-MM-DD HH:MM:SS' timestamps."""
    parse = lambda value: datetime.strptime(value[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S')
    try:
        seconds = int((parse(completed_at) - parse(started_at)).total_seconds())
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m {secs}s" if minutes else f"{secs}s"


def list_scans(*, page=1, page_size=DEFAULT_PAGE_SIZE, kind: Optional[str] = None,
               status: Optional[str] = None, query: Optional[str] = None) -> dict:
    """One page of the scan queue (every queue), active items first, then newest."""
    page = _page_number(page, 1, 'page')
    page_size = min(_page_number(page_size, DEFAULT_PAGE_SIZE, 'page_size'), MAX_PAGE_SIZE)
    if kind and kind not in SCAN_KINDS:
        raise ActivityQueryError(f"kind must be one of: {', '.join(SCAN_KINDS)}")
    if status and status not in SCAN_STATUSES:
        raise ActivityQueryError(f"status must be one of: {', '.join(SCAN_STATUSES)}")

    where, params = [], []
    if kind:
        types = SCAN_KINDS[kind]
        where.append(f"q.scan_type IN ({','.join('?' * len(types))})")
        params.extend(types)
    if status:
        statuses = SCAN_STATUSES[status]
        where.append(f"q.status IN ({','.join('?' * len(statuses))})")
        params.extend(statuses)
    if query and query.strip():
        where.append('LOWER(q.target) LIKE ?')
        params.append(f"%{query.strip().lower()}%")
    where_sql = f"WHERE {' AND '.join(where)}" if where else ''

    conn = get_db_connection()
    try:
        total = conn.execute(f'SELECT COUNT(*) FROM scan_queue q {where_sql}', params).fetchone()[0]
        counts = {row[0]: row[1] for row in conn.execute(
            "SELECT status, COUNT(*) FROM scan_queue WHERE status IN ('pending', 'running', 'processing') GROUP BY status")}
        rows = conn.execute(f'''
            SELECT q.queue_id, q.scan_type, q.cycle, q.target, q.status, q.queued_at, q.started_at, q.completed_at,
                   q.ports_found, q.tech_found, q.cve_found, q.dirs_found, q.error_message, {ASSET_COLUMNS}
            FROM scan_queue q {ASSET_LOOKUP.format(col='q.target')}
            {where_sql}
            ORDER BY CASE WHEN q.status IN ('running', 'processing') THEN 0 WHEN q.status = 'pending' THEN 1 ELSE 2 END,
                     CASE WHEN q.status IN ('pending', 'running', 'processing') THEN q.queued_at END ASC,
                     COALESCE(q.completed_at, q.started_at, q.queued_at) DESC, q.queue_id DESC
            LIMIT ? OFFSET ?
        ''', [*params, page_size, (page - 1) * page_size]).fetchall()
    finally:
        conn.close()

    items = []
    for row in rows:
        item = dict(row)
        item['kind'] = KIND_OF_TYPE.get(item['scan_type'], item['scan_type'])
        item['status'] = 'running' if item['status'] == 'processing' else item['status']
        item['target'] = _scan_target(item['scan_type'], item['target'])
        item['duration'] = _duration(item['started_at'], item['completed_at'])
        items.append(item)
    return {
        'items': items,
        'pagination': _pagination(page, page_size, total),
        'active': {'pending': counts.get('pending', 0),
                   'running': counts.get('running', 0) + counts.get('processing', 0)},
    }
