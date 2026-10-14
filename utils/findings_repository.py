"""Cross-asset findings (CVEs and security findings) for triage and the overview.

CVEs are grouped per host and CVE, the same way the asset page shows them, so
one row here is one decision: fix it, accept it or mark it a false positive.

Rows are ordered by urgency:
    CVEs: P1 known exploited, P2 likely exploited (EPSS), P3 CVSS >= 7, P4 rest
    Security findings: critical -> 1, high -> 2, medium -> 3, low/info -> 4
"""

import json
import math
from datetime import datetime, timedelta
from typing import Optional

from utils.db_utils import VULN_STATUSES, get_db_connection
from utils.threat_intel import CVSS_HIGH, EPSS_HIGH
from utils.timeutil import utc_ago

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
KINDS = ('cve', 'finding')
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info', 'unknown')
SORTS = {
    'urgency': 'urgency ASC, severity_rank ASC, COALESCE(epss, 0) DESC, COALESCE(cvss, 0) DESC, host ASC',
    'newest': 'first_seen DESC, urgency ASC, host ASC',
    'last_seen': 'last_seen DESC, urgency ASC, host ASC',
    'host': 'host ASC, urgency ASC, identifier ASC',
}

ISSUES_CTE = f"""
WITH cve_issues AS (
    SELECT 'cve' AS kind, MIN(v.vuln_id) AS id, h.host AS host, v.cve_id AS identifier,
           v.cve_id || ' in ' || GROUP_CONCAT(DISTINCT t.tech_name || COALESCE(' ' || NULLIF(t.tech_version, ''), '')) AS title,
           MAX(v.cve_score) AS cvss, MAX(ci.epss) AS epss, MAX(COALESCE(ci.in_kev, 0)) AS in_kev,
           MAX(ci.kev_due_date) AS kev_due_date,
           CASE WHEN SUM(v.status = 'open') > 0 THEN 'open' ELSE MAX(v.status) END AS status,
           MAX(v.status_note) AS status_note,
           MIN(v.first_seen) AS first_seen, MAX(v.last_seen) AS last_seen,
           GROUP_CONCAT(DISTINCT h.port_num) AS ports, NULL AS evidence
    FROM vulnerabilities v
    JOIN technologies t ON t.tech_id = v.tech_id
    JOIN http_services h ON h.http_id = t.http_id
    LEFT JOIN cve_intel ci ON ci.cve_id = v.cve_id
    GROUP BY h.host, v.cve_id
),
issues_raw AS (
    SELECT kind, id, host, identifier, title, cvss, epss, in_kev, kev_due_date, status, status_note,
           first_seen, last_seen, ports, evidence,
           CASE WHEN cvss IS NULL THEN 'unknown' WHEN cvss >= 9 THEN 'critical' WHEN cvss >= 7 THEN 'high'
                WHEN cvss >= 4 THEN 'medium' ELSE 'low' END AS severity,
           CASE WHEN in_kev = 1 THEN 1 WHEN epss >= {EPSS_HIGH} THEN 2 WHEN cvss >= {CVSS_HIGH} THEN 3 ELSE 4 END AS urgency
    FROM cve_issues
    UNION ALL
    SELECT 'finding', finding_id, host, finding_type, title, NULL, NULL, 0, NULL, status, status_note,
           first_seen, last_seen, NULL, evidence, LOWER(severity),
           CASE LOWER(severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
    FROM findings
),
issues AS (
    SELECT r.*,
           CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                           WHEN 'low' THEN 3 ELSE 4 END AS severity_rank,
           CASE WHEN s.sub_id IS NOT NULL THEN 'subdomain' WHEN d.dom_id IS NOT NULL THEN 'domain'
                WHEN i.ip_id IS NOT NULL THEN 'ip' END AS asset_type,
           COALESCE(s.sub_id, d.dom_id, i.ip_id) AS asset_id
    FROM issues_raw r
    LEFT JOIN subdomain_asset s ON s.subdomain_name = r.host
    LEFT JOIN domain_asset d ON d.domain_name = r.host
    LEFT JOIN ip_asset i ON i.ip_value = r.host
)
"""


class FindingQueryError(ValueError):
    """Raised when a findings query contains an unsupported value."""


def _page_number(value, default: int, field: str) -> int:
    if value in (None, ''):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise FindingQueryError(f"{field} must be an integer") from exc
    if number < 1:
        raise FindingQueryError(f"{field} must be at least 1")
    return number


def _serialize(row: dict) -> dict:
    row['in_kev'] = bool(row['in_kev'])
    row['priority'] = f"P{row['urgency']}" if row['kind'] == 'cve' else None
    try:
        evidence = json.loads(row['evidence'] or '{}')
    except ValueError:
        evidence = {}
    row['detail'] = evidence.get('detail') or ''
    row['evidence'] = None
    row['ports'] = sorted({int(p) for p in (row['ports'] or '').split(',') if p.strip().isdigit()}
                          | ({int(evidence['port'])} if str(evidence.get('port', '')).isdigit() else set()))
    row.pop('severity_rank', None)
    return row


def list_findings(*, page=1, page_size=DEFAULT_PAGE_SIZE, query: Optional[str] = None,
                  kind: Optional[str] = None, severity: Optional[str] = None,
                  status: Optional[str] = 'open', kev_only=False, identifier: Optional[str] = None,
                  host: Optional[str] = None, sort: str = 'urgency') -> dict:
    """
    One page of findings across all assets.

    status: open (default), fixed, accepted, false_positive, or 'all'
    """
    page = _page_number(page, 1, 'page')
    page_size = min(_page_number(page_size, DEFAULT_PAGE_SIZE, 'page_size'), MAX_PAGE_SIZE)
    if kind and kind not in KINDS:
        raise FindingQueryError(f"kind must be one of: {', '.join(KINDS)}")
    if severity and severity not in SEVERITIES:
        raise FindingQueryError(f"severity must be one of: {', '.join(SEVERITIES)}")
    status = status or 'open'
    if status != 'all' and status not in VULN_STATUSES:
        raise FindingQueryError(f"status must be one of: all, {', '.join(VULN_STATUSES)}")
    sort = sort or 'urgency'
    if sort not in SORTS:
        raise FindingQueryError(f"sort must be one of: {', '.join(SORTS)}")

    where, params = [], []
    if status != 'all':
        where.append('status = ?')
        params.append(status)
    if kind:
        where.append('kind = ?')
        params.append(kind)
    if severity:
        where.append('severity = ?')
        params.append(severity)
    if str(kev_only).lower() in ('1', 'true', 'yes'):
        where.append('in_kev = 1')
    if identifier:
        where.append('identifier = ?')
        params.append(identifier.strip())
    if host:
        where.append('host = ?')
        params.append(host.strip().lower())
    if query and query.strip():
        pattern = f"%{query.strip().lower()}%"
        where.append('(LOWER(host) LIKE ? OR LOWER(identifier) LIKE ? OR LOWER(title) LIKE ?)')
        params.extend([pattern, pattern, pattern])
    where_sql = f"WHERE {' AND '.join(where)}" if where else ''

    conn = get_db_connection()
    try:
        total = conn.execute(f"{ISSUES_CTE} SELECT COUNT(*) FROM issues {where_sql}", params).fetchone()[0]
        rows = conn.execute(
            f"{ISSUES_CTE} SELECT * FROM issues {where_sql} ORDER BY {SORTS[sort]}, kind ASC, id ASC LIMIT ? OFFSET ?",
            [*params, page_size, (page - 1) * page_size],
        ).fetchall()
        items = [_serialize(dict(row)) for row in rows]
    finally:
        conn.close()

    total_pages = math.ceil(total / page_size) if total else 0
    return {
        'items': items,
        'pagination': {
            'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages,
            'has_next': page < total_pages, 'has_previous': page > 1 and total_pages > 0,
        },
    }


def get_overview(top: int = 5) -> dict:
    """Headline numbers, riskiest assets and most widespread open issues."""
    from utils.asset_repository import ASSET_CTES

    week_ago = utc_ago(days=7)
    conn = get_db_connection()
    try:
        severity = {sev: 0 for sev in ('critical', 'high', 'medium', 'low')}
        for row in conn.execute(f"{ISSUES_CTE} SELECT severity, COUNT(*) FROM issues WHERE status = 'open' GROUP BY severity"):
            key = row[0] if row[0] in severity else 'low'
            severity[key] += row[1]

        issues = conn.execute(f'''{ISSUES_CTE}
            SELECT COUNT(*) AS open_total,
                   COALESCE(SUM(in_kev = 1), 0) AS kev,
                   COUNT(DISTINCT CASE WHEN in_kev = 1 THEN host END) AS kev_hosts,
                   COALESCE(SUM(urgency = 1), 0) AS urgent,
                   COALESCE(SUM(first_seen >= ?), 0) AS new_this_week
            FROM issues WHERE status = 'open'
        ''', (week_ago,)).fetchone()

        assets = conn.execute(f'''{ASSET_CTES}
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(status = 'up'), 0) AS up,
                   COALESCE(SUM(status = 'down'), 0) AS down,
                   COALESCE(SUM(first_seen >= ?), 0) AS new_this_week,
                   COALESCE(SUM(certificate_state = 'expired'), 0) AS certs_expired,
                   COALESCE(SUM(certificate_state = 'expiring'), 0) AS certs_expiring
            FROM enriched
        ''', (week_ago,)).fetchone()

        riskiest = [dict(row) for row in conn.execute(f'''{ASSET_CTES}
            SELECT type, id, name, status, kev_count, max_cvss, finding_count, max_finding_severity,
                   vulnerability_count, screenshot_id
            FROM enriched
            WHERE vulnerability_count > 0 OR finding_count > 0
            ORDER BY kev_count DESC, max_cvss DESC, finding_count DESC, name ASC
            LIMIT ?
        ''', (top,))]

        widespread = [dict(row) for row in conn.execute(f'''{ISSUES_CTE}
            SELECT kind, identifier, MIN(title) AS title, MIN(urgency) AS urgency, MIN(severity_rank) AS severity_rank,
                   MAX(in_kev) AS in_kev, COUNT(DISTINCT host) AS host_count
            FROM issues WHERE status = 'open'
            GROUP BY kind, identifier
            ORDER BY urgency ASC, host_count DESC, severity_rank ASC, identifier ASC
            LIMIT ?
        ''', (top,))]
        changes_this_week = conn.execute('SELECT COUNT(*) FROM asset_changes WHERE detected_at >= ?',
                                         (week_ago,)).fetchone()[0]
    finally:
        conn.close()

    for item in widespread:
        item['in_kev'] = bool(item['in_kev'])
        item['priority'] = f"P{item['urgency']}" if item['kind'] == 'cve' else None
        rank = item.pop('severity_rank')
        item['severity'] = SEVERITIES[rank] if rank < 4 else 'info'
        if item['kind'] == 'cve':
            item['title'] = item['identifier']

    return {
        'issues': {**dict(issues), 'by_severity': severity},
        'assets': dict(assets),
        'changes_this_week': changes_this_week,
        'riskiest_assets': riskiest,
        'widespread_issues': widespread,
    }
