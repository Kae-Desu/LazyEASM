"""Read-optimized asset queries for API and UI consumers.

The list query deliberately returns lightweight summaries. Expensive collections
such as technologies, ports, directories, and CVEs are loaded only by
``get_asset_detail`` for a single asset.
"""

import math
import os
from typing import Iterable, Optional

from utils.db_utils import (
    _get_cert_expiry,
    _get_cves_for_host,
    _get_cves_for_ip,
    _get_directories_for_host,
    _get_findings_for_host,
    _get_recent_changes_for_host,
    _get_ips_for_domain,
    _get_ips_for_subdomain,
    _get_ports_for_domain,
    _get_ports_for_ip,
    _get_ports_for_subdomain,
    _get_technologies_for_host,
    _get_technologies_for_ip,
    get_db_connection,
)


DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = max(1, int(os.getenv("ASSET_API_MAX_PAGE_SIZE", "100")))
VALID_TYPES = {"domain", "subdomain", "ip"}
VALID_CERT_STATES = {"none", "expired", "expiring", "valid"}
VALID_SCAN_STATES = {"scanned", "unscanned", "pending", "processing"}
SORT_COLUMNS = {
    "name": "name",
    "type": "type",
    "status": "status",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "last_scanned": "last_scanned",
    "max_cvss": "max_cvss",
    "max_epss": "max_epss",
    "kev_count": "kev_count",
    "finding_count": "finding_count",
}


class AssetQueryError(ValueError):
    """Raised when an asset query contains an unsupported value."""


def _positive_int(value, default: int, field: str) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise AssetQueryError(f"{field} must be an integer") from exc
    if parsed < 1:
        raise AssetQueryError(f"{field} must be at least 1")
    return parsed


def _optional_number(value, field: str) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise AssetQueryError(f"{field} must be a number") from exc


def _normalize_types(asset_types: Optional[Iterable[str]]) -> list[str]:
    if not asset_types:
        return []
    normalized = sorted({str(item).strip().lower() for item in asset_types if str(item).strip()})
    invalid = set(normalized) - VALID_TYPES
    if invalid:
        raise AssetQueryError(f"unsupported asset type: {', '.join(sorted(invalid))}")
    return normalized


ASSET_CTES = """
WITH asset_base AS (
    SELECT d.dom_id AS id, d.domain_name AS name, 'domain' AS type,
           d.domain_name AS root_domain, d.status, d.first_seen, d.last_seen,
           d.last_scanned, d.last_deep_scan, d.last_wappalyzer_scan
    FROM domain_asset d
    UNION ALL
    SELECT s.sub_id AS id, s.subdomain_name AS name, 'subdomain' AS type,
           d.domain_name AS root_domain, s.status, s.first_seen, s.last_seen,
           s.last_scanned, s.last_deep_scan, s.last_wappalyzer_scan
    FROM subdomain_asset s
    LEFT JOIN domain_asset d ON d.dom_id = s.dom_id
    UNION ALL
    SELECT i.ip_id AS id, i.ip_value AS name, 'ip' AS type,
           NULL AS root_domain, i.status, i.first_seen, i.last_seen,
           i.last_scanned, i.last_scanned AS last_deep_scan,
           i.last_scanned AS last_wappalyzer_scan
    FROM ip_asset i
    WHERE NOT EXISTS (SELECT 1 FROM domain_ip di WHERE di.ip_id = i.ip_id)
      AND NOT EXISTS (SELECT 1 FROM subdomain_ip si WHERE si.ip_id = i.ip_id)
),
asset_ips AS (
    SELECT 'domain' AS type, di.dom_id AS asset_id, i.ip_id, i.ip_value
    FROM domain_ip di JOIN ip_asset i ON i.ip_id = di.ip_id
    UNION ALL
    SELECT 'subdomain', si.sub_id, i.ip_id, i.ip_value
    FROM subdomain_ip si JOIN ip_asset i ON i.ip_id = si.ip_id
    UNION ALL
    SELECT 'ip', i.ip_id, i.ip_id, i.ip_value
    FROM ip_asset i
),
ip_rollup AS (
    SELECT type, asset_id, GROUP_CONCAT(DISTINCT ip_value) AS ips_csv,
           COUNT(DISTINCT ip_id) AS ip_count
    FROM asset_ips GROUP BY type, asset_id
),
port_rollup AS (
    SELECT ai.type, ai.asset_id, COUNT(DISTINCT p.port_num) AS open_port_count
    FROM asset_ips ai JOIN ports p ON p.ip_id = ai.ip_id
    GROUP BY ai.type, ai.asset_id
),
asset_services AS (
    SELECT DISTINCT a.type, a.id AS asset_id, h.http_id
    FROM asset_base a
    JOIN http_services h
      ON (a.type IN ('domain', 'subdomain') AND h.host = a.name)
      OR (a.type = 'ip' AND (h.ip_id = a.id OR h.host = a.name))
),
service_rollup AS (
    SELECT type, asset_id, COUNT(*) AS service_count
    FROM asset_services GROUP BY type, asset_id
),
tech_rollup AS (
    SELECT services.type, services.asset_id,
           COUNT(DISTINCT t.tech_id) AS technology_count
    FROM asset_services services
    JOIN technologies t ON t.http_id = services.http_id
    WHERE t.removed_at IS NULL
    GROUP BY services.type, services.asset_id
),
vuln_rollup AS (
    SELECT services.type, services.asset_id,
           COUNT(DISTINCT v.vuln_id) AS vulnerability_count,
           MAX(v.cve_score) AS max_cvss,
           MAX(ci.epss) AS max_epss,
           COUNT(DISTINCT CASE WHEN ci.in_kev = 1 THEN v.cve_id END) AS kev_count
    FROM asset_services services
    JOIN technologies t ON t.http_id = services.http_id
    JOIN vulnerabilities v ON v.tech_id = t.tech_id
    LEFT JOIN cve_intel ci ON ci.cve_id = v.cve_id
    WHERE v.status = 'open'
    GROUP BY services.type, services.asset_id
),
finding_rollup AS (
    SELECT host, COUNT(*) AS finding_count,
           MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                             WHEN 'low' THEN 1 ELSE 0 END) AS max_finding_severity
    FROM findings WHERE status = 'open'
    GROUP BY host
),
cert_rollup AS (
    SELECT hostname,
           MIN(CASE WHEN julianday(not_after) > julianday('now') THEN not_after END) AS active_not_after,
           MAX(not_after) AS latest_not_after
    FROM certificates
    WHERE hostname NOT LIKE '*.%'
    GROUP BY hostname
),
latest_phase2 AS (
    SELECT target, status
    FROM (
        SELECT target, status,
               ROW_NUMBER() OVER (PARTITION BY target ORDER BY queued_at DESC, queue_id DESC) AS row_num
        FROM scan_queue WHERE scan_type = 'phase2_deep_scan'
    ) ranked
    WHERE row_num = 1
),
enriched AS (
    SELECT a.*,
           COALESCE(ir.ips_csv, CASE WHEN a.type = 'ip' THEN a.name END) AS ips_csv,
           COALESCE(ir.ip_count, CASE WHEN a.type = 'ip' THEN 1 ELSE 0 END) AS ip_count,
           COALESCE(pr.open_port_count, 0) AS open_port_count,
           COALESCE(sr.service_count, 0) AS service_count,
           COALESCE(tr.technology_count, 0) AS technology_count,
           COALESCE(vr.vulnerability_count, 0) AS vulnerability_count,
           COALESCE(vr.max_cvss, 0) AS max_cvss,
           vr.max_epss AS max_epss,
           COALESCE(vr.kev_count, 0) AS kev_count,
           COALESCE(fr.finding_count, 0) AS finding_count,
           CASE fr.max_finding_severity WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium'
                                        WHEN 1 THEN 'low' END AS max_finding_severity,
           cr.active_not_after AS certificate_not_after,
           CASE
             WHEN cr.active_not_after IS NOT NULL
                  AND julianday(cr.active_not_after) <= julianday('now', '+30 days') THEN 'expiring'
             WHEN cr.active_not_after IS NOT NULL THEN 'valid'
             WHEN cr.latest_not_after IS NOT NULL THEN 'expired'
             ELSE 'none'
           END AS certificate_state,
           CASE WHEN cr.active_not_after IS NOT NULL
                THEN CAST(julianday(cr.active_not_after) - julianday('now') AS INTEGER)
           END AS certificate_days_remaining,
           CASE WHEN COALESCE(pr.open_port_count, 0) > 0 OR COALESCE(sr.service_count, 0) > 0
                THEN 1 ELSE 0 END AS is_scanned,
           lp.status AS phase2_status
    FROM asset_base a
    LEFT JOIN ip_rollup ir ON ir.type = a.type AND ir.asset_id = a.id
    LEFT JOIN port_rollup pr ON pr.type = a.type AND pr.asset_id = a.id
    LEFT JOIN service_rollup sr ON sr.type = a.type AND sr.asset_id = a.id
    LEFT JOIN tech_rollup tr ON tr.type = a.type AND tr.asset_id = a.id
    LEFT JOIN vuln_rollup vr ON vr.type = a.type AND vr.asset_id = a.id
    LEFT JOIN finding_rollup fr ON fr.host = a.name
    LEFT JOIN cert_rollup cr ON cr.hostname = a.name
    LEFT JOIN latest_phase2 lp ON lp.target = a.name
)
"""


def list_assets(
    *,
    page=1,
    page_size=DEFAULT_PAGE_SIZE,
    query: Optional[str] = None,
    asset_types: Optional[Iterable[str]] = None,
    status: Optional[str] = None,
    root_domain: Optional[str] = None,
    technology: Optional[str] = None,
    port=None,
    min_cvss=None,
    kev_only=False,
    cert_state: Optional[str] = None,
    scan_state: Optional[str] = None,
    sort: str = "name",
    order: str = "asc",
) -> dict:
    """Return one page of lightweight asset summaries."""
    page = _positive_int(page, 1, "page")
    page_size = min(_positive_int(page_size, DEFAULT_PAGE_SIZE, "page_size"), MAX_PAGE_SIZE)
    types = _normalize_types(asset_types)
    min_cvss = _optional_number(min_cvss, "min_cvss")

    parsed_port = None
    if port not in (None, ""):
        parsed_port = _positive_int(port, 0, "port")
        if parsed_port > 65535:
            raise AssetQueryError("port must be between 1 and 65535")

    sort = (sort or "name").lower()
    if sort not in SORT_COLUMNS:
        raise AssetQueryError(f"unsupported sort: {sort}")
    order = (order or "asc").lower()
    if order not in {"asc", "desc"}:
        raise AssetQueryError("order must be asc or desc")

    cert_state = cert_state.lower() if cert_state else None
    if cert_state and cert_state not in VALID_CERT_STATES:
        raise AssetQueryError(f"unsupported cert_state: {cert_state}")
    scan_state = scan_state.lower() if scan_state else None
    if scan_state and scan_state not in VALID_SCAN_STATES:
        raise AssetQueryError(f"unsupported scan_state: {scan_state}")

    where = []
    params = []
    if query and query.strip():
        pattern = f"%{query.strip().lower()}%"
        where.append("(LOWER(name) LIKE ? OR LOWER(COALESCE(root_domain, '')) LIKE ? OR LOWER(COALESCE(ips_csv, '')) LIKE ?)")
        params.extend([pattern, pattern, pattern])
    if types:
        where.append(f"type IN ({','.join('?' for _ in types)})")
        params.extend(types)
    if status:
        where.append("LOWER(status) = ?")
        params.append(status.strip().lower())
    if root_domain:
        where.append("LOWER(COALESCE(root_domain, '')) = ?")
        params.append(root_domain.strip().lower())
    if technology:
        where.append("EXISTS (SELECT 1 FROM asset_services services JOIN technologies t ON t.http_id = services.http_id WHERE services.type = enriched.type AND services.asset_id = enriched.id AND t.removed_at IS NULL AND LOWER(t.tech_name) LIKE ?)")
        params.append(f"%{technology.strip().lower()}%")
    if parsed_port is not None:
        where.append("(EXISTS (SELECT 1 FROM asset_ips ai JOIN ports p ON p.ip_id = ai.ip_id WHERE ai.type = enriched.type AND ai.asset_id = enriched.id AND p.port_num = ?) OR EXISTS (SELECT 1 FROM asset_services services JOIN http_services h ON h.http_id = services.http_id WHERE services.type = enriched.type AND services.asset_id = enriched.id AND h.port_num = ?))")
        params.extend([parsed_port, parsed_port])
    if min_cvss is not None:
        where.append("max_cvss >= ?")
        params.append(min_cvss)
    if str(kev_only).lower() in ("1", "true", "yes"):
        where.append("kev_count > 0")
    if cert_state:
        where.append("certificate_state = ?")
        params.append(cert_state)
    if scan_state == "scanned":
        where.append("is_scanned = 1")
    elif scan_state == "unscanned":
        where.append("is_scanned = 0")
    elif scan_state:
        where.append("phase2_status = ?")
        params.append(scan_state)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"{ASSET_CTES} SELECT COUNT(*) AS total FROM enriched {where_sql}", params)
        total = cursor.fetchone()["total"]

        offset = (page - 1) * page_size
        cursor.execute(
            f"{ASSET_CTES} SELECT * FROM enriched {where_sql} "
            f"ORDER BY {SORT_COLUMNS[sort]} {order.upper()}, type ASC, id ASC LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        )
        items = [_serialize_summary(dict(row)) for row in cursor.fetchall()]
    finally:
        conn.close()

    total_pages = math.ceil(total / page_size) if total else 0
    return {
        "items": items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1 and total_pages > 0,
        },
    }


def _serialize_summary(row: dict) -> dict:
    row["ips"] = sorted(filter(None, (row.pop("ips_csv", "") or "").split(",")))
    row["is_scanned"] = bool(row["is_scanned"])
    row["certificate"] = {
        "state": row.pop("certificate_state"),
        "not_after": row.pop("certificate_not_after"),
        "days_remaining": row.pop("certificate_days_remaining"),
    }
    return row


def export_assets() -> list:
    """Every asset summary (same fields as list_assets), for CSV/JSON export."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"{ASSET_CTES} SELECT * FROM enriched ORDER BY type ASC, name ASC")
        return [_serialize_summary(dict(row)) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_asset_detail(asset_type: str, asset_id: int) -> Optional[dict]:
    """Load the complete detail graph for one asset only."""
    asset_type = (asset_type or "").lower()
    if asset_type not in VALID_TYPES:
        raise AssetQueryError(f"unsupported asset type: {asset_type}")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if asset_type == "domain":
            cursor.execute("SELECT d.*, d.dom_id AS id, d.domain_name AS name, d.domain_name AS root_domain FROM domain_asset d WHERE d.dom_id = ?", (asset_id,))
        elif asset_type == "subdomain":
            cursor.execute("SELECT s.*, s.sub_id AS id, s.subdomain_name AS name, d.domain_name AS root_domain FROM subdomain_asset s LEFT JOIN domain_asset d ON d.dom_id = s.dom_id WHERE s.sub_id = ?", (asset_id,))
        else:
            cursor.execute("SELECT i.*, i.ip_id AS id, i.ip_value AS name, NULL AS root_domain FROM ip_asset i WHERE i.ip_id = ?", (asset_id,))

        row = cursor.fetchone()
        if not row:
            return None
        asset = dict(row)
        asset["type"] = asset_type

        if asset_type == "domain":
            asset["ips"] = _get_ips_for_domain(cursor, asset_id)
            asset["technologies"] = _get_technologies_for_host(cursor, asset["name"])
            asset["vulnerabilities"] = _get_cves_for_host(cursor, asset["name"])
            asset["ports"] = _get_ports_for_domain(cursor, asset_id)
        elif asset_type == "subdomain":
            asset["ips"] = _get_ips_for_subdomain(cursor, asset_id)
            asset["technologies"] = _get_technologies_for_host(cursor, asset["name"])
            asset["vulnerabilities"] = _get_cves_for_host(cursor, asset["name"])
            asset["ports"] = _get_ports_for_subdomain(cursor, asset_id)
        else:
            asset["ips"] = [asset["name"]]
            asset["technologies"] = _get_technologies_for_ip(cursor, asset_id)
            asset["vulnerabilities"] = _get_cves_for_ip(cursor, asset_id)
            asset["ports"] = _get_ports_for_ip(cursor, asset_id)

        asset["directories"] = _get_directories_for_host(cursor, asset["name"])
        asset["certificate"] = _get_cert_expiry(cursor, asset["name"])
        asset["security_findings"] = _get_findings_for_host(cursor, asset["name"])
        asset["history"] = _get_recent_changes_for_host(cursor, asset["name"], limit=200)
        row = cursor.execute(
            "SELECT status FROM scan_queue WHERE target = ? AND scan_type = 'phase2_deep_scan' "
            "ORDER BY queued_at DESC, queue_id DESC LIMIT 1", (asset["name"],)
        ).fetchone()
        asset["phase2_status"] = row["status"] if row else None
        return asset
    finally:
        conn.close()
