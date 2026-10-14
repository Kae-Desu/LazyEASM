"""
Module: db_utils.py
Purpose: Database utility functions for LazyEASM
Functions:
    - get_db_connection: Get database connection
    - domain_exists: Check if domain exists
    - subdomain_exists: Check if subdomain exists
    - ip_exists: Check if IP exists
    - upsert_domain: Insert or update domain
    - upsert_subdomain: Insert or update subdomain
    - upsert_ip: Insert or update IP
    - create_domain_resolution: Create domain-ip junction entries
    - create_subdomain_resolution: Create subdomain-ip junction entries
    - save_scan_hint: Save port/path hints
    - get_scan_hints: Retrieve saved hints
    - log_scan: Insert scan history entry
    - get_domain_by_name: Get domain by name
    - get_subdomain_by_name: Get subdomain by name
    - get_ip_by_value: Get IP by value
"""

import sqlite3
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from utils.timeutil import utc_ago, utc_in, utc_now, utc_now_str

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "lazyeasm.db")


def get_db_connection():
    """Get database connection with row factory."""
    # The web and worker processes share this file: wait for locks instead of
    # failing immediately (WAL mode is enabled once in InitDB.init_db)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def domain_exists(domain_name: str) -> bool:
    """Check if domain already exists in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT dom_id FROM domain_asset WHERE domain_name = ?", (domain_name,))
        result = cursor.fetchone()
        return result is not None
    finally:
        conn.close()


def subdomain_exists(subdomain_name: str) -> bool:
    """Check if subdomain already exists in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?", (subdomain_name,))
        result = cursor.fetchone()
        return result is not None
    finally:
        conn.close()


def ip_exists(ip_value: str) -> bool:
    """Check if IP already exists in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT ip_id FROM ip_asset WHERE ip_value = ?", (ip_value,))
        result = cursor.fetchone()
        return result is not None
    finally:
        conn.close()


# ============================================
# CHANGE HISTORY
# ============================================

def _now() -> str:
    return utc_now_str()


def _record_change(cursor, host: str, change_type: str, summary: str, details: dict = None) -> None:
    """
    Record a change inside the caller's transaction.

    change_type is one of: asset_added, asset_down, asset_up, port_opened,
    port_closed, tech_added, tech_removed, tech_version_changed,
    certificate_changed, vulnerability_found, vulnerability_reopened,
    vulnerability_fixed, vulnerability_closed, finding_opened,
    finding_reopened, finding_fixed, status_changed
    """
    if not host:
        return
    try:
        cursor.execute('''
            INSERT INTO asset_changes (host, change_type, summary, details, detected_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (host, change_type, summary, json.dumps(details, sort_keys=True) if details else None, _now()))
    except sqlite3.OperationalError as e:
        # Database not migrated yet; history is best-effort
        logger.debug(f"Change not recorded ({change_type} {host}): {e}")


def _record_status_change(cursor, host: str, old_status: str, new_status: str) -> None:
    if old_status and new_status and old_status != new_status:
        if new_status == 'down':
            _record_change(cursor, host, 'asset_down', 'Went down', {'old': old_status, 'new': new_status})
        elif new_status == 'up':
            _record_change(cursor, host, 'asset_up', 'Came back up', {'old': old_status, 'new': new_status})


def record_change(host: str, change_type: str, summary: str, details: dict = None) -> None:
    """Record a change in its own transaction."""
    conn = get_db_connection()
    try:
        _record_change(conn.cursor(), host, change_type, summary, details)
        conn.commit()
    finally:
        conn.close()


def get_changes(host: str = None, change_type: str = None, since: str = None,
                limit: int = 100, offset: int = 0) -> list:
    """Most recent changes first, optionally filtered."""
    where, params = [], []
    if host:
        where.append('host = ?')
        params.append(host)
    if change_type:
        where.append('change_type = ?')
        params.append(change_type)
    if since:
        where.append('detected_at >= ?')
        params.append(since)
    query = 'SELECT * FROM asset_changes'
    if where:
        query += ' WHERE ' + ' AND '.join(where)
    query += ' ORDER BY detected_at DESC, change_id DESC LIMIT ? OFFSET ?'
    conn = get_db_connection()
    try:
        rows = []
        for row in conn.execute(query, params + [limit, offset]):
            item = dict(row)
            item['details'] = json.loads(item['details']) if item['details'] else {}
            rows.append(item)
        return rows
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def prune_changes(days: int = 365) -> int:
    """Delete change history older than `days`."""
    cutoff = utc_ago(days=days)
    conn = get_db_connection()
    try:
        cursor = conn.execute('DELETE FROM asset_changes WHERE detected_at < ?', (cutoff,))
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def prune_scan_queue(days: int = 90) -> int:
    """Delete finished queue items (completed, failed, cancelled) older than `days`."""
    cutoff = utc_ago(days=days)
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            DELETE FROM scan_queue
            WHERE status IN ('completed', 'failed', 'cancelled')
              AND COALESCE(completed_at, started_at, queued_at) < ?
        ''', (cutoff,))
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def _host_for_tech(cursor, tech_id: int):
    row = cursor.execute('''
        SELECT h.host, t.tech_name, t.tech_version
        FROM technologies t INNER JOIN http_services h ON h.http_id = t.http_id
        WHERE t.tech_id = ?
    ''', (tech_id,)).fetchone()
    return row


def sync_technologies(http_id: int, host: str, detected) -> dict:
    """
    Store the technologies detected by a successful scan of one HTTP service.

    Technologies not detected any more are marked removed; changes against the
    previous scan are recorded (none on the first scan of a service).

    Args:
        detected: [(tech_name, tech_version or None), ...]

    Returns:
        {tech_name: tech_id}
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = _now()
        previous = cursor.execute('''
            SELECT tech_id, tech_name, tech_version FROM technologies
            WHERE http_id = ? AND removed_at IS NULL ORDER BY tech_id
        ''', (http_id,)).fetchall()

        ids = {}
        for name, version in detected:
            row = cursor.execute('''
                SELECT tech_id FROM technologies
                WHERE http_id = ? AND tech_name = ? AND (tech_version = ? OR (tech_version IS NULL AND ? IS NULL))
            ''', (http_id, name, version, version)).fetchone()
            if row:
                cursor.execute('UPDATE technologies SET removed_at = NULL WHERE tech_id = ?', (row['tech_id'],))
                ids[name] = row['tech_id']
            else:
                cursor.execute('''
                    INSERT INTO technologies (http_id, tech_name, tech_version, first_seen) VALUES (?, ?, ?, ?)
                ''', (http_id, name, version, now))
                ids[name] = cursor.lastrowid

        current_ids = set(ids.values())
        for row in previous:
            if row['tech_id'] not in current_ids:
                cursor.execute('UPDATE technologies SET removed_at = ? WHERE tech_id = ?', (now, row['tech_id']))

        if previous:
            before = {row['tech_name']: row['tech_version'] for row in previous}
            after = dict(detected)
            label = lambda n, v: f"{n} {v}" if v else n
            for name in sorted(after.keys() - before.keys()):
                _record_change(cursor, host, 'tech_added', f"{label(name, after[name])} detected",
                               {'tech': name, 'version': after[name], 'http_id': http_id})
            for name in sorted(before.keys() - after.keys()):
                _record_change(cursor, host, 'tech_removed', f"{label(name, before[name])} no longer detected",
                               {'tech': name, 'version': before[name], 'http_id': http_id})
            for name in sorted(before.keys() & after.keys()):
                if before[name] != after[name]:
                    _record_change(cursor, host, 'tech_version_changed',
                                   f"{name} changed from {before[name] or 'unknown'} to {after[name] or 'unknown'}",
                                   {'tech': name, 'old_version': before[name], 'new_version': after[name],
                                    'http_id': http_id})

        conn.commit()
        return ids
    finally:
        conn.close()


def upsert_domain(domain_name: str, is_wildcard: int = 0, wildcard_ip: str = None, status: str = 'up') -> int:
    """
    Insert new domain or update existing. Returns dom_id.
    
    Args:
        domain_name: Root domain (e.g., 'example.com')
        is_wildcard: 1 if wildcard DNS detected, 0 otherwise
        wildcard_ip: IP that wildcard resolves to
        status: 'up' or 'down'
    
    Returns:
        dom_id
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = utc_now_str()
        
        cursor.execute("SELECT dom_id, status FROM domain_asset WHERE domain_name = ?", (domain_name,))
        result = cursor.fetchone()
        
        if result:
            dom_id = result['dom_id']
            _record_status_change(cursor, domain_name, result['status'], status)
            cursor.execute('''
                UPDATE domain_asset 
                SET last_seen = ?, status = ?, is_wildcard = ?, wildcard_ip = ?
                WHERE dom_id = ?
            ''', (now, status, is_wildcard, wildcard_ip, dom_id))
            conn.commit()
            return dom_id
        else:
            cursor.execute('''
                INSERT INTO domain_asset (domain_name, first_seen, status, is_wildcard, wildcard_ip)
                VALUES (?, ?, ?, ?, ?)
            ''', (domain_name, now, status, is_wildcard, wildcard_ip))
            dom_id = cursor.lastrowid
            _record_change(cursor, domain_name, 'asset_added', 'New domain added', {'type': 'domain'})
            conn.commit()
            return dom_id
    finally:
        conn.close()


def add_container_domain(domain_name: str) -> int:
    """
    The parent of a subdomain submitted on its own: stored so the subdomain
    has a parent, but not expanded (no discovery, scans or monitoring of the
    domain itself). Returns dom_id; an existing domain is left as it is.
    """
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT dom_id FROM domain_asset WHERE domain_name = ?', (domain_name,)).fetchone()
        if row:
            return row['dom_id']
        cursor = conn.execute('''
            INSERT INTO domain_asset (domain_name, first_seen, status, expand) VALUES (?, ?, 'up', 0)
        ''', (domain_name, utc_now_str()))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def is_domain_expanded(domain_name: str) -> bool:
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT expand FROM domain_asset WHERE domain_name = ?', (domain_name,)).fetchone()
        return bool(row and row['expand'])
    finally:
        conn.close()


def set_domain_expanded(dom_id: int) -> None:
    conn = get_db_connection()
    try:
        conn.execute('UPDATE domain_asset SET expand = 1 WHERE dom_id = ?', (dom_id,))
        conn.commit()
    finally:
        conn.close()


def upsert_subdomain(subdomain_name: str, dom_id: int, status: str = 'up') -> int:
    """
    Insert new subdomain or update existing. Returns sub_id.
    
    Args:
        subdomain_name: Full subdomain (e.g., 'api.example.com')
        dom_id: Parent domain ID
        status: 'up' or 'down'
    
    Returns:
        sub_id
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = utc_now_str()
        
        cursor.execute("SELECT sub_id, status FROM subdomain_asset WHERE subdomain_name = ?", (subdomain_name,))
        result = cursor.fetchone()
        
        if result:
            sub_id = result['sub_id']
            _record_status_change(cursor, subdomain_name, result['status'], status)
            cursor.execute('''
                UPDATE subdomain_asset 
                SET last_seen = ?, status = ?
                WHERE sub_id = ?
            ''', (now, status, sub_id))
            conn.commit()
            return sub_id
        else:
            cursor.execute('''
                INSERT INTO subdomain_asset (subdomain_name, dom_id, first_seen, status)
                VALUES (?, ?, ?, ?)
            ''', (subdomain_name, dom_id, now, status))
            sub_id = cursor.lastrowid
            _record_change(cursor, subdomain_name, 'asset_added', 'New subdomain discovered', {'type': 'subdomain'})
            conn.commit()
            return sub_id
    finally:
        conn.close()


def upsert_ip(ip_value: str, is_private: int = 0, is_shared: int = 0, shared_provider: str = None, status: str = 'up') -> int:
    """
    Insert new IP or update existing. Returns ip_id.
    
    Args:
        ip_value: IP address (e.g., '1.2.3.4')
        is_private: 1 if private IP, 0 otherwise
        is_shared: 1 if shared hosting detected, 0 otherwise
        shared_provider: Hosting provider name
        status: 'up' or 'down'
    
    Returns:
        ip_id
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = utc_now_str()
        
        cursor.execute("SELECT ip_id, status FROM ip_asset WHERE ip_value = ?", (ip_value,))
        result = cursor.fetchone()
        
        if result:
            ip_id = result['ip_id']
            _record_status_change(cursor, ip_value, result['status'], status)
            cursor.execute('''
                UPDATE ip_asset 
                SET last_seen = ?, status = ?, is_shared = ?, shared_provider = ?
                WHERE ip_id = ?
            ''', (now, status, is_shared, shared_provider, ip_id))
            conn.commit()
            return ip_id
        else:
            cursor.execute('''
                INSERT INTO ip_asset (ip_value, is_private, is_shared, shared_provider, first_seen, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip_value, is_private, is_shared, shared_provider, now, status))
            ip_id = cursor.lastrowid
            _record_change(cursor, ip_value, 'asset_added', 'New IP address discovered', {'type': 'ip'})
            conn.commit()
            return ip_id
    finally:
        conn.close()


def create_domain_resolution(dom_id: int, ip_ids: list) -> None:
    """
    Create domain-ip junction entries for resolved IPs.
    
    Args:
        dom_id: Domain ID
        ip_ids: List of IP IDs
    """
    if not ip_ids:
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        for ip_id in ip_ids:
            cursor.execute('''
                INSERT OR IGNORE INTO domain_ip (dom_id, ip_id)
                VALUES (?, ?)
            ''', (dom_id, ip_id))
        conn.commit()
    finally:
        conn.close()


def create_subdomain_resolution(sub_id: int, ip_ids: list) -> None:
    """
    Create subdomain-ip junction entries for resolved IPs.
    
    Args:
        sub_id: Subdomain ID
        ip_ids: List of IP IDs
    """
    if not ip_ids:
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        for ip_id in ip_ids:
            cursor.execute('''
                INSERT OR IGNORE INTO subdomain_ip (sub_id, ip_id)
                VALUES (?, ?)
            ''', (sub_id, ip_id))
        conn.commit()
    finally:
        conn.close()


def save_scan_hint(target: str, hint_type: str, hint_value: str, source: str = 'input') -> None:
    """
    Save port/path hints for later scanning.
    
    Args:
        target: Domain or IP
        hint_type: 'port' or 'path'
        hint_value: '8080' or '/admin'
        source: 'input', 'manual', 'api'
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO scan_hints (target, hint_type, hint_value, source, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (target, hint_type, hint_value, source, utc_now_str()))
        conn.commit()
    finally:
        conn.close()


def get_scan_hints(target: str) -> list:
    """
    Retrieve saved hints for a target.
    
    Args:
        target: Domain or IP
    
    Returns:
        List of hint dicts
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT hint_type, hint_value, source, created_at
            FROM scan_hints
            WHERE target = ?
            ORDER BY created_at DESC
        ''', (target,))
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def log_scan(scan_type: str, target: str, status: str, items_found: int = 0, started_at: str = None, completed_at: str = None) -> None:
    """
    Insert scan history entry.
    
    Args:
        scan_type: 'parser', 'nmap', 'ctlogs', etc.
        target: What was scanned
        status: 'started', 'completed', 'failed'
        items_found: Number of items found
        started_at: Start timestamp
        completed_at: End timestamp
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO scan_history (scan_type, target, started_at, completed_at, status, items_found)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_type, target, started_at, completed_at, status, items_found))
        conn.commit()
    finally:
        conn.close()


def get_domain_by_name(domain_name: str) -> dict:
    """Get domain row by name."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM domain_asset WHERE domain_name = ?", (domain_name,))
        result = cursor.fetchone()
        return dict(result) if result else None
    finally:
        conn.close()


def get_subdomain_by_name(subdomain_name: str) -> dict:
    """Get subdomain row by name."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM subdomain_asset WHERE subdomain_name = ?", (subdomain_name,))
        result = cursor.fetchone()
        return dict(result) if result else None
    finally:
        conn.close()


def get_ip_by_value(ip_value: str) -> dict:
    """Get IP row by value."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM ip_asset WHERE ip_value = ?", (ip_value,))
        result = cursor.fetchone()
        return dict(result) if result else None
    finally:
        conn.close()


def get_all_domains() -> list:
    """Get all domains from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM domain_asset")
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def get_all_ips() -> list:
    """Get all IPs from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM ip_asset")
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def get_all_subdomains() -> list:
    """Get all subdomains from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM subdomain_asset")
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def get_http_targets() -> list:
    """
    Get all domains/subdomains with open HTTP/HTTPS ports and 'up' status.
    
    Returns:
        List of dicts: [{host, ip_id, ip_value, port_num, is_https, type}, ...]
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        query = """
        -- Domains with HTTP ports
        SELECT 
            'domain' as type,
            d.domain_name as host,
            di.ip_id,
            i.ip_value,
            p.port_num,
            CASE WHEN p.port_num = 443 THEN 1 ELSE 0 END as is_https
        FROM domain_asset d
        INNER JOIN domain_ip di ON di.dom_id = d.dom_id
        INNER JOIN ip_asset i ON i.ip_id = di.ip_id
        INNER JOIN ports p ON p.ip_id = i.ip_id
        WHERE d.status = 'up'
            AND i.status = 'up'
            AND p.port_num IN (80, 443, 8080, 8443)
        
        UNION ALL
        
        -- Subdomains with HTTP ports
        SELECT 
            'subdomain' as type,
            s.subdomain_name as host,
            si.ip_id,
            i.ip_value,
            p.port_num,
            CASE WHEN p.port_num = 443 THEN 1 ELSE 0 END as is_https
        FROM subdomain_asset s
        INNER JOIN subdomain_ip si ON si.sub_id = s.sub_id
        INNER JOIN ip_asset i ON i.ip_id = si.ip_id
        INNER JOIN ports p ON p.ip_id = i.ip_id
        WHERE s.status = 'up'
            AND i.status = 'up'
            AND p.port_num IN (80, 443, 8080, 8443)
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def upsert_http_service(host: str, port_num: int,
                        ip_id: int = None,
                        is_https: int = 0, title: str = None, 
                        web_server: str = None) -> int:
    """
    Create or update http_services entry.
    
    Args:
        host: Domain/subdomain name
        port_num: Port number
        ip_id: IP ID from database (optional, None for Cloudflare/CDN sites)
        is_https: 1 for HTTPS, 0 for HTTP
        title: Page title
        web_server: Web server software
    
    Returns:
        http_id (int)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        now = utc_now_str()
        
        cursor.execute('''
            SELECT http_id FROM http_services 
            WHERE host = ? AND port_num = ?
        ''', (host, port_num))
        
        existing = cursor.fetchone()
        
        if existing:
            http_id = existing['http_id']
            
            update_fields = ['last_seen = ?']
            update_values = [now]
            
            if ip_id is not None:
                update_fields.append('ip_id = ?')
                update_values.append(ip_id)
            
            if title:
                update_fields.append('title = ?')
                update_values.append(title)
            
            if web_server:
                update_fields.append('web_server = ?')
                update_values.append(web_server)
            
            update_values.extend([http_id])
            
            cursor.execute(f'''
                UPDATE http_services 
                SET {', '.join(update_fields)}
                WHERE http_id = ?
            ''', update_values)
            
            conn.commit()
            return http_id
        else:
            cursor.execute('''
                INSERT INTO http_services (host, ip_id, port_num, is_https, title, web_server, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (host, ip_id, port_num, is_https, title, web_server, now, now))
            
            conn.commit()
            return cursor.lastrowid
    finally:
        conn.close()


def upsert_technology(http_id: int, tech_name: str, 
                      tech_version: str = None) -> int:
    """
    Create technology entry.
    
    Args:
        http_id: HTTP service ID
        tech_name: Technology name (e.g., 'nginx', 'jQuery')
        tech_version: Version string (e.g., '1.18.0')
    
    Returns:
        tech_id (int)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        now = utc_now_str()
        
        cursor.execute('''
            SELECT tech_id FROM technologies 
            WHERE http_id = ? AND tech_name = ? AND (tech_version = ? OR (tech_version IS NULL AND ? IS NULL))
        ''', (http_id, tech_name, tech_version, tech_version))
        
        existing = cursor.fetchone()
        
        if existing:
            return existing['tech_id']
        
        cursor.execute('''
            INSERT INTO technologies (http_id, tech_name, tech_version, first_seen)
            VALUES (?, ?, ?, ?)
        ''', (http_id, tech_name, tech_version, now))
        
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_technologies_for_host(http_id: int) -> list:
    """
    Get all technologies for a given http_id.
    
    Args:
        http_id: HTTP service ID
    
    Returns:
        List of technology dicts: [{tech_name, tech_version}, ...]
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT tech_id, tech_name, tech_version, first_seen
            FROM technologies
            WHERE http_id = ? AND removed_at IS NULL
            ORDER BY tech_name
        ''', (http_id,))
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def get_all_http_services() -> list:
    """Get all http_services entries."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM http_services")
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def get_all_technologies() -> list:
    """Get all technologies entries."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM technologies")
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


VULN_STATUSES = ('open', 'fixed', 'accepted', 'false_positive')


def upsert_vulnerability(tech_id: int, cve_id: str, cve_score: float = None,
                        description: str = None, recommendation: str = None,
                        match_method: str = 'cpe') -> int:
    """
    Create or update vulnerability entry.

    A finding that was auto-closed as 'fixed' is reopened when it is detected
    again. Findings a user marked 'accepted' or 'false_positive' keep their status.

    Args:
        tech_id: Technology ID
        cve_id: CVE identifier (e.g., 'CVE-2021-44228')
        cve_score: CVSS score (0.0 - 10.0)
        description: CVE description
        recommendation: Remediation recommendation (kept if None)
        match_method: How the CVE was matched ('cpe')

    Returns:
        vuln_id (int)
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        now = utc_now_str()

        cursor.execute('''
            SELECT vuln_id, status FROM vulnerabilities
            WHERE tech_id = ? AND cve_id = ?
        ''', (tech_id, cve_id))

        existing = cursor.fetchone()

        if existing:
            vuln_id = existing['vuln_id']

            cursor.execute('''
                UPDATE vulnerabilities
                SET last_seen = ?, cve_score = ?, description = ?,
                    recommendation = COALESCE(?, recommendation), match_method = ?
                WHERE vuln_id = ?
            ''', (now, cve_score, description, recommendation, match_method, vuln_id))

            if existing['status'] == 'fixed':
                cursor.execute('''
                    UPDATE vulnerabilities
                    SET status = 'open', status_note = 'Detected again on rescan', status_updated_at = ?
                    WHERE vuln_id = ?
                ''', (now, vuln_id))
                tech = _host_for_tech(cursor, tech_id)
                if tech:
                    _record_change(cursor, tech['host'], 'vulnerability_reopened',
                                   f"{cve_id} detected again on {tech['tech_name']}", {'cve_id': cve_id})

            conn.commit()
            return vuln_id
        else:
            cursor.execute('''
                INSERT INTO vulnerabilities (tech_id, cve_id, cve_score, description, recommendation,
                                             first_seen, last_seen, status, status_updated_at, match_method)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            ''', (tech_id, cve_id, cve_score, description, recommendation, now, now, now, match_method))
            vuln_id = cursor.lastrowid
            tech = _host_for_tech(cursor, tech_id)
            if tech:
                version = f" {tech['tech_version']}" if tech['tech_version'] else ''
                _record_change(cursor, tech['host'], 'vulnerability_found',
                               f"{cve_id} found in {tech['tech_name']}{version}",
                               {'cve_id': cve_id, 'cvss': cve_score})

            conn.commit()
            return vuln_id
    finally:
        conn.close()


def reconcile_vulnerabilities(http_id: int, seen_vuln_ids, min_cvss: float = 0.0) -> dict:
    """
    Close open findings on an HTTP service that a complete rescan no longer reports.

    Only call this when every CVE lookup for the service succeeded, otherwise
    a lookup failure would look like a fix.

    - CPE-matched findings that disappear become 'fixed'.
    - Legacy keyword-matched findings that CPE matching does not confirm
      become 'false_positive'.

    Args:
        http_id: HTTP service that was just rescanned
        seen_vuln_ids: vuln_ids reported by this rescan
        min_cvss: CVSS filter the rescan used; findings below it were not
                  looked for, so they are left alone

    Returns:
        {'fixed': int, 'false_positive': int}
    """
    seen = set(seen_vuln_ids)
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        now = utc_now_str()
        cursor.execute('''
            SELECT v.vuln_id, v.match_method, v.cve_id, h.host
            FROM vulnerabilities v
            INNER JOIN technologies t ON t.tech_id = v.tech_id
            INNER JOIN http_services h ON h.http_id = t.http_id
            WHERE t.http_id = ? AND v.status = 'open' AND COALESCE(v.cve_score, 0) >= ?
        ''', (http_id, min_cvss))

        counts = {'fixed': 0, 'false_positive': 0}
        for row in cursor.fetchall():
            if row['vuln_id'] in seen:
                continue
            if row['match_method'] == 'keyword':
                status, note = 'false_positive', 'Legacy keyword match not confirmed by CPE matching'
            else:
                status, note = 'fixed', 'No longer detected on rescan'
            cursor.execute('''
                UPDATE vulnerabilities
                SET status = ?, status_note = ?, status_updated_at = ?
                WHERE vuln_id = ?
            ''', (status, note, now, row['vuln_id']))
            counts[status] += 1
            _record_change(cursor, row['host'],
                           'vulnerability_fixed' if status == 'fixed' else 'vulnerability_closed',
                           f"{row['cve_id']} {'no longer detected' if status == 'fixed' else 'not confirmed by CPE matching'}",
                           {'cve_id': row['cve_id'], 'status': status})

        conn.commit()
        return counts
    finally:
        conn.close()


def _set_vulnerability_status(cursor, vuln_id: int, status: str, note: str, now: str) -> int:
    """
    Apply a status to every row with the same CVE on the same host as vuln_id
    (the dashboard groups CVEs per host). Returns rows updated, 0 if not found.
    """
    cursor.execute('''
        SELECT v.cve_id, h.host
        FROM vulnerabilities v
        INNER JOIN technologies t ON t.tech_id = v.tech_id
        INNER JOIN http_services h ON h.http_id = t.http_id
        WHERE v.vuln_id = ?
    ''', (vuln_id,))
    row = cursor.fetchone()
    if not row:
        return 0

    cursor.execute('''
        UPDATE vulnerabilities
        SET status = ?, status_note = ?, status_updated_at = ?
        WHERE cve_id = ? AND tech_id IN (
            SELECT t.tech_id FROM technologies t
            INNER JOIN http_services h ON h.http_id = t.http_id
            WHERE h.host = ?
        )
    ''', (status, note, now, row['cve_id'], row['host']))
    updated = cursor.rowcount
    _record_change(cursor, row['host'], 'status_changed',
                   f"{row['cve_id']} marked {status.replace('_', ' ')}" + (f": {note}" if note else ''),
                   {'cve_id': row['cve_id'], 'status': status, 'note': note})
    return updated


def _set_finding_status(cursor, finding_id: int, status: str, note: str, now: str) -> int:
    row = cursor.execute('SELECT host, title FROM findings WHERE finding_id = ?', (finding_id,)).fetchone()
    if not row:
        return 0
    cursor.execute('''
        UPDATE findings SET status = ?, status_note = ?, status_updated_at = ?
        WHERE finding_id = ?
    ''', (status, note, now, finding_id))
    updated = cursor.rowcount
    _record_change(cursor, row['host'], 'status_changed',
                   f"{row['title']} marked {status.replace('_', ' ')}" + (f": {note}" if note else ''),
                   {'finding_id': finding_id, 'status': status, 'note': note})
    return updated


def set_vulnerability_status(vuln_id: int, status: str, note: str = None) -> int:
    """
    Set the status of a CVE finding from the dashboard (every row with the
    same CVE on the same host).

    Returns:
        Number of rows updated (0 if vuln_id does not exist)
    """
    return set_statuses([('cve', vuln_id)], status, note)


def set_statuses(items, status: str, note: str = None) -> int:
    """
    Set the status of several CVE findings and security findings in one transaction.

    Args:
        items: iterable of ('cve', vuln_id) or ('finding', finding_id)

    Returns:
        Number of rows updated
    """
    if status not in VULN_STATUSES:
        raise ValueError(f"invalid status: {status}")
    setters = {'cve': _set_vulnerability_status, 'finding': _set_finding_status}

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = utc_now_str()
        updated = 0
        for kind, item_id in items:
            if kind not in setters:
                raise ValueError(f"invalid kind: {kind}")
            updated += setters[kind](cursor, int(item_id), status, note, now)
        conn.commit()
        return updated
    finally:
        conn.close()


def get_cached_cves(cpe: str, max_age_hours: int = 24) -> Optional[list]:
    """Return cached CVE matches for a CPE match string, or None if missing/stale."""
    conn = get_db_connection()
    try:
        row = conn.execute(
            'SELECT result_json, fetched_at FROM cve_cache WHERE cpe = ?', (cpe,)
        ).fetchone()
        if not row:
            return None
        fetched = datetime.strptime(row['fetched_at'], "%Y-%m-%d %H:%M:%S")
        if utc_now() - fetched > timedelta(hours=max_age_hours):
            return None
        return json.loads(row['result_json'])
    except sqlite3.OperationalError:
        # cve_cache table missing (DB not migrated yet)
        return None
    finally:
        conn.close()


def set_cached_cves(cpe: str, cves: list) -> None:
    """Store CVE matches for a CPE match string."""
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT OR REPLACE INTO cve_cache (cpe, result_json, fetched_at) VALUES (?, ?, ?)',
            (cpe, json.dumps(cves), utc_now_str())
        )
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()


def upsert_finding(finding_type: str, host: str, title: str, severity: str,
                   evidence: dict = None) -> tuple:
    """
    Create or refresh a non-CVE finding (e.g. subdomain takeover).

    A 'fixed' finding is reopened when detected again; 'accepted' and
    'false_positive' keep their status.

    Returns:
        (finding_id, alert) - alert is True when the finding is new or reopened
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        now = utc_now_str()
        evidence_json = json.dumps(evidence or {}, sort_keys=True)

        cursor.execute('''
            SELECT finding_id, status FROM findings WHERE finding_type = ? AND host = ?
        ''', (finding_type, host))
        existing = cursor.fetchone()

        if existing:
            finding_id = existing['finding_id']
            cursor.execute('''
                UPDATE findings SET title = ?, severity = ?, evidence = ?, last_seen = ?
                WHERE finding_id = ?
            ''', (title, severity, evidence_json, now, finding_id))
            reopened = existing['status'] == 'fixed'
            if reopened:
                cursor.execute('''
                    UPDATE findings
                    SET status = 'open', status_note = 'Detected again on recheck', status_updated_at = ?
                    WHERE finding_id = ?
                ''', (now, finding_id))
                _record_change(cursor, host, 'finding_reopened', f"{title} (detected again)",
                               {'finding_type': finding_type, 'severity': severity})
            conn.commit()
            return finding_id, reopened

        cursor.execute('''
            INSERT INTO findings (finding_type, host, title, severity, evidence, status,
                                  status_updated_at, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?)
        ''', (finding_type, host, title, severity, evidence_json, now, now, now))
        finding_id = cursor.lastrowid
        _record_change(cursor, host, 'finding_opened', title, {'finding_type': finding_type, 'severity': severity})
        conn.commit()
        return finding_id, True
    finally:
        conn.close()


def reconcile_findings(host: str, finding_types, seen_finding_ids) -> int:
    """
    Mark open findings of the given types on a host as 'fixed' when a
    conclusive recheck no longer reports them.

    Returns:
        Number of findings closed
    """
    types = list(finding_types)
    if not types:
        return 0
    seen = set(seen_finding_ids)
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        now = utc_now_str()
        placeholders = ','.join('?' * len(types))
        cursor.execute(f'''
            SELECT finding_id, finding_type, title FROM findings
            WHERE host = ? AND status = 'open' AND finding_type IN ({placeholders})
        ''', [host] + types)
        to_close = [row for row in cursor.fetchall() if row['finding_id'] not in seen]
        for row in to_close:
            cursor.execute('''
                UPDATE findings
                SET status = 'fixed', status_note = 'No longer detected on recheck', status_updated_at = ?
                WHERE finding_id = ?
            ''', (now, row['finding_id']))
            _record_change(cursor, host, 'finding_fixed', f"{row['title']} (no longer detected)",
                           {'finding_type': row['finding_type']})
        conn.commit()
        return len(to_close)
    finally:
        conn.close()


def set_finding_status(finding_id: int, status: str, note: str = None) -> int:
    """
    Set the status of a security finding from the dashboard.

    Returns:
        Number of rows updated (0 if finding_id does not exist)
    """
    return set_statuses([('finding', finding_id)], status, note)


def get_hostnames_for_takeover_check() -> list:
    """All expanded domain and subdomain names, regardless of liveness status."""
    conn = get_db_connection()
    try:
        rows = conn.execute('''
            SELECT domain_name AS name FROM domain_asset WHERE expand = 1
            UNION
            SELECT subdomain_name AS name FROM subdomain_asset
        ''').fetchall()
        return [row['name'] for row in rows if row['name']]
    finally:
        conn.close()


def get_all_vulnerability_cve_ids() -> list:
    """Distinct CVE IDs across all findings."""
    conn = get_db_connection()
    try:
        return [row['cve_id'] for row in conn.execute('SELECT DISTINCT cve_id FROM vulnerabilities')]
    finally:
        conn.close()


def get_cve_intel(cve_ids) -> dict:
    """Stored exploit intel keyed by CVE ID."""
    ids = list(cve_ids)
    if not ids:
        return {}
    conn = get_db_connection()
    try:
        result = {}
        for i in range(0, len(ids), 500):
            batch = ids[i:i + 500]
            rows = conn.execute(
                f"SELECT * FROM cve_intel WHERE cve_id IN ({','.join('?' * len(batch))})", batch
            ).fetchall()
            result.update({row['cve_id']: dict(row) for row in rows})
        return result
    finally:
        conn.close()


def upsert_cve_intel(cve_id: str, epss: dict = None, kev: dict = None,
                     update_epss: bool = True, update_kev: bool = True) -> None:
    """
    Store exploit intel for one CVE.

    Args:
        epss: {'epss', 'percentile', 'date'} or None (no score)
        kev: {'date_added', 'due_date', 'required_action', 'ransomware'} or None (not in KEV)
        update_epss / update_kev: False keeps the stored values (source unavailable)
    """
    conn = get_db_connection()
    try:
        now = utc_now_str()
        conn.execute('INSERT OR IGNORE INTO cve_intel (cve_id) VALUES (?)', (cve_id,))
        if update_epss:
            conn.execute('''
                UPDATE cve_intel SET epss = ?, epss_percentile = ?, epss_date = ?, updated_at = ?
                WHERE cve_id = ?
            ''', (epss['epss'] if epss else None, epss['percentile'] if epss else None,
                  epss.get('date') if epss else None, now, cve_id))
        if update_kev:
            conn.execute('''
                UPDATE cve_intel SET in_kev = ?, kev_date_added = ?, kev_due_date = ?,
                                     kev_required_action = ?, kev_ransomware = ?, updated_at = ?
                WHERE cve_id = ?
            ''', (1 if kev else 0, kev and kev.get('date_added'), kev and kev.get('due_date'),
                  kev and kev.get('required_action'), 1 if kev and kev.get('ransomware') else 0,
                  now, cve_id))
        conn.commit()
    finally:
        conn.close()


def get_open_hosts_for_cve(cve_id: str) -> list:
    """Hosts with an open finding for this CVE."""
    conn = get_db_connection()
    try:
        rows = conn.execute('''
            SELECT DISTINCT h.host
            FROM vulnerabilities v
            INNER JOIN technologies t ON t.tech_id = v.tech_id
            INNER JOIN http_services h ON h.http_id = t.http_id
            WHERE v.cve_id = ? AND v.status = 'open'
            ORDER BY h.host
        ''', (cve_id,)).fetchall()
        return [row['host'] for row in rows]
    finally:
        conn.close()


def _add_priority(cve: dict) -> dict:
    """Attach exploit intel fields and the P1-P4 priority to a CVE row."""
    from utils.threat_intel import compute_priority
    cve['in_kev'] = bool(cve.get('in_kev'))
    cve['kev_ransomware'] = bool(cve.get('kev_ransomware'))
    cve.update(compute_priority(cve.get('cve_score'), cve.get('epss'), cve['in_kev']))
    return cve


def get_http_services_by_host(hosts=None) -> dict:
    """
    HTTP services grouped by hostname: {host: [(port, is_https), ...]}.
    hosts=None returns every host; an empty list returns nothing.
    """
    if hosts is not None and not hosts:
        return {}
    conn = get_db_connection()
    try:
        query = 'SELECT host, port_num, is_https FROM http_services'
        params = []
        if hosts is not None:
            query += f" WHERE host IN ({','.join('?' * len(hosts))})"
            params = list(hosts)
        services = {}
        for row in conn.execute(query + ' ORDER BY host, port_num', params):
            services.setdefault(row['host'], []).append((row['port_num'], bool(row['is_https'])))
        return services
    finally:
        conn.close()


def get_unserved_candidates(hosts=None, finding_type: str = 'unserved_hostname') -> dict:
    """
    Hostnames to check for "resolves but nothing serves it": up, resolving
    only to non-CDN IPs, and without any recorded HTTP service. Hostnames
    with an open finding of that type are included (whatever their state) so
    the finding can be closed. hosts=None returns all; an empty list nothing.

    Returns:
        {hostname: [ip, ...]}
    """
    if hosts is not None and not hosts:
        return {}
    conn = get_db_connection()
    try:
        rows = conn.execute('''
            SELECT d.domain_name AS name, d.status, i.ip_value, i.is_shared
            FROM domain_asset d JOIN domain_ip di ON di.dom_id = d.dom_id JOIN ip_asset i ON i.ip_id = di.ip_id
            WHERE d.expand = 1
            UNION ALL
            SELECT s.subdomain_name, s.status, i.ip_value, i.is_shared
            FROM subdomain_asset s JOIN subdomain_ip si ON si.sub_id = s.sub_id JOIN ip_asset i ON i.ip_id = si.ip_id
        ''').fetchall()
        served = {row['host'] for row in conn.execute('SELECT DISTINCT host FROM http_services')}
        open_findings = {row['host'] for row in conn.execute(
            "SELECT host FROM findings WHERE finding_type = ? AND status = 'open'", (finding_type,))}
    finally:
        conn.close()

    by_host, shared, status = {}, set(), {}
    for row in rows:
        by_host.setdefault(row['name'], []).append(row['ip_value'])
        status[row['name']] = row['status']
        if row['is_shared']:
            shared.add(row['name'])
    candidates = {host: sorted(set(ips)) for host, ips in by_host.items()
                  if status[host] == 'up' and host not in shared and host not in served}
    for host in open_findings:
        candidates.setdefault(host, sorted(set(by_host.get(host, []))))
    if hosts is not None:
        candidates = {h: ips for h, ips in candidates.items() if h in set(hosts)}
    return candidates


def get_risky_ports_by_ip(ports, ips=None) -> dict:
    """
    Recorded open ports from the given list, on public non-CDN IPs: {ip: [port, ...]}.
    ips=None returns every IP; an empty list returns nothing.
    """
    ports = list(ports)
    if not ports or (ips is not None and not ips):
        return {}
    conn = get_db_connection()
    try:
        query = f'''
            SELECT DISTINCT i.ip_value, p.port_num
            FROM ports p
            INNER JOIN ip_asset i ON i.ip_id = p.ip_id
            WHERE COALESCE(i.is_private, 0) = 0 AND COALESCE(i.is_shared, 0) = 0
              AND COALESCE(p.protocol, 'tcp') = 'tcp'
              AND p.port_num IN ({','.join('?' * len(ports))})
        '''
        params = ports
        if ips is not None:
            query += f" AND i.ip_value IN ({','.join('?' * len(ips))})"
            params = ports + list(ips)
        result = {}
        for row in conn.execute(query + ' ORDER BY i.ip_value, p.port_num', params):
            result.setdefault(row['ip_value'], []).append(row['port_num'])
        return result
    finally:
        conn.close()


def _cvss_severity(score) -> str:
    if score is None:
        return 'unknown'
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    return 'low' if score > 0 else 'none'


def get_findings_for_export(status: str = None) -> list:
    """
    CVE findings (one row per host, port and CVE) and security findings in
    one list, sorted by host. status filters on open/fixed/accepted/false_positive.
    """
    from utils.threat_intel import compute_priority

    conn = get_db_connection()
    try:
        params = [status] if status else []
        rows = []
        cves = conn.execute(f'''
            SELECT h.host, h.port_num, t.tech_name, t.tech_version, v.cve_id, v.cve_score,
                   v.status, v.status_note, v.first_seen, v.last_seen,
                   ci.epss, COALESCE(ci.in_kev, 0) AS in_kev, ci.kev_due_date
            FROM vulnerabilities v
            INNER JOIN technologies t ON t.tech_id = v.tech_id
            INNER JOIN http_services h ON h.http_id = t.http_id
            LEFT JOIN cve_intel ci ON ci.cve_id = v.cve_id
            {'WHERE v.status = ?' if status else ''}
        ''', params).fetchall()
        for r in cves:
            tech = f"{r['tech_name']} {r['tech_version']}".strip() if r['tech_version'] else r['tech_name']
            rows.append({
                'host': r['host'],
                'kind': 'cve',
                'identifier': r['cve_id'],
                'title': f"{r['cve_id']} in {tech}",
                'severity': _cvss_severity(r['cve_score']),
                'priority': compute_priority(r['cve_score'], r['epss'], bool(r['in_kev']))['priority'],
                'cvss': r['cve_score'],
                'epss': r['epss'],
                'in_kev': bool(r['in_kev']),
                'kev_due_date': r['kev_due_date'],
                'technology': tech,
                'port': r['port_num'],
                'status': r['status'],
                'status_note': r['status_note'],
                'first_seen': r['first_seen'],
                'last_seen': r['last_seen'],
                'evidence': '',
            })

        findings = conn.execute(f'''
            SELECT host, finding_type, title, severity, evidence, status, status_note, first_seen, last_seen
            FROM findings {'WHERE status = ?' if status else ''}
        ''', params).fetchall()
        for r in findings:
            try:
                evidence = json.loads(r['evidence'] or '{}')
            except ValueError:
                evidence = {}
            rows.append({
                'host': r['host'],
                'kind': 'finding',
                'identifier': r['finding_type'],
                'title': r['title'],
                'severity': r['severity'],
                'priority': '',
                'cvss': None,
                'epss': None,
                'in_kev': False,
                'kev_due_date': None,
                'technology': '',
                'port': evidence.get('port'),
                'status': r['status'],
                'status_note': r['status_note'],
                'first_seen': r['first_seen'],
                'last_seen': r['last_seen'],
                'evidence': ' '.join(filter(None, [evidence.get('detail'), ', '.join(evidence.get('urls') or [])])),
            })
        rows.sort(key=lambda row: (row['host'], row['kind'], row['identifier'] or ''))
        return rows
    finally:
        conn.close()


def get_screenshot_targets(hosts=None) -> list:
    """
    HTTP services to capture: [{'http_id', 'host', 'url'}].
    hosts=None returns every service; an empty list returns nothing.
    """
    if hosts is not None and not hosts:
        return []
    conn = get_db_connection()
    try:
        query = 'SELECT http_id, host, port_num, is_https FROM http_services'
        params = []
        if hosts is not None:
            query += f" WHERE host IN ({','.join('?' * len(hosts))})"
            params = list(hosts)
        targets = []
        for row in conn.execute(query + ' ORDER BY host, port_num', params):
            scheme = 'https' if row['is_https'] else 'http'
            default = 443 if row['is_https'] else 80
            port = '' if row['port_num'] == default else f":{row['port_num']}"
            targets.append({'http_id': row['http_id'], 'host': row['host'],
                            'url': f"{scheme}://{row['host']}{port}/"})
        return targets
    finally:
        conn.close()


def store_screenshot(capture, image_file: str, thumb_file: str, change_threshold: int,
                     keep: int, delete_file) -> bool:
    """
    Store a capture, record an appearance change against the previous one,
    keep the newest `keep` captures per service (older files are deleted)
    and remember the page title.

    Returns:
        True if the page looks substantially different from the previous capture
    """
    from utils.screenshots import hash_distance

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = _now()
        previous = cursor.execute('''
            SELECT phash FROM screenshots WHERE http_id = ? ORDER BY captured_at DESC, screenshot_id DESC LIMIT 1
        ''', (capture.http_id,)).fetchone()
        cursor.execute('''
            INSERT INTO screenshots (http_id, host, url, final_url, status_code, title, image_file, thumb_file, phash, captured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (capture.http_id, capture.host, capture.url, capture.final_url, capture.status_code,
              capture.title, image_file, thumb_file, capture.phash, now))
        cursor.execute('UPDATE http_services SET title = ? WHERE http_id = ?', (capture.title or None, capture.http_id))

        changed = False
        if previous and previous['phash'] and capture.phash:
            distance = hash_distance(previous['phash'], capture.phash)
            if distance > change_threshold:
                changed = True
                _record_change(cursor, capture.host, 'appearance_changed',
                               f"Page at {capture.url} looks different" + (f" ({capture.title})" if capture.title else ''),
                               {'url': capture.url, 'distance': distance, 'title': capture.title})

        old = cursor.execute('''
            SELECT screenshot_id, image_file, thumb_file FROM screenshots WHERE http_id = ?
            ORDER BY captured_at DESC, screenshot_id DESC LIMIT -1 OFFSET ?
        ''', (capture.http_id, keep)).fetchall()
        for row in old:
            cursor.execute('DELETE FROM screenshots WHERE screenshot_id = ?', (row['screenshot_id'],))
        conn.commit()
    finally:
        conn.close()

    for row in old:
        delete_file(row['image_file'])
        delete_file(row['thumb_file'])
    return changed


def get_screenshot(screenshot_id: int):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT * FROM screenshots WHERE screenshot_id = ?', (screenshot_id,)).fetchone()
        return dict(row) if row else None
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()


def delete_screenshots(http_id: int) -> list:
    """Delete every screenshot of an HTTP service; returns the file names to remove."""
    conn = get_db_connection()
    try:
        rows = conn.execute('SELECT image_file, thumb_file FROM screenshots WHERE http_id = ?', (http_id,)).fetchall()
        conn.execute('DELETE FROM screenshots WHERE http_id = ?', (http_id,))
        conn.commit()
        return [name for row in rows for name in (row['image_file'], row['thumb_file']) if name]
    finally:
        conn.close()


def _get_screenshots_for_host(cursor, host: str) -> list:
    """Latest screenshot per HTTP service of a host, plus how many captures each has."""
    try:
        cursor.execute('''
            SELECT s.*, (SELECT COUNT(*) FROM screenshots c WHERE c.http_id = s.http_id) AS capture_count
            FROM screenshots s
            WHERE s.host = ? AND s.screenshot_id = (
                SELECT screenshot_id FROM screenshots l WHERE l.http_id = s.http_id
                ORDER BY captured_at DESC, screenshot_id DESC LIMIT 1)
            ORDER BY s.url
        ''', (host,))
        return [dict(row) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        return []


def _get_recent_changes_for_host(cursor, host: str, limit: int = 10) -> list:
    try:
        cursor.execute('''
            SELECT change_type, summary, detected_at FROM asset_changes
            WHERE host = ? ORDER BY detected_at DESC, change_id DESC LIMIT ?
        ''', (host, limit))
        return [dict(row) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        return []


def _get_findings_for_host(cursor, host: str) -> list:
    """Security findings for a hostname, open first then by severity."""
    try:
        cursor.execute('''
            SELECT finding_id, finding_type, title, severity, evidence, status, status_note,
                   first_seen, last_seen
            FROM findings
            WHERE host = ?
            ORDER BY status = 'open' DESC,
                     CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                     finding_id
        ''', (host,))
    except sqlite3.OperationalError:
        # findings table missing (DB not migrated yet)
        return []

    findings = []
    for row in cursor.fetchall():
        finding = dict(row)
        try:
            finding['evidence'] = json.loads(finding['evidence'] or '{}')
        except ValueError:
            finding['evidence'] = {}
        findings.append(finding)
    return findings


def get_vulnerabilities_for_tech(tech_id: int, min_cvss: float = 0.0) -> list:
    """
    Get all vulnerabilities for a technology.
    
    Args:
        tech_id: Technology ID
        min_cvss: Minimum CVSS score filter (default 0.0)
    
    Returns:
        List of vulnerability dicts: [{vuln_id, cve_id, cve_score, description, status}, ...]
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT vuln_id, cve_id, cve_score, description, recommendation, status, first_seen
            FROM vulnerabilities
            WHERE tech_id = ? AND cve_score >= ?
            ORDER BY cve_score DESC
        ''', (tech_id, min_cvss))
        
        results = cursor.fetchall()
        return [dict(row) for row in results]
    finally:
        conn.close()


def get_new_cves_for_alert(min_cvss: float = 5.0) -> dict:
    """
    Get CVEs with CVSS >= min_cvss, grouped by asset for Discord alerts.
    
    Args:
        min_cvss: Minimum CVSS score (default 5.0 for Medium+)
    
    Returns:
        Dict keyed by asset name: {
            'scanme.nmap.org': {
                'http_id': 1,
                'host': 'scanme.nmap.org',
                'port': 80,
                'cves': [
                    {'cve_id': 'CVE-2021-44228', 'cve_score': 10.0, 'tech_name': 'Apache', 'description': '...'}
                ]
            }
        }
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        query = """
        SELECT 
            h.http_id,
            h.host,
            h.port_num,
            h.is_https,
            t.tech_name,
            t.tech_version,
            v.vuln_id,
            v.cve_id,
            v.cve_score,
            v.description
        FROM vulnerabilities v
        INNER JOIN technologies t ON t.tech_id = v.tech_id
        INNER JOIN http_services h ON h.http_id = t.http_id
        WHERE v.cve_score >= ? AND v.status = 'open'
        ORDER BY h.host, v.cve_score DESC
        """
        
        cursor.execute(query, (min_cvss,))
        results = cursor.fetchall()
        
        assets = {}
        for row in results:
            host = row['host']
            
            if host not in assets:
                assets[host] = {
                    'http_id': row['http_id'],
                    'host': host,
                    'port': row['port_num'],
                    'is_https': row['is_https'],
                    'cves': []
                }
            
            assets[host]['cves'].append({
                'cve_id': row['cve_id'],
                'cve_score': row['cve_score'],
                'tech_name': row['tech_name'],
                'tech_version': row['tech_version'],
                'description': row['description']
            })
        
        return assets
    finally:
        conn.close()


def get_asset_with_tech_and_cves(host: str = None, ip_value: str = None) -> dict:
    """
    Get asset info with technologies and CVEs for frontend display.
    
    Args:
        host: Domain/subdomain name
        ip_value: IP address
    
    Returns:
        Dict with asset info, technologies, and vulnerabilities
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        asset = None
        
        if host:
            cursor.execute('''
                SELECT 
                    h.http_id,
                    h.host,
                    h.port_num,
                    h.is_https,
                    h.title,
                    h.web_server
                FROM http_services h
                WHERE h.host = ?
            ''', (host,))
            result = cursor.fetchone()
            
            if result:
                asset = dict(result)
                asset['type'] = 'hostname'
                http_id = result['http_id']
                
                cursor.execute('''
                    SELECT tech_name, tech_version
                    FROM technologies
                    WHERE http_id = ?
                    ORDER BY tech_name
                ''', (http_id,))
                asset['technologies'] = [dict(r) for r in cursor.fetchall()]
                
                cursor.execute('''
                    SELECT 
                        v.cve_id,
                        v.cve_score,
                        v.description,
                        v.recommendation,
                        t.tech_name
                    FROM vulnerabilities v
                    INNER JOIN technologies t ON t.tech_id = v.tech_id
                    WHERE t.http_id = ?
                    ORDER BY v.cve_score DESC
                ''', (http_id,))
                asset['cves'] = [dict(r) for r in cursor.fetchall()]
        
        elif ip_value:
            pass
        
        return asset
    finally:
        conn.close()


def _get_ips_for_domain(cursor, dom_id: int) -> list:
    """
    Get IPs for a domain.
    
    Args:
        cursor: Database cursor
        dom_id: Domain ID
    
    Returns:
        List of IP strings
    """
    cursor.execute('''
        SELECT DISTINCT i.ip_value
        FROM domain_ip di
        JOIN ip_asset i ON di.ip_id = i.ip_id
        WHERE di.dom_id = ?
        ORDER BY i.ip_value
    ''', (dom_id,))
    return [row['ip_value'] for row in cursor.fetchall()]


def _get_ips_for_subdomain(cursor, sub_id: int) -> list:
    """
    Get IPs for a subdomain.
    
    Args:
        cursor: Database cursor
        sub_id: Subdomain ID
    
    Returns:
        List of IP strings
    """
    cursor.execute('''
        SELECT DISTINCT i.ip_value
        FROM subdomain_ip si
        JOIN ip_asset i ON si.ip_id = i.ip_id
        WHERE si.sub_id = ?
        ORDER BY i.ip_value
    ''', (sub_id,))
    return [row['ip_value'] for row in cursor.fetchall()]


def _get_cert_expiry(cursor, hostname: str) -> dict:
    """
    The certificate the host currently serves (soonest-expiring if its HTTPS
    ports differ), including an expired one.

    Returns:
        Dict with 'not_after', 'issuer', 'port', 'days_until_expiry', or None
    """
    from datetime import datetime, timezone

    row = cursor.execute(f"""
        SELECT not_after, issuer, port FROM certificates
        WHERE {SERVED_CERT} AND hostname = ?
        ORDER BY not_after ASC LIMIT 1
    """, (hostname,)).fetchone()
    if not row:
        return None
    result = dict(row)
    try:
        not_after = datetime.strptime(result['not_after'][:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        result['days_until_expiry'] = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)
    except (ValueError, TypeError):
        result['days_until_expiry'] = None
    return result


def _get_technologies_for_host(cursor, host: str) -> list:
    """
    Get technologies for a hostname (domain or subdomain).
    Returns one entry per technology per port.
    
    Args:
        cursor: Database cursor
        host: Hostname
    
    Returns:
        List of {'name': str, 'version': str or None, 'port': int}
    """
    cursor.execute('''
        SELECT 
            t.tech_name as name,
            t.tech_version as version,
            h.port_num as port
        FROM technologies t
        INNER JOIN http_services h ON h.http_id = t.http_id
        WHERE h.host = ? AND t.removed_at IS NULL
        ORDER BY h.port_num, t.tech_name
    ''', (host,))
    
    techs = []
    for row in cursor.fetchall():
        tech = dict(row)
        tech['name'] = tech['name'] or ''
        tech['version'] = tech['version'] or None
        techs.append(tech)
    
    return techs


def _get_cves_for_host(cursor, host: str) -> list:
    """
    Get CVEs for a hostname, grouped by cve_id with aggregated ports.
    
    Args:
        cursor: Database cursor
        host: Hostname
    
    Returns:
        List of {'vuln_id': int, 'cve_id': str, 'cve_score': float, 'description': str, 'recommendation': str, 'tech_name': str, 'ports': str}
    """
    cursor.execute('''
        SELECT 
            MIN(v.vuln_id) as vuln_id,
            v.cve_id,
            MAX(v.cve_score) as cve_score,
            v.description,
            CASE 
                WHEN SUM(CASE WHEN v.recommendation IS NOT NULL THEN 1 ELSE 0 END) > 0 
                THEN (
                    SELECT recommendation 
                    FROM vulnerabilities v2 
                    WHERE v2.cve_id = v.cve_id 
                    AND v2.recommendation IS NOT NULL 
                    LIMIT 1
                )
                ELSE NULL 
            END as recommendation,
            GROUP_CONCAT(DISTINCT t.tech_name) as tech_name,
            GROUP_CONCAT(DISTINCT h.port_num) as ports,
            CASE WHEN SUM(v.status = 'open') > 0 THEN 'open' ELSE MAX(v.status) END as status,
            MAX(v.status_note) as status_note,
            MAX(ci.epss) as epss,
            MAX(ci.epss_percentile) as epss_percentile,
            MAX(COALESCE(ci.in_kev, 0)) as in_kev,
            MAX(ci.kev_due_date) as kev_due_date,
            MAX(ci.kev_required_action) as kev_required_action,
            MAX(COALESCE(ci.kev_ransomware, 0)) as kev_ransomware
        FROM vulnerabilities v
        INNER JOIN technologies t ON t.tech_id = v.tech_id
        INNER JOIN http_services h ON h.http_id = t.http_id
        LEFT JOIN cve_intel ci ON ci.cve_id = v.cve_id
        WHERE h.host = ?
        GROUP BY v.cve_id
        ORDER BY SUM(v.status = 'open') > 0 DESC, MAX(COALESCE(ci.in_kev, 0)) DESC,
                 COALESCE(MAX(ci.epss), 0) >= 0.1 DESC, MAX(v.cve_score) DESC, COALESCE(MAX(ci.epss), 0) DESC
    ''', (host,))
    
    cves = []
    for row in cursor.fetchall():
        cve = dict(row)
        cve['cve_score'] = float(cve['cve_score']) if cve['cve_score'] else 0.0
        cve['description'] = cve['description'] or ''
        cve['recommendation'] = cve['recommendation'] or None
        cve['tech_name'] = cve['tech_name'] or ''
        cve['ports'] = cve['ports'] or ''
        cve['status'] = cve['status'] or 'open'
        cves.append(_add_priority(cve))
    
    return cves


def _get_technologies_for_ip(cursor, ip_id: int) -> list:
    """
    Get technologies for a standalone IP asset.
    
    Args:
        cursor: Database cursor
        ip_id: IP ID
    
    Returns:
        List of {'name': str, 'version': str or None, 'port': int}
    """
    cursor.execute('''
        SELECT 
            t.tech_name as name,
            t.tech_version as version,
            h.port_num as port
        FROM technologies t
        INNER JOIN http_services h ON h.http_id = t.http_id
        INNER JOIN ip_asset i ON i.ip_id = ?
        WHERE (h.ip_id = ? OR h.host = i.ip_value) AND t.removed_at IS NULL
        ORDER BY h.port_num, t.tech_name
    ''', (ip_id, ip_id))
    
    techs = []
    for row in cursor.fetchall():
        tech = dict(row)
        tech['name'] = tech['name'] or ''
        tech['version'] = tech['version'] or None
        techs.append(tech)
    
    return techs


def _get_cves_for_ip(cursor, ip_id: int) -> list:
    """
    Get CVEs for a standalone IP asset, grouped by cve_id with aggregated ports.
    
    Args:
        cursor: Database cursor
        ip_id: IP ID
    
    Returns:
        List of {'vuln_id': int, 'cve_id': str, 'cve_score': float, 'description': str, 'recommendation': str, 'tech_name': str, 'ports': str}
    """
    cursor.execute('''
        SELECT 
            MIN(v.vuln_id) as vuln_id,
            v.cve_id,
            MAX(v.cve_score) as cve_score,
            v.description,
            CASE 
                WHEN SUM(CASE WHEN v.recommendation IS NOT NULL THEN 1 ELSE 0 END) > 0 
                THEN (
                    SELECT recommendation 
                    FROM vulnerabilities v2 
                    WHERE v2.cve_id = v.cve_id 
                    AND v2.recommendation IS NOT NULL 
                    LIMIT 1
                )
                ELSE NULL 
            END as recommendation,
            GROUP_CONCAT(DISTINCT t.tech_name) as tech_name,
            GROUP_CONCAT(DISTINCT h.port_num) as ports,
            CASE WHEN SUM(v.status = 'open') > 0 THEN 'open' ELSE MAX(v.status) END as status,
            MAX(v.status_note) as status_note,
            MAX(ci.epss) as epss,
            MAX(ci.epss_percentile) as epss_percentile,
            MAX(COALESCE(ci.in_kev, 0)) as in_kev,
            MAX(ci.kev_due_date) as kev_due_date,
            MAX(ci.kev_required_action) as kev_required_action,
            MAX(COALESCE(ci.kev_ransomware, 0)) as kev_ransomware
        FROM vulnerabilities v
        INNER JOIN technologies t ON t.tech_id = v.tech_id
        INNER JOIN http_services h ON h.http_id = t.http_id
        INNER JOIN ip_asset i ON i.ip_id = ?
        LEFT JOIN cve_intel ci ON ci.cve_id = v.cve_id
        WHERE h.ip_id = ? OR h.host = i.ip_value
        GROUP BY v.cve_id
        ORDER BY SUM(v.status = 'open') > 0 DESC, MAX(COALESCE(ci.in_kev, 0)) DESC,
                 COALESCE(MAX(ci.epss), 0) >= 0.1 DESC, MAX(v.cve_score) DESC, COALESCE(MAX(ci.epss), 0) DESC
    ''', (ip_id, ip_id))
    
    cves = []
    for row in cursor.fetchall():
        cve = dict(row)
        cve['cve_score'] = float(cve['cve_score']) if cve['cve_score'] else 0.0
        cve['description'] = cve['description'] or ''
        cve['recommendation'] = cve['recommendation'] or None
        cve['tech_name'] = cve['tech_name'] or ''
        cve['ports'] = cve['ports'] or ''
        cve['status'] = cve['status'] or 'open'
        cves.append(_add_priority(cve))
    
    return cves


def _get_ports_for_ip(cursor, ip_id: int) -> list:
    """
    Get ports for an IP asset.
    
    Args:
        cursor: Database cursor
        ip_id: IP ID
    
    Returns:
        List of {'port': str, 'service': str}
    """
    cursor.execute('''
        SELECT
            p.port_num,
            p.service_name
        FROM ports p
        WHERE p.ip_id = ?
        ORDER BY p.port_num
    ''', (ip_id,))
    
    findings = []
    for row in cursor.fetchall():
        finding = {
            'port': f"{row['port_num']}/TCP",
            'service': row['service_name'] or 'unknown'
        }
        findings.append(finding)
    
    return findings


def _get_ports_for_domain(cursor, dom_id: int) -> list:
    """
    Get ports for all IPs linked to a domain.
    
    Args:
        cursor: Database cursor
        dom_id: Domain ID
    
    Returns:
        List of {'port': str, 'service': str, 'ip': str}
    """
    cursor.execute('''
        SELECT DISTINCT
            p.port_num,
            p.service_name,
            i.ip_value
        FROM ports p
        INNER JOIN ip_asset i ON i.ip_id = p.ip_id
        INNER JOIN domain_ip di ON di.ip_id = i.ip_id
        WHERE di.dom_id = ?
        ORDER BY p.port_num
    ''', (dom_id,))
    
    findings = []
    seen = set()
    for row in cursor.fetchall():
        key = (row['port_num'], row['service_name'])
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            'port': f"{row['port_num']}/TCP",
            'service': row['service_name'] or 'unknown'
        })
    
    return findings


def _get_ports_for_subdomain(cursor, sub_id: int) -> list:
    """
    Get ports for all IPs linked to a subdomain.
    
    Args:
        cursor: Database cursor
        sub_id: Subdomain ID
    
    Returns:
        List of {'port': str, 'service': str}
    """
    cursor.execute('''
        SELECT DISTINCT
            p.port_num,
            p.service_name
        FROM ports p
        INNER JOIN ip_asset i ON i.ip_id = p.ip_id
        INNER JOIN subdomain_ip si ON si.ip_id = i.ip_id
        WHERE si.sub_id = ?
        ORDER BY p.port_num
    ''', (sub_id,))
    
    findings = []
    for row in cursor.fetchall():
        findings.append({
            'port': f"{row['port_num']}/TCP",
            'service': row['service_name'] or 'unknown'
        })
    
    return findings


def _get_directories_for_host(cursor, host: str) -> list:
    """
    Get directories discovered for a hostname.
    
    Args:
        cursor: Database cursor
        host: Hostname
    
    Returns:
        List of {'path': str, 'status': int, 'length': int}
    """
    cursor.execute('''
        SELECT DISTINCT
            d.path,
            d.status_code as status,
            d.content_length as length
        FROM directories d
        INNER JOIN http_services h ON h.http_id = d.http_id
        WHERE h.host = ?
        ORDER BY d.path
    ''', (host,))
    
    dirs = []
    for row in cursor.fetchall():
        dirs.append({
            'path': row['path'],
            'status': row['status'] or 0,
            'length': row['length'] or 0
        })
    
    return dirs


# ============================================
# PHASE 1 HELPER FUNCTIONS
# ============================================

def domain_exists(domain: str) -> bool:
    """
    Check if domain exists in domain_asset.
    
    Args:
        domain: Domain name to check
    
    Returns:
        True if domain exists, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT dom_id FROM domain_asset WHERE domain_name = ?", (domain,))
        result = cursor.fetchone()
        return result is not None
    finally:
        conn.close()


def subdomain_exists(subdomain: str) -> bool:
    """
    Check if subdomain exists in subdomain_asset.
    
    Args:
        subdomain: Subdomain name to check
    
    Returns:
        True if subdomain exists, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?", (subdomain,))
        result = cursor.fetchone()
        return result is not None
    finally:
        conn.close()


def ip_exists(ip: str) -> bool:
    """
    Check if IP exists in ip_asset.
    
    Args:
        ip: IP address to check
    
    Returns:
        True if IP exists, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT ip_id FROM ip_asset WHERE ip_value = ?", (ip,))
        result = cursor.fetchone()
        return result is not None
    finally:
        conn.close()


def filter_new_subdomains(subdomains: list) -> list:
    """
    Filter out subdomains that already exist in database.
    
    Args:
        subdomains: List of subdomain names
    
    Returns:
        List of subdomains that do NOT exist in database
    """
    if not subdomains:
        return []
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        new_subdomains = []
        for sub in subdomains:
            cursor.execute("SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?", (sub,))
            if not cursor.fetchone():
                new_subdomains.append(sub)
        return new_subdomains
    finally:
        conn.close()


def filter_new_ips(ips: list) -> list:
    """
    Filter out IPs that already exist in database.
    
    Args:
        ips: List of IP addresses
    
    Returns:
        List of IPs that do NOT exist in database
    """
    if not ips:
        return []
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        new_ips = []
        for ip in ips:
            cursor.execute("SELECT ip_id FROM ip_asset WHERE ip_value = ?", (ip,))
            if not cursor.fetchone():
                new_ips.append(ip)
        return new_ips
    finally:
        conn.close()


def get_domain_id(domain: str) -> int:
    """
    Get domain ID from domain_asset.
    
    Args:
        domain: Domain name
    
    Returns:
        Domain ID or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT dom_id FROM domain_asset WHERE domain_name = ?", (domain,))
        result = cursor.fetchone()
        return result['dom_id'] if result else None
    finally:
        conn.close()


def get_subdomain_id(subdomain: str) -> int:
    """
    Get subdomain ID from subdomain_asset.
    
    Args:
        subdomain: Subdomain name
    
    Returns:
        Subdomain ID or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?", (subdomain,))
        result = cursor.fetchone()
        return result['sub_id'] if result else None
    finally:
        conn.close()


def get_ip_id(ip: str) -> int:
    """
    Get IP ID from ip_asset.
    
    Args:
        ip: IP address
    
    Returns:
        IP ID or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT ip_id FROM ip_asset WHERE ip_value = ?", (ip,))
        result = cursor.fetchone()
        return result['ip_id'] if result else None
    finally:
        conn.close()


def update_domain_status(dom_id: int, status: str) -> bool:
    """
    Update domain status in domain_asset.
    
    Args:
        dom_id: Domain ID
        status: New status ('up', 'down', 'pending')
    
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE domain_asset SET status = ?, last_seen = ? WHERE dom_id = ?",
            (status, utc_now_str(), dom_id)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating domain status: {e}")
        return False
    finally:
        conn.close()


def update_subdomain_status(sub_id: int, status: str) -> bool:
    """
    Update subdomain status in subdomain_asset.
    
    Args:
        sub_id: Subdomain ID
        status: New status ('up', 'down', 'pending')
    
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE subdomain_asset SET status = ?, last_seen = ? WHERE sub_id = ?",
            (status, utc_now_str(), sub_id)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating subdomain status: {e}")
        return False
    finally:
        conn.close()


def update_ip_status(ip_id: int, status: str) -> bool:
    """
    Update IP status in ip_asset.
    
    Args:
        ip_id: IP ID
        status: New status ('up', 'down', 'pending')
    
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE ip_asset SET status = ?, last_seen = ? WHERE ip_id = ?",
            (status, utc_now_str(), ip_id)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating IP status: {e}")
        return False
    finally:
        conn.close()


def update_asset_last_scanned(asset_id: int, asset_type: str) -> None:
    """
    Update last_scanned timestamp for an asset.
    
    Args:
        asset_id: Asset ID (dom_id or sub_id)
        asset_type: 'domain', 'subdomain', or 'ip'
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_now_str()
    
    try:
        if asset_type == 'domain':
            cursor.execute('''
                UPDATE domain_asset SET last_scanned = ? WHERE dom_id = ?
            ''', (now, asset_id))
        elif asset_type == 'subdomain':
            cursor.execute('''
                UPDATE subdomain_asset SET last_scanned = ? WHERE sub_id = ?
            ''', (now, asset_id))
        elif asset_type == 'ip':
            cursor.execute('''
                UPDATE ip_asset SET last_scanned = ? WHERE ip_id = ?
            ''', (now, asset_id))
        
        conn.commit()
    except Exception as e:
        print(f"Error updating last_scanned: {e}")
    finally:
        conn.close()


SERVED_CERT = "source = 'tls' AND replaced_at IS NULL"   # certificates currently presented


def get_https_services(hosts=None) -> list:
    """Distinct (host, port) of HTTPS services, optionally only for hosts."""
    if hosts is not None and not hosts:
        return []
    conn = get_db_connection()
    try:
        query = 'SELECT DISTINCT host, port_num FROM http_services WHERE is_https = 1'
        params = []
        if hosts is not None:
            query += f" AND host IN ({','.join('?' * len(hosts))})"
            params = list(hosts)
        return [(row['host'], row['port_num']) for row in conn.execute(query + ' ORDER BY host, port_num', params)]
    finally:
        conn.close()


def record_served_certificate(cert: dict):
    """
    Store the certificate a service presents (from utils.tls_certs).

    Returns:
        ('same', None) unchanged, ('new', None) first certificate seen, or
        ('changed', {'hostname', 'port', 'summary'}) when it was replaced;
        the change is also recorded in the change history.
    """
    now = utc_now_str()
    host, port = cert['hostname'], cert['port']
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        current = cursor.execute(f"""
            SELECT cert_id, issuer, not_after, fingerprint FROM certificates
            WHERE {SERVED_CERT} AND hostname = ? AND port = ?
            ORDER BY cert_id DESC LIMIT 1
        """, (host, port)).fetchone()
        if current and current['fingerprint'] == cert['fingerprint']:
            cursor.execute('UPDATE certificates SET last_seen = ? WHERE cert_id = ?', (now, current['cert_id']))
            conn.commit()
            return 'same', None

        sub = cursor.execute('SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?', (host,)).fetchone()
        cursor.execute("""
            INSERT INTO certificates (sub_id, hostname, port, issuer, not_before, not_after, serial_number,
                                      fingerprint, source, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'tls', ?, ?)
        """, (sub['sub_id'] if sub else None, host, port, cert.get('issuer'), cert.get('not_before'),
              cert['not_after'], cert.get('serial_number'), cert['fingerprint'], now, now))
        if not current:
            conn.commit()
            return 'new', None

        cursor.execute('UPDATE certificates SET replaced_at = ? WHERE cert_id = ?', (now, current['cert_id']))
        where = f" on port {port}" if port != 443 else ''
        if (current['issuer'] or '') != (cert.get('issuer') or ''):
            summary = (f"Certificate replaced{where}: now issued by {cert.get('issuer') or 'unknown'} "
                       f"(was {current['issuer'] or 'unknown'}), valid until {cert['not_after'][:10]}")
        else:
            summary = f"Certificate replaced{where}, valid until {cert['not_after'][:10]}"
        _record_change(cursor, host, 'certificate_changed', summary, {
            'port': port, 'old_fingerprint': current['fingerprint'], 'new_fingerprint': cert['fingerprint'],
            'old_issuer': current['issuer'], 'new_issuer': cert.get('issuer'),
            'old_not_after': current['not_after'], 'not_after': cert['not_after'],
        })
        conn.commit()
        return 'changed', {'hostname': host, 'port': port, 'summary': summary}
    finally:
        conn.close()


def retire_served_certificates(still_served) -> int:
    """Mark certificates of services that are no longer HTTPS (or gone) as replaced."""
    keep = {(host, port) for host, port in still_served}
    now = utc_now_str()
    conn = get_db_connection()
    try:
        stale = [row['cert_id'] for row in conn.execute(f'SELECT cert_id, hostname, port FROM certificates WHERE {SERVED_CERT}')
                 if (row['hostname'], row['port']) not in keep]
        conn.executemany('UPDATE certificates SET replaced_at = ? WHERE cert_id = ?', [(now, cert_id) for cert_id in stale])
        conn.commit()
        return len(stale)
    finally:
        conn.close()


def get_http_service_id(host: str, port: int) -> Optional[int]:
    """
    Get http_id for host:port combination.
    
    Args:
        host: Hostname
        port: Port number
    
    Returns:
        http_id or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT http_id FROM http_services WHERE host = ? AND port_num = ?
    ''', (host, port))
    
    result = cursor.fetchone()
    conn.close()
    
    return result['http_id'] if result else None


def clear_phase1_queue() -> int:
    """
    Clear pending/running Phase 1 items from scan queue.
    
    Called by Phase 2 before starting to ensure clean slate.
    
    Returns:
        Number of items deleted
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        DELETE FROM scan_queue
        WHERE scan_type = 'phase1'
          AND status IN ('pending', 'running')
    ''')
    
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    
    return deleted


# ============================================
# PHASE 3 SETTINGS FUNCTIONS
# ============================================

def get_setting(key: str) -> str:
    """
    Get setting value from settings table.
    
    Args:
        key: Setting key
    
    Returns:
        Setting value or empty string if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    result = cursor.fetchone()
    conn.close()
    
    return result['value'] if result else ''


def set_setting(key: str, value: str) -> bool:
    """
    Update or insert setting.
    
    Args:
        key: Setting key
        value: Setting value
    
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = utc_now_str()
    
    cursor.execute('''
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?
    ''', (key, value, now, value, now))
    
    conn.commit()
    conn.close()
    
    return True


def get_all_assets_for_liveness() -> list:
    """
    Get all domains, subdomains and standalone IPs (submitted directly, not
    resolved from a hostname) with their current status.
    
    Returns:
        List of dicts with asset_id, asset_type, name, status, last_liveness_check
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    assets = []
    
    # Get domains
    cursor.execute('''
        SELECT dom_id as asset_id, 'domain' as asset_type, domain_name as name, status, last_liveness_check
        FROM domain_asset WHERE expand = 1
    ''')
    assets.extend([dict(row) for row in cursor.fetchall()])
    
    # Get subdomains
    cursor.execute('''
        SELECT sub_id as asset_id, 'subdomain' as asset_type, subdomain_name as name, status, last_liveness_check
        FROM subdomain_asset
    ''')
    assets.extend([dict(row) for row in cursor.fetchall()])

    # IPs behind a hostname are covered by that hostname's check
    cursor.execute('''
        SELECT ip_id as asset_id, 'ip' as asset_type, ip_value as name, status, last_liveness_check
        FROM ip_asset
        WHERE ip_id NOT IN (SELECT ip_id FROM domain_ip UNION SELECT ip_id FROM subdomain_ip)
    ''')
    assets.extend([dict(row) for row in cursor.fetchall()])
    
    conn.close()
    
    return assets


def update_asset_status(asset_id: int, asset_type: str, status: str) -> bool:
    """
    Update status column for domain or subdomain.
    
    Args:
        asset_id: dom_id or sub_id
        asset_type: 'domain' or 'subdomain'
        status: 'up' or 'down'
    
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = utc_now_str()
    
    if asset_type == 'domain':
        cursor.execute('''
            UPDATE domain_asset SET status = ?, last_seen = ? WHERE dom_id = ?
        ''', (status, now, asset_id))
    else:
        cursor.execute('''
            UPDATE subdomain_asset SET status = ?, last_seen = ? WHERE sub_id = ?
        ''', (status, now, asset_id))
    
    conn.commit()
    conn.close()
    
    return cursor.rowcount > 0


def get_all_monitored_domains() -> list:
    """
    Get all domains for CT logs monitoring.
    
    Returns:
        List of domain names
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Containers (parents of subdomains submitted on their own) are not expanded
    cursor.execute('SELECT domain_name FROM domain_asset WHERE expand = 1')
    domains = [row['domain_name'] for row in cursor.fetchall()]
    
    conn.close()
    
    return domains


def get_known_subdomains() -> set:
    """
    Get all known subdomains from database.
    
    Includes:
    - Subdomains in subdomain_asset (already processed)
    - Subdomains in scan_queue pending/processing (being discovered)
    
    Returns:
        Set of subdomain names
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT subdomain_name FROM subdomain_asset')
    subdomains = {row['subdomain_name'] for row in cursor.fetchall()}
    
    cursor.execute('''
        SELECT target FROM scan_queue 
        WHERE scan_type = 'phase0_discovery' 
          AND status IN ('pending', 'processing')
    ''')
    subdomains.update(row['target'] for row in cursor.fetchall())
    
    conn.close()
    
    return subdomains


def queue_subdomain_discovery(subdomain_name: str, domain_name: str):
    """
    Queue a newly discovered subdomain for Phase 0 processing.
    
    Args:
        subdomain_name: New subdomain found via CT logs
        domain_name: Parent domain
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if already exists in subdomain_asset
    cursor.execute('SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?', (subdomain_name,))
    if cursor.fetchone():
        conn.close()
        return
    
    # Check if it's a root domain in domain_asset
    cursor.execute('SELECT dom_id FROM domain_asset WHERE domain_name = ?', (subdomain_name,))
    if cursor.fetchone():
        conn.close()
        return
    
    # Add to scan_queue for Phase 0
    now = utc_now_str()
    cursor.execute('''
        INSERT OR IGNORE INTO scan_queue (scan_type, target, target_type, status, cycle, queued_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ('phase0_discovery', subdomain_name, 'subdomain', 'pending', 'continuous_monitoring', now))
    
    conn.commit()
    conn.close()


def blacklist_token(jti: str, user: str, expires_at: str) -> bool:
    """
    Add token JTI to blacklist and cleanup expired entries.
    
    Args:
        jti: Unique token ID
        user: Token owner
        expires_at: When the token naturally expires
    
    Returns:
        True if successfully blacklisted
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_now_str()
    
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO token_blacklist (jti, user, expires_at, created_at)
            VALUES (?, ?, ?, ?)
        ''', (jti, user, expires_at, now))
        
        # Lazy cleanup: remove expired entries
        cursor.execute("DELETE FROM token_blacklist WHERE expires_at < ?", (now,))
        
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to blacklist token: {e}")
        return False
    finally:
        conn.close()


def is_token_blacklisted(jti: str) -> bool:
    """
    Check if token JTI is in the blacklist.
    
    Args:
        jti: Unique token ID
    
    Returns:
        True if token is blacklisted
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT 1 FROM token_blacklist WHERE jti = ?', (jti,))
    result = cursor.fetchone()
    
    conn.close()
    return result is not None


def blacklist_all_user_tokens(user: str) -> int:
    """
    Blacklist all active refresh tokens for a user.
    Used when token reuse is detected (possible theft).
    
    Args:
        user: Username
    
    Returns:
        Number of tokens blacklisted
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_now_str()
    
    # Find all non-expired, non-blacklisted tokens for this user
    # Since we only blacklist refresh tokens, all entries belong to refresh tokens
    cursor.execute('''
        SELECT jti, expires_at FROM token_blacklist 
        WHERE user = ? AND expires_at > ?
    ''', (user, now))
    
    # All user's tokens that aren't already blacklisted won't be in the table
    # We need a different approach: add a catch-all blacklist entry
    cursor.execute('''
        INSERT OR IGNORE INTO token_blacklist (jti, user, expires_at, created_at)
        VALUES (?, ?, ?, ?)
    ''', (f'user_revoke:{user}:{now}', user, 
          utc_in(days=7), now))
    
    conn.commit()
    conn.close()
    
    logger.warning(f"All refresh tokens revoked for user: {user}")
    return 1


def is_user_revoked(user: str) -> bool:
    """
    Check if all tokens for a user have been revoked.
    Used after token reuse detection.
    
    Args:
        user: Username
    
    Returns:
        True if user's tokens are revoked
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_now_str()
    
    cursor.execute('''
        SELECT 1 FROM token_blacklist 
        WHERE jti LIKE ? AND expires_at > ?
        LIMIT 1
    ''', (f'user_revoke:{user}:%', now))
    
    result = cursor.fetchone()
    conn.close()
    return result is not None


def mark_cert_notified(cert_id: int, hostname: str, threshold: int) -> bool:
    """
    Record that a certificate expiry notification was sent at this threshold.
    
    Args:
        cert_id: Certificate ID from certificates table
        hostname: Certificate hostname
        threshold: Days threshold (7, 5, 3, or 1)
    
    Returns:
        True if inserted successfully
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO cert_notifications (cert_id, hostname, days_threshold)
            VALUES (?, ?, ?)
        ''', (cert_id, hostname, threshold))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error marking cert notification: {e}")
        return False
    finally:
        conn.close()


def is_cert_notified(cert_id: int, threshold: int) -> bool:
    """
    Check if notification already sent for this cert at this threshold.
    
    Args:
        cert_id: Certificate ID
        threshold: Days threshold
    
    Returns:
        True if already notified
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 1 FROM cert_notifications
        WHERE cert_id = ? AND days_threshold = ?
    ''', (cert_id, threshold))
    
    result = cursor.fetchone()
    conn.close()
    return result is not None


def cleanup_cert_notifications():
    """
    Remove notification tracking entries for certificates
    that no longer exist or have been renewed (new cert_id).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        DELETE FROM cert_notifications
        WHERE cert_id NOT IN (SELECT cert_id FROM certificates)
    ''')
    
    conn.commit()
    conn.close()


if __name__ == '__main__':
    print("Use InitDB.py to initialize database")