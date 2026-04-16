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
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "lazyeasm.db")


def get_db_connection():
    """Get database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
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


def upsert_domain(domain_name: str, is_wildcard: int = 0, wildcard_ip: str = None, status: str = 'up') -> int:
    """
    Insert new domain or update existing. Returns dom_id.
    
    Args:
        domain_name: Root domain (e.g., 'nutelyn.com')
        is_wildcard: 1 if wildcard DNS detected, 0 otherwise
        wildcard_ip: IP that wildcard resolves to
        status: 'up' or 'down'
    
    Returns:
        dom_id
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("SELECT dom_id FROM domain_asset WHERE domain_name = ?", (domain_name,))
        result = cursor.fetchone()
        
        if result:
            dom_id = result['dom_id']
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
            conn.commit()
            return cursor.lastrowid
    finally:
        conn.close()


def upsert_subdomain(subdomain_name: str, dom_id: int, status: str = 'up') -> int:
    """
    Insert new subdomain or update existing. Returns sub_id.
    
    Args:
        subdomain_name: Full subdomain (e.g., 'api.nutelyn.com')
        dom_id: Parent domain ID
        status: 'up' or 'down'
    
    Returns:
        sub_id
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?", (subdomain_name,))
        result = cursor.fetchone()
        
        if result:
            sub_id = result['sub_id']
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
            conn.commit()
            return cursor.lastrowid
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
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("SELECT ip_id FROM ip_asset WHERE ip_value = ?", (ip_value,))
        result = cursor.fetchone()
        
        if result:
            ip_id = result['ip_id']
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
            conn.commit()
            return cursor.lastrowid
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
        ''', (target, hint_type, hint_value, source, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
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
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
            SELECT http_id FROM http_services 
            WHERE host = ? AND port_num = ?
        ''', (host, port_num))
        
        existing = cursor.fetchone()
        
        if existing:
            http_id = existing['http_id']
            
            update_fields = ['last_seen = ?']
            update_values = [now]
            
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
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
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
            WHERE http_id = ?
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


def upsert_vulnerability(tech_id: int, cve_id: str, cve_score: float = None,
                        description: str = None, recommendation: str = None) -> int:
    """
    Create or update vulnerability entry.
    
    Args:
        tech_id: Technology ID
        cve_id: CVE identifier (e.g., 'CVE-2021-44228')
        cve_score: CVSS score (0.0 - 10.0)
        description: CVE description
        recommendation: Remediation recommendation
    
    Returns:
        vuln_id (int)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
            SELECT vuln_id FROM vulnerabilities 
            WHERE tech_id = ? AND cve_id = ?
        ''', (tech_id, cve_id))
        
        existing = cursor.fetchone()
        
        if existing:
            vuln_id = existing['vuln_id']
            
            cursor.execute('''
                UPDATE vulnerabilities 
                SET last_seen = ?, cve_score = ?, description = ?, recommendation = ?
                WHERE vuln_id = ?
            ''', (now, cve_score, description, recommendation, vuln_id))
            
            conn.commit()
            return vuln_id
        else:
            cursor.execute('''
                INSERT INTO vulnerabilities (tech_id, cve_id, cve_score, description, recommendation, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
            ''', (tech_id, cve_id, cve_score, description, recommendation, now, now))
            
            conn.commit()
            return cursor.lastrowid
    finally:
        conn.close()


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
        WHERE v.cve_score >= ?
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
    Get certificate expiry for a hostname.
    
    Args:
        cursor: Database cursor
        hostname: Hostname to check
    
    Returns:
        Dict with 'not_after', 'issuer', 'days_until_expiry' or None
    """
    cursor.execute('''
        SELECT not_after, issuer, 
               julianday(not_after) - julianday('now') as days_until_expiry
        FROM certificates
        WHERE hostname = ?
        ORDER BY not_after DESC
        LIMIT 1
    ''', (hostname,))
    
    row = cursor.fetchone()
    if row:
        return dict(row)
    return None


def get_all_assets_for_display() -> list:
    """
    Get all assets with technologies and CVEs for frontend display.
    
    Returns:
        List of asset dicts:
        [
            {
                'id': int,
                'name': str,
                'type': 'domain' | 'subdomain' | 'ip',
                'status': str,
                'is_scanned': bool,
                'ips': ['1.2.3.4', '5.6.7.8'],  # for domains/subdomains
                'technologies': [{'name': str, 'version': str}, ...],
                'findings': [{'port': str, 'service': str}, ...],  # for IPs
                'directories': [{'path': str, 'status': str}, ...],  # for hostnames
                'cves': [{'vuln_id': int, 'cve_id': str, 'cve_score': float, 'description': str, 'recommendation': str, 'tech_name': str}, ...]
            },
            ...
        ]
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    assets = []
    
    try:
        cursor.execute('''
            SELECT DISTINCT
                d.dom_id as id,
                d.domain_name as name,
                'domain' as type,
                d.status,
                d.last_scanned,
                CASE WHEN 
                    COUNT(p.port_id) > 0 
                    OR EXISTS(SELECT 1 FROM http_services h WHERE h.host = d.domain_name)
                THEN 1 ELSE 0 END as is_scanned
            FROM domain_asset d
            LEFT JOIN domain_ip di ON di.dom_id = d.dom_id
            LEFT JOIN ip_asset i ON i.ip_id = di.ip_id
            LEFT JOIN ports p ON p.ip_id = i.ip_id AND p.port_num IN (80, 443, 8080, 8443)
            GROUP BY d.dom_id
        ''')
        
        for row in cursor.fetchall():
            asset = dict(row)
            asset['is_scanned'] = bool(asset.get('is_scanned', 0))
            asset['ips'] = _get_ips_for_domain(cursor, asset['id'])
            asset['cert'] = _get_cert_expiry(cursor, asset['name'])
            asset['technologies'] = _get_technologies_for_host(cursor, asset['name']) if asset['is_scanned'] else []
            asset['cves'] = _get_cves_for_host(cursor, asset['name']) if asset['is_scanned'] else []
            asset['findings'] = _get_ports_for_domain(cursor, asset['id']) if asset['is_scanned'] else []
            asset['directories'] = _get_directories_for_host(cursor, asset['name']) if asset['is_scanned'] else []
            assets.append(asset)
        
        cursor.execute('''
            SELECT DISTINCT
                s.sub_id as id,
                s.subdomain_name as name,
                'subdomain' as type,
                s.status,
                s.last_scanned,
                CASE WHEN 
                    COUNT(p.port_id) > 0 
                    OR EXISTS(SELECT 1 FROM http_services h WHERE h.host = s.subdomain_name)
                THEN 1 ELSE 0 END as is_scanned
            FROM subdomain_asset s
            LEFT JOIN subdomain_ip si ON si.sub_id = s.sub_id
            LEFT JOIN ip_asset i ON i.ip_id = si.ip_id
            LEFT JOIN ports p ON p.ip_id = i.ip_id AND p.port_num IN (80, 443, 8080, 8443)
            GROUP BY s.sub_id
        ''')
        
        for row in cursor.fetchall():
            asset = dict(row)
            asset['is_scanned'] = bool(asset.get('is_scanned', 0))
            asset['ips'] = _get_ips_for_subdomain(cursor, asset['id'])
            asset['cert'] = _get_cert_expiry(cursor, asset['name'])
            asset['technologies'] = _get_technologies_for_host(cursor, asset['name']) if asset['is_scanned'] else []
            asset['cves'] = _get_cves_for_host(cursor, asset['name']) if asset['is_scanned'] else []
            asset['findings'] = _get_ports_for_subdomain(cursor, asset['id']) if asset['is_scanned'] else []
            asset['directories'] = _get_directories_for_host(cursor, asset['name']) if asset['is_scanned'] else []
            assets.append(asset)
        
        cursor.execute('''
            SELECT 
                i.ip_id as id,
                i.ip_value as name,
                'ip' as type,
                i.status,
                i.last_scanned,
                CASE WHEN 
                    COUNT(p.port_id) > 0 
                    OR EXISTS(SELECT 1 FROM http_services h WHERE h.ip_id = i.ip_id)
                THEN 1 ELSE 0 END as is_scanned
            FROM ip_asset i
            LEFT JOIN ports p ON p.ip_id = i.ip_id
            WHERE i.ip_id NOT IN (
                SELECT DISTINCT ip_id FROM domain_ip
                UNION
                SELECT DISTINCT ip_id FROM subdomain_ip
            )
            GROUP BY i.ip_id
        ''')
        
        for row in cursor.fetchall():
            asset = dict(row)
            asset['is_scanned'] = bool(asset.get('is_scanned', 0))
            asset['ips'] = [asset['name']]
            asset['technologies'] = []
            asset['cves'] = []
            asset['findings'] = _get_ports_for_ip(cursor, asset['id']) if asset['is_scanned'] else []
            assets.append(asset)
        
        return assets
    finally:
        conn.close()


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
        WHERE h.host = ?
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
            GROUP_CONCAT(DISTINCT h.port_num) as ports
        FROM vulnerabilities v
        INNER JOIN technologies t ON t.tech_id = v.tech_id
        INNER JOIN http_services h ON h.http_id = t.http_id
        WHERE h.host = ?
        GROUP BY v.cve_id
        ORDER BY MAX(v.cve_score) DESC
    ''', (host,))
    
    cves = []
    for row in cursor.fetchall():
        cve = dict(row)
        cve['cve_score'] = float(cve['cve_score']) if cve['cve_score'] else 0.0
        cve['description'] = cve['description'] or ''
        cve['recommendation'] = cve['recommendation'] or None
        cve['tech_name'] = cve['tech_name'] or ''
        cve['ports'] = cve['ports'] or ''
        cves.append(cve)
    
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
            (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), dom_id)
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
            (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sub_id)
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
            (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip_id)
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
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
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


def upsert_certificate(hostname: str, issuer: str = None, not_before: str = None, 
                       not_after: str = None, serial_number: str = None, 
                       fingerprint: str = None, sub_id: int = None, source: str = 'ctlogs') -> int:
    """
    Insert or update certificate record.
    
    Args:
        hostname: Hostname the cert is for
        issuer: Certificate issuer (e.g., "Let's Encrypt")
        not_before: Validity start date (ISO format)
        not_after: Expiry date (ISO format)
        serial_number: Certificate serial number
        fingerprint: Certificate fingerprint/hash
        sub_id: Subdomain ID (optional)
        source: Source of cert data ('ctlogs', 'ssl_scan')
    
    Returns:
        cert_id
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        cursor.execute('''
            SELECT cert_id FROM certificates 
            WHERE hostname = ? AND not_after = ?
        ''', (hostname, not_after))
        
        result = cursor.fetchone()
        
        if result:
            cert_id = result['cert_id']
            cursor.execute('''
                UPDATE certificates 
                SET issuer = ?, not_before = ?, serial_number = ?, fingerprint = ?, 
                    sub_id = ?, first_seen = ?
                WHERE cert_id = ?
            ''', (issuer, not_before, serial_number, fingerprint, sub_id, now, cert_id))
            conn.commit()
            return cert_id
        else:
            cursor.execute('''
                INSERT INTO certificates (hostname, issuer, not_before, not_after, serial_number, fingerprint, sub_id, source, first_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (hostname, issuer, not_before, not_after, serial_number, fingerprint, sub_id, source, now))
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"Error upserting certificate: {e}")
        return 0
    finally:
        conn.close()


def get_expiring_certificates(days: int = 30) -> list:
    """
    Get certificates expiring within specified days.
    
    Args:
        days: Number of days to look ahead (default: 30)
    
    Returns:
        List of certificate records with days_until_expiry
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT cert_id, hostname, issuer, not_after, 
                   julianday(not_after) - julianday('now') as days_until_expiry,
                   sub_id, source
            FROM certificates
            WHERE not_after IS NOT NULL
              AND julianday(not_after) - julianday('now') <= ?
              AND julianday(not_after) - julianday('now') > 0
            ORDER BY not_after ASC
        ''', (days,))
        
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_expired_certificates() -> list:
    """
    Get all expired certificates.
    
    Returns:
        List of expired certificate records
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT cert_id, hostname, issuer, not_after,
                   julianday('now') - julianday(not_after) as days_expired,
                   sub_id, source
            FROM certificates
            WHERE not_after IS NOT NULL
              AND julianday('now') > julianday(not_after)
            ORDER BY not_after DESC
        ''')
        
        return [dict(row) for row in cursor.fetchall()]
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


if __name__ == '__main__':
    print("Use InitDB.py to initialize database")