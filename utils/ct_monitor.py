"""
CT Logs Monitor - Poll crt.sh for new certificates/subdomains.

Phase 3 continuous monitoring component.
Runs every 1 hour to check for new subdomains and certificate expiry.

Exports:
    - poll_all_domains() -> dict summary for notification
"""

import logging
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Set

logger = logging.getLogger(__name__)

CTLOGS_URL = "https://crt.sh/json?q={domain}"


def fetch_ctlogs(domain: str) -> tuple:
    """
    Fetch CT logs from crt.sh for a domain.
    
    Reuses logic from modules/03-asset-expansion.py.
    
    Args:
        domain: Root domain (e.g., 'example.com')
    
    Returns:
        (subdomains list, certificates list)
    """
    url = CTLOGS_URL.format(domain=domain)
    domain_lower = domain.lower()
    subdomains = set()
    certificates = []
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    # Common name
                    if 'common_name' in entry:
                        cn = entry['common_name'].lower()
                        if cn.endswith(domain_lower) or cn == domain_lower:
                            subdomains.add(cn)
                    
                    # Subject Alternative Names
                    if 'name_value' in entry:
                        for name in entry['name_value'].split('\n'):
                            name = name.strip().lower()
                            if name.endswith(domain_lower) or name == domain_lower:
                                subdomains.add(name)
                    
                    # Certificate info
                    hostname = entry.get('common_name', '').lower()
                    not_after = entry.get('not_after')
                    
                    if hostname and not_after:
                        if hostname.endswith(domain_lower) or hostname == domain_lower:
                            certificates.append({
                                'hostname': hostname,
                                'issuer': entry.get('issuer_name', ''),
                                'not_before': entry.get('not_before'),
                                'not_after': not_after,
                                'serial_number': entry.get('serial_number')
                            })
                
                break
            
            elif response.status_code == 503:
                logger.warning(f"crt.sh returned 503 for {domain}, retrying...")
                time.sleep(2 ** attempt)
            else:
                logger.warning(f"crt.sh returned {response.status_code} for {domain}")
                break
        
        except requests.exceptions.Timeout:
            logger.warning(f"crt.sh timeout for {domain} (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            logger.error(f"crt.sh request error for {domain}: {e}")
            break
    
    return list(subdomains), certificates


def get_expiring_certs(days_threshold: int = 3) -> List[Dict]:
    """
    Get certificates expiring within threshold.
    
    Args:
        days_threshold: Days until expiry (default: 3)
    
    Returns:
        List of {'hostname': str, 'days_remaining': int}
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now()
    threshold = now + timedelta(days=days_threshold)
    threshold_str = threshold.strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        SELECT hostname, not_after
        FROM certificates
        WHERE datetime(not_after) <= datetime(?)
        ORDER BY not_after ASC
    ''', (threshold_str,))
    
    expiring = []
    for row in cursor.fetchall():
        try:
            not_after = datetime.strptime(row['not_after'], '%Y-%m-%d %H:%M:%S')
            days_remaining = (not_after - now).days
            
            if days_remaining >= 0:
                expiring.append({
                    'hostname': row['hostname'],
                    'days_remaining': days_remaining
                })
        except Exception:
            continue
    
    conn.close()
    return expiring


def check_cert_signature_changes(certificates: List[Dict]) -> List[Dict]:
    """
    Check for certificate signature changes by comparing with DB.
    
    Args:
        certificates: List of certificates from CT logs
    
    Returns:
        List of signature changes [{'hostname', 'old_serial', 'new_serial', 'not_after'}, ...]
    """
    from utils.db_utils import get_db_connection
    
    signature_changes = []
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for cert in certificates:
        hostname = cert.get('hostname', '')
        not_after = cert.get('not_after', '')
        new_serial = cert.get('serial_number', '')
        
        if not hostname or not not_after:
            continue
        
        # Find existing cert in DB with same hostname and not_after
        cursor.execute('''
            SELECT serial_number, fingerprint FROM certificates 
            WHERE hostname = ? AND not_after = ?
        ''', (hostname, not_after))
        
        existing = cursor.fetchone()
        
        if existing:
            old_serial = existing['serial_number']
            old_fingerprint = existing['fingerprint']
            new_fingerprint = cert.get('fingerprint', '')
            
            # Check if signature changed
            if old_serial and new_serial and old_serial != new_serial:
                signature_changes.append({
                    'hostname': hostname,
                    'old_serial': old_serial,
                    'new_serial': new_serial,
                    'not_after': not_after
                })
                logger.info(f"Certificate signature changed for {hostname}: {old_serial[:16]}... -> {new_serial[:16]}...")
            elif old_fingerprint and new_fingerprint and old_fingerprint != new_fingerprint:
                signature_changes.append({
                    'hostname': hostname,
                    'old_serial': old_serial or 'N/A',
                    'new_serial': new_serial or 'N/A',
                    'not_after': not_after
                })
                logger.info(f"Certificate fingerprint changed for {hostname}")
    
    conn.close()
    return signature_changes


def poll_all_domains() -> Dict:
    """
    Poll all monitored domains for new subdomains, cert expiry, and signature changes.
    
    Returns:
        {
            'new_subdomains': [(domain, subdomain), ...],
            'cert_expiring': [(hostname, days_remaining), ...],
            'signature_changes': [{'hostname', 'old_serial', 'new_serial'}, ...]
        }
    """
    from utils.db_utils import (
        get_all_monitored_domains,
        get_known_subdomains,
        queue_subdomain_discovery,
        set_setting
    )
    
    domains = get_all_monitored_domains()
    
    if not domains:
        logger.info("No domains to monitor")
        return {'new_subdomains': [], 'cert_expiring': [], 'signature_changes': []}
    
    logger.info(f"Polling CT logs for {len(domains)} domains")
    
    known_subdomains = get_known_subdomains()
    new_subdomains = []
    all_certificates = []
    
    for domain in domains:
        logger.debug(f"Fetching CT logs for {domain}")
        
        subdomains, certificates = fetch_ctlogs(domain)
        all_certificates.extend(certificates)
        
        # Find new subdomains
        for subdomain in subdomains:
            # Skip wildcards (*.example.com)
            if subdomain.startswith('*.'):
                logger.debug(f"Skipping wildcard: {subdomain}")
                continue
            
            # Skip if it's the root domain itself
            if subdomain == domain:
                logger.debug(f"Skipping root domain: {subdomain}")
                continue
            
            if subdomain not in known_subdomains:
                # Queue for Phase 0
                queue_subdomain_discovery(subdomain, domain)
                new_subdomains.append((domain, subdomain))
                known_subdomains.add(subdomain)  # Avoid duplicates
        
        time.sleep(1)  # Rate limiting
    
    # Check certificate expiry
    expiring_certs = get_expiring_certs(days_threshold=3)
    
    # Check certificate signature changes
    signature_changes = check_cert_signature_changes(all_certificates)
    
    # Update last check timestamp
    set_setting('last_ctlogs_check', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    logger.info(
        f"CT logs poll complete: "
        f"{len(new_subdomains)} new subdomains, "
        f"{len(expiring_certs)} certs expiring, "
        f"{len(signature_changes)} signature changes"
    )
    
    return {
        'new_subdomains': new_subdomains,
        'cert_expiring': expiring_certs,
        'signature_changes': signature_changes
    }


def get_cert_expiry_summary() -> Dict:
    """
    Get summary of certificate expiry status.
    
    Returns:
        {
            'expiring_3_days': int,
            'expiring_7_days': int,
            'expiring_30_days': int,
            'total_certs': int
        }
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now()
    
    cursor.execute('SELECT COUNT(*) as count FROM certificates')
    total = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT COUNT(*) as count FROM certificates
        WHERE datetime(not_after) <= datetime(?)
    ''', ((now + timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S'),))
    expiring_3_days = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT COUNT(*) as count FROM certificates
        WHERE datetime(not_after) <= datetime(?)
    ''', ((now + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S'),))
    expiring_7_days = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT COUNT(*) as count FROM certificates
        WHERE datetime(not_after) <= datetime(?)
    ''', ((now + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S'),))
    expiring_30_days = cursor.fetchone()['count']
    
    conn.close()
    
    return {
        'total_certs': total,
        'expiring_3_days': expiring_3_days,
        'expiring_7_days': expiring_7_days,
        'expiring_30_days': expiring_30_days
    }


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description='CT Logs monitor')
    parser.add_argument('--poll', action='store_true', help='Poll all domains')
    parser.add_argument('--check-expiry', action='store_true', help='Check certificate expiry')
    parser.add_argument('--summary', action='store_true', help='Get cert expiry summary')
    
    args = parser.parse_args()
    
    if args.poll:
        result = poll_all_domains()
        print(f"New subdomains: {result['new_subdomains']}")
        print(f"Certs expiring: {result['cert_expiring']}")
    elif args.check_expiry:
        expiring = get_expiring_certs()
        for cert in expiring:
            print(f"{cert['hostname']}: {cert['days_remaining']} days remaining")
    elif args.summary:
        summary = get_cert_expiry_summary()
        print(f"Total certs: {summary['total_certs']}")
        print(f"Expiring in 3 days: {summary['expiring_3_days']}")
        print(f"Expiring in 7 days: {summary['expiring_7_days']}")
        print(f"Expiring in 30 days: {summary['expiring_30_days']}")
    else:
        parser.print_help()