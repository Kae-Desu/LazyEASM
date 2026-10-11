"""
Wappalyzer Monitor - Periodic tech stack re-scanning for Phase 3.

Runs every 24 hours on hosts with HTTP services and status='up'.
Updates technologies and CVEs in database.

Exports:
    - get_hosts_for_wappalyzer() -> list
    - run_wappalyzer_scan() -> dict
"""

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.db_utils import get_db_connection, set_setting

logger = logging.getLogger(__name__)


def _update_wappalyzer_timestamp(host: str, timestamp: str) -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'UPDATE domain_asset SET last_wappalyzer_scan = ? WHERE domain_name = ?',
            (timestamp, host)
        )
        if cursor.rowcount == 0:
            cursor.execute(
                'UPDATE subdomain_asset SET last_wappalyzer_scan = ? WHERE subdomain_name = ?',
                (timestamp, host)
            )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to update last_wappalyzer_scan for {host}: {e}")
    finally:
        conn.close()


def get_hosts_for_wappalyzer() -> list:
    """
    Get distinct hostnames that have HTTP services and status='up'.

    Returns:
        List of dicts: [{host: str, ports: [int]}, ...]
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    hosts = {}

    cursor.execute('''
        SELECT DISTINCT s.subdomain_name, h.port_num, h.is_https
        FROM http_services h
        JOIN subdomain_asset s ON s.subdomain_name = h.host
        WHERE s.status = 'up'
    ''')
    for row in cursor.fetchall():
        host = row['subdomain_name']
        if host not in hosts:
            hosts[host] = {'host': host, 'ports': []}
        hosts[host]['ports'].append({
            'port_num': row['port_num'],
            'is_https': row['is_https']
        })

    cursor.execute('''
        SELECT DISTINCT d.domain_name, h.port_num, h.is_https
        FROM http_services h
        JOIN domain_asset d ON d.domain_name = h.host
        WHERE d.status = 'up'
    ''')
    for row in cursor.fetchall():
        host = row['domain_name']
        if host not in hosts:
            hosts[host] = {'host': host, 'ports': []}
        hosts[host]['ports'].append({
            'port_num': row['port_num'],
            'is_https': row['is_https']
        })

    conn.close()

    return list(hosts.values())


def run_wappalyzer_scan() -> dict:
    """
    Run Wappalyzer re-scan on all up hosts with HTTP services.

    Returns:
        {
            'hosts_scanned': int,
            'technologies_found': int,
            'cves_found': int,
            'new_cves': [{'cve_id': str, 'cvss': float, 'host': str, 'tech_name': str}, ...],
            'errors': [str, ...]
        }
    """
    from datetime import datetime, timezone
    from modules.Wappalyzer import WappalyzerScanner

    hosts = get_hosts_for_wappalyzer()

    if not hosts:
        logger.info("No hosts with HTTP services to scan")
        set_setting('last_wappalyzer_check',
                     datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
        return {
            'hosts_scanned': 0,
            'technologies_found': 0,
            'cves_found': 0,
            'new_cves': [],
            'errors': []
        }

    logger.info(f"Starting Wappalyzer re-scan for {len(hosts)} hosts")

    conn = get_db_connection()
    cursor = conn.cursor()

    existing_cves = set()
    cursor.execute('SELECT cve_id FROM vulnerabilities')
    for row in cursor.fetchall():
        existing_cves.add(row['cve_id'])
    conn.close()

    scanner = WappalyzerScanner(enable_cve=True, cvss_min=5.0)

    result = {
        'hosts_scanned': 0,
        'technologies_found': 0,
        'cves_found': 0,
        'new_cves': [],
        'errors': []
    }

    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    for host_info in hosts:
        host = host_info['host']
        ports = host_info['ports']
        host_scan_success = False

        if not ports:
            ports = [
                {'port_num': 80, 'is_https': 0},
                {'port_num': 443, 'is_https': 1}
            ]

        for port_info in ports:
            port = port_info['port_num']
            is_https = port_info['is_https']

            try:
                scan_result = scanner.scan_target(
                    host=host,
                    port=port,
                    ip_id=None,
                    is_https=is_https
                )

                if scan_result.get('success', False):
                    host_scan_success = True
                    result['hosts_scanned'] += 1
                    result['technologies_found'] += len(scan_result.get('technologies', []))

                    for cve in scan_result.get('cves', []):
                        result['cves_found'] += 1

                        if cve['cve_id'] not in existing_cves:
                            existing_cves.add(cve['cve_id'])
                            result['new_cves'].append({
                                'cve_id': cve['cve_id'],
                                'cvss': cve.get('cvss', 0),
                                'host': host,
                                'tech_name': cve.get('tech_name', '')
                            })
                else:
                    error = scan_result.get('error_info', {})
                    error_msg = error.get('error_category', 'unknown') if error else 'unknown'
                    result['errors'].append(f"{host}:{port} ({error_msg})")

            except Exception as e:
                logger.error(f"Wappalyzer scan failed for {host}:{port} - {e}")
                result['errors'].append(f"{host}:{port} (exception: {str(e)[:80]})")

        if host_scan_success:
            _update_wappalyzer_timestamp(host, now_str)

    set_setting('last_wappalyzer_check', now_str)

    logger.info(
        f"Wappalyzer re-scan complete: "
        f"{result['hosts_scanned']} hosts, "
        f"{result['technologies_found']} techs, "
        f"{result['cves_found']} CVEs, "
        f"{len(result['new_cves'])} new CVEs"
    )

    return result


if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Wappalyzer Monitor')
    parser.add_argument('--scan', action='store_true', help='Run Wappalyzer re-scan')
    parser.add_argument('--list-hosts', action='store_true', help='List hosts with HTTP services')

    args = parser.parse_args()

    if args.list_hosts:
        hosts = get_hosts_for_wappalyzer()
        for h in hosts:
            print(f"  {h['host']}: ports {[p['port_num'] for p in h['ports']]}")
        print(f"Total: {len(hosts)} hosts")
    elif args.scan:
        result = run_wappalyzer_scan()
        print(f"Hosts scanned: {result['hosts_scanned']}")
        print(f"Technologies found: {result['technologies_found']}")
        print(f"CVEs found: {result['cves_found']}")
        print(f"New CVEs: {len(result['new_cves'])}")
        if result['new_cves']:
            print("\nNew CVEs:")
            for cve in result['new_cves']:
                print(f"  {cve['cve_id']} (CVSS {cve['cvss']}) on {cve['host']} ({cve['tech_name']})")
        if result['errors']:
            print(f"\nErrors ({len(result['errors'])}):")
            for err in result['errors'][:5]:
                print(f"  {err}")
    else:
        parser.print_help()