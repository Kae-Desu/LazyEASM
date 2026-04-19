"""
Phase 1 Runner - Execute full pipeline for one asset.

Pipeline:
    1. Port scan (nmap --top-ports 100)
    2. Wappalyzer (tech fingerprinting + http_services)
    3. CVE match (already integrated in Wappalyzer)
    4. Discord notification

Note: Dirsearch moved to Phase 2 (see modules/phase2_dirsearch.py)
"""

import logging
import importlib
from typing import Dict, List, Optional
from utils.db_utils import get_db_connection

logger = logging.getLogger(__name__)


def run_phase1(asset_id: int, asset_type: str, asset_name: str) -> Dict:
    """
    Execute Phase 1 pipeline for a single asset.
    
    Args:
        asset_id: Database ID (dom_id, sub_id, or ip_id)
        asset_type: 'domain', 'subdomain', or 'ip'
        asset_name: Hostname or IP address
    
    Returns:
        Dict with stats: {ports_found, tech_found, cve_found}
    """
    stats = {
        'ports_found': 0,
        'tech_found': 0,
        'cve_found': 0,
        'skipped_ips': 0,
        'skip_reasons': []
    }
    
    logger.info(f"Starting Phase 1 for {asset_name} ({asset_type})")
    
    # Get IPs for this asset
    ips = get_ips_for_asset(asset_id, asset_type)
    
    if not ips:
        logger.warning(f"No IPs found for {asset_name}")
        return stats
    
    # Filter out shared hosting and CDN IPs
    conn_filter = get_db_connection()
    cursor_filter = conn_filter.cursor()
    
    ips_to_scan = []
    for ip_info in ips:
        cursor_filter.execute('''
            SELECT is_shared, shared_provider 
            FROM ip_asset 
            WHERE ip_id = ?
        ''', (ip_info['ip_id'],))
        
        ip_data = cursor_filter.fetchone()
        
        if ip_data and ip_data['is_shared']:
            provider = ip_data['shared_provider'] or 'Unknown'
            reason = f"Shared hosting ({provider})"
            logger.info(f"Skipping shared hosting IP: {ip_info['ip_value']} - {reason}")
            stats['skipped_ips'] += 1
            stats['skip_reasons'].append((ip_info['ip_value'], reason))
            continue
        
        ips_to_scan.append(ip_info)
    
    conn_filter.close()
    
    # Log skipped IPs
    if stats['skipped_ips'] > 0:
        logger.info(f"Skipped {stats['skipped_ips']} shared/CDN IPs for port scanning")
        for ip, reason in stats['skip_reasons']:
            logger.info(f"  Skipped: {ip} - {reason}")
    
    # Port scan only if we have non-shared IPs
    if ips_to_scan:
        logger.info(f"Phase 1: Scanning {len(ips_to_scan)} IPs...")
    else:
        logger.info(f"No IPs to port scan for {asset_name} (all shared/CDN), continuing to web analysis...")
    
    # 1. Port scan on non-shared IPs
    if ips_to_scan:
        try:
            port_scanner_module = importlib.import_module('modules.02-port-scanner')
            scanner = port_scanner_module.PortScanner(cycle='initial', skip_down=False)
            
            port_nums_seen = set()
            
            for ip_info in ips_to_scan:
                try:
                    result = scanner.scan_single_ip(ip_info['ip_id'], ip_info['ip_value'])
                    if result.get('success'):
                        # Count unique port numbers only
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute('SELECT DISTINCT port_num FROM ports WHERE ip_id = ?', (ip_info['ip_id'],))
                        for row in cursor.fetchall():
                            port_nums_seen.add(row['port_num'])
                        conn.close()
                except Exception as e:
                    logger.error(f"Port scan failed for {ip_info['ip_value']}: {e}")
            
            stats['ports_found'] = len(port_nums_seen)
            logger.info(f"Port scan complete for {asset_name}: {stats['ports_found']} unique ports")
            
        except Exception as e:
            logger.error(f"Port scan failed for {asset_name}: {e}")
    
    # 2. Wappalyzer (tech fingerprinting + CVE)
    # Always run on hostname - works through Cloudflare/CDN proxy
    try:
        from modules.Wappalyzer import WappalyzerScanner
        
        wappalyzer = WappalyzerScanner(enable_cve=True, cvss_min=5.0)
        
        tech_found = 0
        unique_cves = set()
        
        # Always scan hostname on ports 80 and 443 (works through Cloudflare)
        for port in [80, 443]:
            is_https = 1 if port == 443 else 0
            
            try:
                result = wappalyzer.scan_target(
                    host=asset_name,
                    port=port,
                    ip_id=None,  # No IP association for Cloudflare/CDN sites
                    is_https=is_https
                )
                tech_found += len(result.get('technologies', []))
                for cve in result.get('cves', []):
                    unique_cves.add(cve['cve_id'])
            except Exception as e:
                logger.error(f"Wappalyzer failed for {asset_name}:{port} - {e}")
        
        stats['tech_found'] = tech_found
        stats['cve_found'] = len(unique_cves)
        logger.info(f"Wappalyzer complete for {asset_name}: {stats['tech_found']} techs, {stats['cve_found']} CVEs")
            
    except Exception as e:
        logger.error(f"Wappalyzer failed for {asset_name}: {e}")
    
    # 3. Discord notification
    try:
        from modules.Notify import send_message
        
        # Build notification based on scan results
        if stats['skipped_ips'] > 0 and not ips_to_scan:
            # All IPs were shared/CDN - port scan skipped entirely
            msg = (f"✅ **Phase 1 Complete**: {asset_name}\n"
                   f"━━━━━━━━━━━━━━━━━━\n"
                   f"**Port Scan:** Skipped\n"
                   f"**Technologies:** {stats['tech_found']}\n"
                   f"**CVEs:** {stats['cve_found']}\n"
                   f"\n**Skipped IPs ({stats['skipped_ips']}):**")
        elif stats['skipped_ips'] > 0:
            # Some IPs skipped, some scanned
            msg = (f"✅ **Phase 1 Complete**: {asset_name}\n"
                   f"━━━━━━━━━━━━━━━━━━\n"
                   f"**Ports:** {stats['ports_found']}\n"
                   f"**Technologies:** {stats['tech_found']}\n"
                   f"**CVEs:** {stats['cve_found']}\n"
                   f"\n**Skipped IPs ({stats['skipped_ips']}):**")
        else:
            # Normal scan, no skipped IPs
            msg = (f"✅ **Phase 1 Complete**: {asset_name}\n"
                   f"━━━━━━━━━━━━━━━━━━\n"
                   f"**Ports:** {stats['ports_found']}\n"
                   f"**Technologies:** {stats['tech_found']}\n"
                   f"**CVEs:** {stats['cve_found']}")
        
        # Add all skipped IPs (not just first 3)
        if stats['skipped_ips'] > 0:
            for ip, reason in stats['skip_reasons']:
                msg += f"\n  • {ip}: {reason}"
        
        send_message(msg)
        
    except Exception as e:
        logger.error(f"Discord notification failed: {e}")
    
    # 5. Update last_scanned timestamp
    try:
        from utils.db_utils import update_asset_last_scanned
        update_asset_last_scanned(asset_id, asset_type)
    except Exception as e:
        logger.error(f"Failed to update last_scanned: {e}")
    
    logger.info(f"Finished Phase 1 for {asset_name}: {stats}")
    return stats


def get_ips_for_asset(asset_id: int, asset_type: str) -> List[Dict]:
    """
    Get IPs linked to domain/subdomain.
    
    Args:
        asset_id: Database ID
        asset_type: 'domain', 'subdomain', or 'ip'
    
    Returns:
        List of dicts with ip_id and ip_value
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if asset_type == 'domain':
        cursor.execute('''
            SELECT DISTINCT i.ip_id, i.ip_value 
            FROM ip_asset i
            JOIN domain_ip di ON i.ip_id = di.ip_id
            WHERE di.dom_id = ?
        ''', (asset_id,))
    elif asset_type == 'subdomain':
        cursor.execute('''
            SELECT DISTINCT i.ip_id, i.ip_value 
            FROM ip_asset i
            JOIN subdomain_ip si ON i.ip_id = si.ip_id
            WHERE si.sub_id = ?
        ''', (asset_id,))
    else:
        # Direct IP
        cursor.execute('SELECT ip_id, ip_value FROM ip_asset WHERE ip_id = ?', (asset_id,))
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return results


def get_http_services_for_asset(asset_id: int, asset_type: str) -> List[Dict]:
    """
    Get HTTP services for asset.
    
    Args:
        asset_id: Database ID
        asset_type: 'domain', 'subdomain', or 'ip'
    
    Returns:
        List of dicts with host and port_num
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if asset_type == 'domain':
        cursor.execute('''
            SELECT DISTINCT host, port_num 
            FROM http_services
            WHERE host IN (SELECT domain_name FROM domain_asset WHERE dom_id = ?)
              AND port_num IN (80, 443)
        ''', (asset_id,))
    elif asset_type == 'subdomain':
        cursor.execute('''
            SELECT DISTINCT host, port_num 
            FROM http_services
            WHERE host IN (SELECT subdomain_name FROM subdomain_asset WHERE sub_id = ?)
              AND port_num IN (80, 443)
        ''', (asset_id,))
    else:
        cursor.execute('''
            SELECT DISTINCT host, port_num 
            FROM http_services 
            WHERE ip_id = ?
              AND port_num IN (80, 443)
        ''', (asset_id,))
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return results