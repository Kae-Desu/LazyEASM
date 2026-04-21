"""
Phase 2 - Full Port Scan + Directory Enumeration

Runs every 2 days at midnight via cron.

Pipeline per asset:
    1. Check last_dirsearch timestamp (skip if < 48 hours)
    2. Get asset details (IPs, hostnames)
    3. Skip nmap if CDN/Shared hosting
    4. Run parallel: nmap (-p- -sV -T2) + dirsearch (3 threads)
    5. Save results (append mode)
    6. Send Discord notification
    7. Update last_dirsearch
    8. Move to next asset
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import importlib
import requests

logger = logging.getLogger(__name__)


def get_assets_for_phase2() -> List[Dict]:
    """
    Get all assets eligible for Phase 2 scan.
    
    Returns ALL assets with http_services (status_code = 200).
    Cron handles the 2-day scheduling.
    
    Returns:
        List of assets with http_services
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get subdomains with http_services
    cursor.execute('''
        SELECT DISTINCT
            sa.sub_id as asset_id,
            'subdomain' as asset_type,
            sa.subdomain_name as name
        FROM subdomain_asset sa
        INNER JOIN http_services hs ON hs.host = sa.subdomain_name
        WHERE hs.status_code = 200
        ORDER BY sa.sub_id
    ''')
    
    subdomains = [dict(row) for row in cursor.fetchall()]
    
    # Get domains with http_services
    cursor.execute('''
        SELECT DISTINCT
            da.dom_id as asset_id,
            'domain' as asset_type,
            da.domain_name as name
        FROM domain_asset da
        INNER JOIN http_services hs ON hs.host = da.domain_name
        WHERE hs.status_code = 200
        ORDER BY da.dom_id
    ''')
    
    domains = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    all_assets = subdomains + domains
    logger.info(f"Found {len(all_assets)} assets for Phase 2 scan")
    
    return all_assets


def get_asset_ips(asset_id: int, asset_type: str) -> List[Dict]:
    """
    Get IPs for an asset.
    
    Args:
        asset_id: Database ID
        asset_type: 'domain' or 'subdomain'
    
    Returns:
        List of dicts with ip_id, ip_value, is_shared, shared_provider
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if asset_type == 'domain':
        cursor.execute('''
            SELECT DISTINCT i.ip_id, i.ip_value, i.is_shared, i.shared_provider
            FROM ip_asset i
            INNER JOIN domain_ip di ON di.ip_id = i.ip_id
            WHERE di.dom_id = ?
        ''', (asset_id,))
    else:
        cursor.execute('''
            SELECT DISTINCT i.ip_id, i.ip_value, i.is_shared, i.shared_provider
            FROM ip_asset i
            INNER JOIN subdomain_ip si ON si.ip_id = i.ip_id
            WHERE si.sub_id = ?
        ''', (asset_id,))
    
    ips = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return ips


def should_skip_nmap(ip_value: str, is_shared: int, shared_provider: str = '') -> Tuple[bool, str]:
    """
    Check if nmap should be skipped for this IP.
    
    Args:
        ip_value: IP address
        is_shared: Whether IP is shared hosting
        shared_provider: Provider name (e.g., 'Cloudflare')
    
    Returns:
        (skip_nmap, reason)
    """
    if is_shared:
        return True, f"Shared hosting ({shared_provider or 'Unknown'})"
    
    if shared_provider and 'cloudflare' in shared_provider.lower():
        return True, "CDN (Cloudflare)"
    
    return False, ''


def run_full_nmap(ip_id: int, ip_value: str) -> Dict:
    """
    Run nmap full port scan on IP.
    
    Args:
        ip_id: Database IP ID
        ip_value: IP address
    
    Returns:
        Dict with 'success', 'ports_found', 'services_found', 'error'
    """
    try:
        port_scanner_module = importlib.import_module('modules.02-port-scanner')
        scanner = port_scanner_module.PortScanner(cycle='long', skip_down=False)
        
        result = scanner.scan_full_ports(ip_id, ip_value)
        
        return {
            'success': result.get('success', False),
            'ports_found': result.get('ports_found', 0),
            'services_found': result.get('services_found', []),
            'skipped': result.get('skipped', False),
            'reason': result.get('reason'),
            'error': result.get('error')
        }
    except Exception as e:
        logger.error(f"Full nmap failed for {ip_value}: {e}")
        return {
            'success': False,
            'ports_found': 0,
            'services_found': [],
            'skipped': False,
            'reason': None,
            'error': str(e)
        }


def detect_http_port(host: str, port: int = 80, timeout: int = 5) -> Dict:
    """
    Quick HTTP check to detect redirect to HTTPS.
    
    Args:
        host: Hostname
        port: Port to check (default: 80)
        timeout: Request timeout in seconds
    
    Returns:
        Dict with 'use_https', 'redirect_url', 'status'
    """
    try:
        url = f"http://{host}:{port}"
        resp = requests.head(url, timeout=timeout, allow_redirects=False, verify=False)
        
        if resp.status_code in [301, 302, 307, 308]:
            location = resp.headers.get('Location', '')
            if 'https://' in location.lower():
                return {'use_https': True, 'redirect_url': location, 'status': resp.status_code}
        
        return {'use_https': False, 'status': resp.status_code}
    except Exception as e:
        logger.debug(f"HTTP check failed for {host}:{port}: {e}")
        return {'use_https': False, 'status': 0}


def run_dirsearch_limited(asset_name: str, ports: Optional[List[int]] = None) -> Dict:
    """
    Run dirsearch with limited threads (3).
    
    Pre-flight: Detects if port 80 redirects to HTTPS.
    If redirect to HTTPS detected, scans port 443 only.
    If port 80 returns 200, scans port 80 only.
    Otherwise scans both ports.
    
    Args:
        asset_name: Hostname
        ports: List of ports (default: [80, 443])
    
    Returns:
        Dict with 'success', 'directories_found', 'error'
    """
    if ports is None:
        ports = [80, 443]
    
    try:
        dirsearch_module = importlib.import_module('modules.05-dirsearch')
        
        # Pre-flight: check if port 80 redirects to HTTPS
        if 80 in ports and 443 in ports:
            redirect_check = detect_http_port(asset_name, port=80)
            if redirect_check.get('use_https'):
                logger.info(f"{asset_name}:80 redirects to HTTPS, using port 443 only")
                ports = [443]
            elif redirect_check.get('status') == 200:
                logger.info(f"{asset_name}:80 returns 200, using port 80 only")
                ports = [80]
            else:
                logger.debug(f"{asset_name}:80 status {redirect_check.get('status')}, scanning both ports")
        
        total_dirs = 0
        
        for port in ports:
            result = dirsearch_module.run_dirsearch(
                asset_id=0,
                host=asset_name,
                port=port,
                threads=25,
                recursive=False,
                timeout=None
            )
            
            if result:
                total_dirs += len(result)
        
        return {
            'success': True,
            'directories_found': total_dirs,
            'error': None
        }
    except Exception as e:
        logger.error(f"Dirsearch failed for {asset_name}: {e}")
        return {
            'success': False,
            'directories_found': 0,
            'error': str(e)
        }


def update_last_dirsearch(asset_id: int, asset_type: str):
    """
    Update last_dirsearch timestamp for asset.
    
    Args:
        asset_id: Database ID
        asset_type: 'domain' or 'subdomain'
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if asset_type == 'domain':
        cursor.execute('UPDATE domain_asset SET last_dirsearch = ? WHERE dom_id = ?', (timestamp, asset_id))
    else:
        cursor.execute('UPDATE subdomain_asset SET last_dirsearch = ? WHERE sub_id = ?', (timestamp, asset_id))
    
    conn.commit()
    conn.close()


def send_asset_notification(asset: Dict, nmap_result: Dict, dirsearch_result: Dict):
    """
    Send Discord notification per asset.
    
    Args:
        asset: Asset dict with 'name', 'asset_type'
        nmap_result: Result from nmap scan
        dirsearch_result: Result from dirsearch
    """
    try:
        from modules.Notify import send_message
        
        name = asset.get('name', 'Unknown')
        
        # Build message
        msg = f"**Phase 2 Complete**: {name}\n"
        msg += "━━━━━━━━━━━━━━━━━━\n"
        
        # Nmap results
        if nmap_result.get('skipped'):
            msg += f"**Nmap:** Skipped ({nmap_result.get('reason', 'CDN/Shared')})\n"
        elif nmap_result.get('success'):
            ports = nmap_result.get('ports_found', 0)
            services = len(nmap_result.get('services_found', []))
            msg += f"**Ports:** {ports}\n"
            msg += f"**Services:** {services}\n"
        else:
            msg += f"**Nmap:** Failed ({nmap_result.get('error', 'Unknown')})\n"
        
        # Dirsearch results
        if dirsearch_result.get('success'):
            dirs = dirsearch_result.get('directories_found', 0)
            msg += f"**Directories:** {dirs}\n"
        else:
            msg += f"**Dirsearch:** Failed ({dirsearch_result.get('error', 'Unknown')})\n"
        
        send_message(msg)
        
    except Exception as e:
        logger.error(f"Discord notification failed: {e}")


def save_results(asset: Dict, nmap_result: Dict, dirsearch_result: Dict):
    """
    Save results to database (append mode).
    
    Args:
        asset: Asset dict
        nmap_result: Nmap scan result
        dirsearch_result: Dirsearch result
    """
    # Nmap results already saved in scan_full_ports()
    # Dirsearch results already saved in run_dirsearch()
    # Just need to update timestamp
    
    update_last_dirsearch(asset['asset_id'], asset['asset_type'])


def run_phase2_asset(asset: Dict) -> Dict:
    """
    Run Phase 2 on a single asset.
    
    Parallel execution:
        - Thread 1: nmap full scan (if not CDN)
        - Thread 2: dirsearch (3 threads)
    
    Wait for both, save partial results, notify.
    
    Args:
        asset: Dict with asset_id, asset_type, name
    
    Returns:
        Dict with 'asset', 'nmap', 'dirsearch'
    """
    name = asset.get('name', 'Unknown')
    logger.info(f"Starting Phase 2 for {name}")
    
    # Get IPs for asset
    ips = get_asset_ips(asset['asset_id'], asset['asset_type'])
    
    # Check if we should skip nmap
    skip_nmap = True
    skip_reason = "No IPs"
    
    if ips:
        for ip_info in ips:
            ip_value = ip_info.get('ip_value', '')
            is_shared = ip_info.get('is_shared', 0) or 0
            shared_provider = ip_info.get('shared_provider', '') or ''
            
            skip, reason = should_skip_nmap(ip_value, is_shared, shared_provider)
            
            if not skip:
                skip_nmap = False
                skip_reason = None
                break
            else:
                skip_reason = reason
    
    nmap_result = {'success': False, 'ports_found': 0, 'services_found': [], 'skipped': skip_nmap, 'reason': skip_reason}
    dirsearch_result = {'success': False, 'directories_found': 0, 'error': None}
    
    # Run parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        if skip_nmap:
            # Only run dirsearch
            logger.info(f"Skipping nmap for {name}: {skip_reason}")
            dirsearch_future = executor.submit(run_dirsearch_limited, name)
            
            dirsearch_result = dirsearch_future.result()
        else:
            # Run both in parallel
            nmap_future = executor.submit(run_full_nmap, ips[0]['ip_id'], ips[0]['ip_value'])
            dirsearch_future = executor.submit(run_dirsearch_limited, name)
            
            nmap_result = nmap_future.result()
            dirsearch_result = dirsearch_future.result()
    
    # Save results
    save_results(asset, nmap_result, dirsearch_result)
    
    # Notify
    send_asset_notification(asset, nmap_result, dirsearch_result)
    
    logger.info(f"Finished Phase 2 for {name}: ports={nmap_result.get('ports_found', 0)}, dirs={dirsearch_result.get('directories_found', 0)}")
    
    return {
        'asset': name,
        'nmap': nmap_result,
        'dirsearch': dirsearch_result
    }


def run_phase2_daily():
    """
    Main entry point for Phase 2.
    
    Called by cron every 2 days at midnight.
    Handles running Phase 0/1 gracefully.
    """
    from utils.phase_lock import set_phase, clear_phase, PHASE_2_RUNNING, update_phase2_progress
    from utils.process_utils import find_phase0_processes, kill_phase1_processes, wait_for_phase0_completion
    from utils.db_utils import clear_phase1_queue
    
    logger.info("=" * 60)
    logger.info("Starting Phase 2")
    logger.info("=" * 60)
    
    # Get all assets with http_services
    assets = get_assets_for_phase2()
    
    if not assets:
        logger.info("No assets found for Phase 2 scan")
        return
    
    # Set Phase 2 lock
    set_phase(PHASE_2_RUNNING, total_assets=len(assets))
    
    # Send Discord: Phase 2 started
    try:
        from modules.Notify import send_message
        send_message(f"**Phase 2 Started**\nScanning {len(assets)} assets with full port enumeration and directory discovery.")
    except Exception as e:
        logger.error(f"Discord notification failed: {e}")
    
    try:
        # Check for Phase 0
        phase0_procs = find_phase0_processes()
        if phase0_procs:
            logger.info(f"Phase 0 running ({len(phase0_procs)} processes), waiting...")
            try:
                from modules.Notify import send_message
                send_message(f"Phase 0 running ({len(phase0_procs)} processes), waiting for completion...")
            except:
                pass
            wait_for_phase0_completion()  # Wait forever
        
        # Kill Phase 1
        killed = kill_phase1_processes()
        if killed:
            logger.info(f"Killed {len(killed)} Phase 1 processes")
            try:
                from modules.Notify import send_message
                send_message(f"Killed {len(killed)} Phase 1 processes to start Phase 2.")
            except:
                pass
            clear_phase1_queue()
        
        # Run Phase 2
        logger.info(f"Running Phase 2 on {len(assets)} assets")
        
        # Process one at a time
        results = []
        for i, asset in enumerate(assets):
            logger.info(f"Processing asset {i+1}/{len(assets)}: {asset['name']}")
            
            # Update progress
            update_phase2_progress(processed=i)
            
            try:
                result = run_phase2_asset(asset)
                results.append(result)
                
                # Send progress notification every 10 assets
                if (i + 1) % 10 == 0:
                    try:
                        from modules.Notify import send_message
                        percent = int((i + 1) / len(assets) * 100)
                        send_message(f"Phase 2 progress: {i+1}/{len(assets)} assets ({percent}%)")
                    except:
                        pass
                        
            except Exception as e:
                logger.error(f"Phase 2 failed for {asset['name']}: {e}")
        
        # Send completion notification
        total_ports = sum(r.get('nmap', {}).get('ports_found', 0) for r in results)
        total_dirs = sum(r.get('dirsearch', {}).get('directories_found', 0) for r in results)
        
        try:
            from modules.Notify import send_message
            send_message(
                f"**Phase 2 Complete**\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"Assets scanned: {len(results)}\n"
                f"Total ports: {total_ports}\n"
                f"Total directories: {total_dirs}"
            )
        except Exception as e:
            logger.error(f"Discord notification failed: {e}")
        
        logger.info("=" * 60)
        logger.info(f"Phase 2 complete: {len(results)} assets processed")
        logger.info("=" * 60)
    
    finally:
        # Always clear phase lock
        clear_phase()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    run_phase2_daily()