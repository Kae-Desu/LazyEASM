"""
Phase 3 Worker - Background threads for continuous monitoring.

Orchestrates:
    - Liveness checker (every 5 minutes)
    - CT logs monitor (every 1 hour)

Exports:
    - start_phase3_workers()
    - stop_phase3_workers()
    - get_phase3_status()
"""

import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

# Global state
_phase3_running = False
_liveness_thread = None
_ctlogs_thread = None
_wappalyzer_thread = None


def send_liveness_notification(result: dict):
    """
    Send bundled Discord notification for liveness changes.
    
    Args:
        result: Dict from check_all_liveness()
    """
    try:
        from modules.Notify import send_message
        
        lines = ["**Phase 3: Liveness Status Update**", "━━━━━━━━━━━━━━━━━━━━━━━━━"]
        
        if result['down']:
            lines.append(f"🔴 **Down ({len(result['down'])}):**")
            for name in result['down'][:10]:  # Limit to 10
                lines.append(f"• {name}")
            if len(result['down']) > 10:
                lines.append(f"• ... and {len(result['down']) - 10} more")
        
        if result['recovered']:
            lines.append(f"🟢 **Recovered ({len(result['recovered'])}):**")
            for name in result['recovered'][:10]:
                lines.append(f"• {name}")
            if len(result['recovered']) > 10:
                lines.append(f"• ... and {len(result['recovered']) - 10} more")
        
        if result.get('new_up'):
            lines.append(f"✅ **New Assets Up ({len(result['new_up'])}):**")
            for name in result['new_up'][:10]:
                lines.append(f"• {name}")
            if len(result['new_up']) > 10:
                lines.append(f"• ... and {len(result['new_up']) - 10} more")
        
        if result.get('new_down'):
            lines.append(f"⚠️ **New Assets Down ({len(result['new_down'])}):**")
            for name in result['new_down'][:10]:
                lines.append(f"• {name}")
            if len(result['new_down']) > 10:
                lines.append(f"• ... and {len(result['new_down']) - 10} more")
        
        if result.get('still_down'):
            lines.append(f"⚫ **Still Down ({len(result['still_down'])}):**")
            for name in result['still_down'][:5]:
                lines.append(f"• {name}")
            if len(result['still_down']) > 5:
                lines.append(f"• ... and {len(result['still_down']) - 5} more")
        
        # Only send if there are actual changes
        has_changes = result['down'] or result['recovered'] or result.get('new_up') or result.get('new_down')
        if has_changes:
            send_message('\n'.join(lines))
        
    except Exception as e:
        logger.error(f"Failed to send liveness notification: {e}")


def send_ctlogs_notification(result: dict):
    """
    Send bundled Discord notification for CT logs discoveries.
    
    Args:
        result: Dict from poll_all_domains()
    """
    try:
        from modules.Notify import send_message, send_cert_expiry_threshold_alert
        from utils.db_utils import mark_cert_notified
        
        lines = ["**Phase 3: CT Logs Update**", "━━━━━━━━━━━━━━━━━━━━━━━━━"]
        
        if result['new_subdomains']:
            lines.append(f"\n**New Subdomains ({len(result['new_subdomains'])}):**")
            for domain, subdomain in result['new_subdomains'][:10]:
                lines.append(f"• {subdomain} (Phase 0 queued)")
            if len(result['new_subdomains']) > 10:
                lines.append(f"• ... and {len(result['new_subdomains']) - 10} more")
        
        if result.get('signature_changes'):
            lines.append(f"\n**Certificate Signature Changed ({len(result['signature_changes'])}):**")
            for change in result['signature_changes'][:5]:
                lines.append(f"• {change['hostname']}")
                old_serial = change.get('old_serial', 'N/A')
                new_serial = change.get('new_serial', 'N/A')
                if old_serial and new_serial and old_serial != 'N/A':
                    lines.append(f"  Serial: {old_serial[:16]}... → {new_serial[:16]}...")
            if len(result['signature_changes']) > 5:
                lines.append(f"• ... and {len(result['signature_changes']) - 5} more")
        
        if len(lines) > 2:
            send_message('\n'.join(lines))
        
        # Send cert expiry threshold alerts separately
        expiry_alerts = result.get('expiry_alerts', {})
        if any(expiry_alerts.values()):
            success, msg = send_cert_expiry_threshold_alert(expiry_alerts)
            logger.info(f"Cert expiry alert: {msg}")
            
            for threshold, certs in expiry_alerts.items():
                for cert in certs:
                    mark_cert_notified(cert['cert_id'], cert['hostname'], threshold)
    
    except Exception as e:
        logger.error(f"Failed to send CT logs notification: {e}")


def send_wappalyzer_notification(result: dict):
    """
    Send Discord notification for Wappalyzer re-scan results.
    
    Only sends if new CVEs were detected.
    
    Args:
        result: Dict from run_wappalyzer_scan()
    """
    try:
        from modules.Notify import send_message
        
        lines = [
            "**Phase 3: Wappalyzer Re-scan Complete**",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ]
        
        lines.append(f"\n**Hosts Scanned:** {result['hosts_scanned']}")
        lines.append(f"**Technologies Found:** {result['technologies_found']}")
        lines.append(f"**Total CVEs:** {result['cves_found']}")
        lines.append(f"**New CVEs:** {len(result['new_cves'])}")
        
        if result['new_cves']:
            lines.append(f"\n🔴 **New CVEs Detected:**")
            for cve in result['new_cves'][:10]:
                cvss_str = f" (CVSS {cve['cvss']})" if cve.get('cvss') else ""
                lines.append(f"• {cve['cve_id']}{cvss_str} on {cve['host']} ({cve['tech_name']})")
            if len(result['new_cves']) > 10:
                lines.append(f"• ... and {len(result['new_cves']) - 10} more")
        
        if result['errors']:
            lines.append(f"\n⚠️ **Errors ({len(result['errors'])}):**")
            for err in result['errors'][:3]:
                lines.append(f"• {err}")
            if len(result['errors']) > 3:
                lines.append(f"• ... and {len(result['errors']) - 3} more")
        
        send_message('\n'.join(lines))
    
    except Exception as e:
        logger.error(f"Failed to send Wappalyzer notification: {e}")


def liveness_loop(interval_min: int = 5):
    """
    Liveness checker loop.
    
    Runs every interval_min minutes if Phase 3 is enabled.
    
    Args:
        interval_min: Interval in minutes (default: 5)
    """
    global _phase3_running
    
    from utils.liveness_checker import check_all_liveness
    from utils.db_utils import get_setting
    
    logger.info("Liveness checker thread started")
    
    while _phase3_running:
        try:
            # Check if still enabled
            if get_setting('phase3_enabled') == '1':
                logger.info("Running liveness check...")
                result = check_all_liveness()
                
                # Send notification if any changes
                if result['down'] or result['recovered']:
                    send_liveness_notification(result)
            else:
                logger.debug("Phase 3 disabled, skipping liveness check")
        
        except Exception as e:
            logger.error(f"Liveness check error: {e}")
        
        # Sleep in small intervals to allow quick shutdown
        sleep_seconds = interval_min * 60
        elapsed = 0
        while elapsed < sleep_seconds and _phase3_running:
            time.sleep(5)
            elapsed += 5
    
    logger.info("Liveness checker thread stopped")


def ctlogs_loop(interval_hr: int = 1):
    """
    CT logs poller loop.
    
    Runs every interval_hr hours if Phase 3 is enabled.
    
    Args:
        interval_hr: Interval in hours (default: 1)
    """
    global _phase3_running
    
    from utils.ct_monitor import poll_all_domains
    from utils.db_utils import get_setting
    
    logger.info("CT logs monitor thread started")
    
    while _phase3_running:
        try:
            # Check if still enabled
            if get_setting('phase3_enabled') == '1':
                logger.info("Polling CT logs...")
                result = poll_all_domains()
                
                # Send notification if any discoveries
                has_alerts = result['new_subdomains'] or any(result.get('expiry_alerts', {}).values()) or result.get('signature_changes')
                if has_alerts:
                    send_ctlogs_notification(result)
            else:
                logger.debug("Phase 3 disabled, skipping CT logs poll")
        
        except Exception as e:
            logger.error(f"CT logs poll error: {e}")
        
        # Sleep in small intervals to allow quick shutdown
        sleep_seconds = interval_hr * 3600
        elapsed = 0
        while elapsed < sleep_seconds and _phase3_running:
            time.sleep(5)
            elapsed += 5
    
    logger.info("CT logs monitor thread stopped")


def wappalyzer_loop(interval_hr: int = 24):
    """
    Wappalyzer re-scan loop.
    
    Runs every interval_hr hours if Phase 3 is enabled.
    Scans hosts with HTTP services and status='up'.
    
    Args:
        interval_hr: Interval in hours (default: 24)
    """
    global _phase3_running
    
    from utils.wappalyzer_monitor import run_wappalyzer_scan
    from utils.db_utils import get_setting
    
    logger.info("Wappalyzer monitor thread started")
    
    while _phase3_running:
        try:
            if get_setting('phase3_enabled') == '1':
                logger.info("Running Wappalyzer re-scan...")
                result = run_wappalyzer_scan()
                
                if result.get('new_cves'):
                    send_wappalyzer_notification(result)
            else:
                logger.debug("Phase 3 disabled, skipping Wappalyzer scan")
        
        except Exception as e:
            logger.error(f"Wappalyzer scan error: {e}")
        
        # Sleep in small intervals to allow quick shutdown
        sleep_seconds = interval_hr * 3600
        elapsed = 0
        while elapsed < sleep_seconds and _phase3_running:
            time.sleep(5)
            elapsed += 5
    
    logger.info("Wappalyzer monitor thread stopped")


def start_phase3_workers():
    """
    Start all Phase 3 monitoring threads.
    
    Checks settings for enabled status and intervals.
    """
    global _phase3_running, _liveness_thread, _ctlogs_thread, _wappalyzer_thread
    
    from utils.db_utils import get_setting
    
    # Check if enabled
    if get_setting('phase3_enabled') != '1':
        logger.info("Phase 3 monitoring is disabled")
        return
    
    # Prevent duplicate threads
    if _phase3_running:
        logger.warning("Phase 3 workers already running")
        return
    
    _phase3_running = True
    
    # Get intervals
    liveness_interval = int(get_setting('liveness_interval_min') or '5')
    ctlogs_interval = int(get_setting('ctlogs_interval_hr') or '1')
    wappalyzer_interval = int(get_setting('wappalyzer_interval_hr') or '24')
    
    logger.info(f"Starting Phase 3 workers (liveness: {liveness_interval}min, ctlogs: {ctlogs_interval}hr, wappalyzer: {wappalyzer_interval}hr)")
    
    # Start liveness thread
    _liveness_thread = threading.Thread(
        target=liveness_loop,
        args=(liveness_interval,),
        daemon=True,
        name='Phase3-Liveness'
    )
    _liveness_thread.start()
    
    # Start CT logs thread
    _ctlogs_thread = threading.Thread(
        target=ctlogs_loop,
        args=(ctlogs_interval,),
        daemon=True,
        name='Phase3-CTLogs'
    )
    _ctlogs_thread.start()
    
    # Start Wappalyzer monitor thread
    _wappalyzer_thread = threading.Thread(
        target=wappalyzer_loop,
        args=(wappalyzer_interval,),
        daemon=True,
        name='Phase3-Wappalyzer'
    )
    _wappalyzer_thread.start()
    
    logger.info("Phase 3 workers started")


def stop_phase3_workers():
    """
    Stop all Phase 3 monitoring threads.
    """
    global _phase3_running
    
    logger.info("Stopping Phase 3 workers...")
    _phase3_running = False
    
    # Wait for threads to finish (max 10 seconds each)
    if _liveness_thread and _liveness_thread.is_alive():
        _liveness_thread.join(timeout=10)
    
    if _ctlogs_thread and _ctlogs_thread.is_alive():
        _ctlogs_thread.join(timeout=10)
    
    if _wappalyzer_thread and _wappalyzer_thread.is_alive():
        _wappalyzer_thread.join(timeout=10)
    
    logger.info("Phase 3 workers stopped")


def get_phase3_status() -> dict:
    """
    Get current Phase 3 status.
    
    Returns:
        {
            'running': bool,
            'enabled': bool,
            'last_liveness_check': str,
            'last_ctlogs_check': str,
            'liveness_interval_min': int,
            'ctlogs_interval_hr': int
        }
    """
    from utils.db_utils import get_setting
    
    return {
        'running': _phase3_running,
        'enabled': get_setting('phase3_enabled') == '1',
        'last_liveness_check': get_setting('last_liveness_check') or '-',
        'last_ctlogs_check': get_setting('last_ctlogs_check') or '-',
        'last_wappalyzer_check': get_setting('last_wappalyzer_check') or '-',
        'liveness_interval_min': int(get_setting('liveness_interval_min') or '5'),
        'ctlogs_interval_hr': int(get_setting('ctlogs_interval_hr') or '1'),
        'wappalyzer_interval_hr': int(get_setting('wappalyzer_interval_hr') or '24')
    }


if __name__ == '__main__':
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Phase 3 Worker')
    parser.add_argument('--start', action='store_true', help='Start workers (foreground)')
    parser.add_argument('--status', action='store_true', help='Get status')
    
    args = parser.parse_args()
    
    if args.start:
        print("Starting Phase 3 workers (press Ctrl+C to stop)...")
        start_phase3_workers()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
            stop_phase3_workers()
    elif args.status:
        status = get_phase3_status()
        print(f"Running: {status['running']}")
        print(f"Enabled: {status['enabled']}")
        print(f"Last liveness check: {status['last_liveness_check']}")
        print(f"Last CT logs check: {status['last_ctlogs_check']}")
    else:
        parser.print_help()