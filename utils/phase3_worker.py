"""
Phase 3 Worker - Background threads for continuous monitoring.

Orchestrates:
    - Liveness checker (every 5 minutes)
    - CT logs monitor (every 1 hour)
    - Wappalyzer re-scan (every 24 hours)
    - Subdomain takeover check (every 24 hours)
    - Exploit intel refresh: CISA KEV + EPSS (every 24 hours)
    - Misconfiguration checks (every 24 hours)
    - Extra subdomain discovery: passive sources + DNS brute force (every 24 hours)
    - Web screenshots (every 24 hours)

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


def send_liveness_notification(result: dict):
    """
    Send bundled Discord notification for liveness changes.
    
    Args:
        result: Dict from check_all_liveness()
    """
    try:
        from modules.Notify import send_message
        
        lines = ["**Liveness Status Update**", "━━━━━━━━━━━━━━━━━━━━━━━━━"]
        
        if result['down']:
            lines.append(f"**Down ({len(result['down'])}):**")
            for name in result['down'][:10]:  # Limit to 10
                lines.append(f"• {name}")
            if len(result['down']) > 10:
                lines.append(f"• ... and {len(result['down']) - 10} more")
        
        if result['recovered']:
            lines.append(f"**Recovered ({len(result['recovered'])}):**")
            for name in result['recovered'][:10]:
                lines.append(f"• {name}")
            if len(result['recovered']) > 10:
                lines.append(f"• ... and {len(result['recovered']) - 10} more")
        
        if result.get('new_up'):
            lines.append(f"**New Assets Up ({len(result['new_up'])}):**")
            for name in result['new_up'][:10]:
                lines.append(f"• {name}")
            if len(result['new_up']) > 10:
                lines.append(f"• ... and {len(result['new_up']) - 10} more")
        
        if result.get('new_down'):
            lines.append(f"**New Assets Down ({len(result['new_down'])}):**")
            for name in result['new_down'][:10]:
                lines.append(f"• {name}")
            if len(result['new_down']) > 10:
                lines.append(f"• ... and {len(result['new_down']) - 10} more")
        
        if result.get('still_down'):
            lines.append(f"**Still Down ({len(result['still_down'])}):**")
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
        
        lines = ["**CT Logs Update**", "━━━━━━━━━━━━━━━━━━━━━━━━━"]
        
        if result['new_subdomains']:
            lines.append(f"\n**New Subdomains ({len(result['new_subdomains'])}):**")
            for domain, subdomain in result['new_subdomains'][:10]:
                lines.append(f"• {subdomain} (queued)")
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
            "**Wappalyzer Re-scan Complete**",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ]
        
        lines.append(f"\n**Hosts Scanned:** {result['hosts_scanned']}")
        lines.append(f"**Technologies Found:** {result['technologies_found']}")
        lines.append(f"**Total CVEs:** {result['cves_found']}")
        lines.append(f"**New CVEs:** {len(result['new_cves'])}")
        
        if result['new_cves']:
            lines.append(f"\n**New CVEs Detected:**")
            for cve in result['new_cves'][:10]:
                cvss_str = f" (CVSS {cve['cvss']})" if cve.get('cvss') else ""
                lines.append(f"• {cve['cve_id']}{cvss_str} on {cve['host']} ({cve['tech_name']})")
            if len(result['new_cves']) > 10:
                lines.append(f"• ... and {len(result['new_cves']) - 10} more")
        
        if result['errors']:
            lines.append(f"\n**Errors ({len(result['errors'])}):**")
            for err in result['errors'][:3]:
                lines.append(f"• {err}")
            if len(result['errors']) > 3:
                lines.append(f"• ... and {len(result['errors']) - 3} more")
        
        send_message('\n'.join(lines))
    
    except Exception as e:
        logger.error(f"Failed to send Wappalyzer notification: {e}")


def send_takeover_notification(result: dict):
    """
    Send Discord notification for new or reopened takeover findings.

    Args:
        result: Dict from run_takeover_check()
    """
    try:
        from modules.Notify import send_message

        lines = [
            "**Subdomain Takeover Check**",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"\n**Hosts Checked:** {result['hosts_checked']}",
            f"**New Findings:** {len(result['new_findings'])}",
            "",
        ]
        for finding in result['new_findings'][:10]:
            lines.append(f"• [{finding['severity'].upper()}] {finding['host']}: {finding['title']}")
        if len(result['new_findings']) > 10:
            lines.append(f"• ... and {len(result['new_findings']) - 10} more")

        send_message('\n'.join(lines))

    except Exception as e:
        logger.error(f"Failed to send takeover notification: {e}")


def send_kev_notification(result: dict):
    """
    Send Discord notification when CVEs with open findings are added to CISA KEV.

    Args:
        result: Dict from refresh_threat_intel()
    """
    try:
        from modules.Notify import send_message

        lines = [
            "**Actively Exploited CVEs on Your Assets (CISA KEV)**",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]
        for item in result['newly_kev'][:10]:
            hosts = ', '.join(item['hosts'][:5]) + (f" (+{len(item['hosts']) - 5} more)" if len(item['hosts']) > 5 else '')
            ransomware = " · used in ransomware" if item.get('ransomware') else ""
            lines.append(f"\n• **{item['cve_id']}**{ransomware} · CISA due date {item.get('due_date') or '-'}")
            lines.append(f"  Hosts: {hosts}")
            if item.get('required_action'):
                lines.append(f"  Action: {item['required_action'][:200]}")
        if len(result['newly_kev']) > 10:
            lines.append(f"\n• ... and {len(result['newly_kev']) - 10} more")

        send_message('\n'.join(lines))

    except Exception as e:
        logger.error(f"Failed to send KEV notification: {e}")


def send_misconfig_notification(result: dict):
    """
    Send Discord notification for new or reopened misconfiguration findings
    (medium severity and above).

    Args:
        result: Dict from run_misconfig_check()
    """
    try:
        from modules.Notify import send_message

        order = {'critical': 0, 'high': 1, 'medium': 2}
        findings = sorted(result['new_findings'], key=lambda f: order.get(f['severity'], 3))
        lines = [
            "**Misconfiguration Check**",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"\n**New Findings:** {len(findings)}",
            "",
        ]
        for finding in findings[:15]:
            lines.append(f"• [{finding['severity'].upper()}] {finding['host']}: {finding['title']}")
        if len(findings) > 15:
            lines.append(f"• ... and {len(findings) - 15} more")

        send_message('\n'.join(lines))

    except Exception as e:
        logger.error(f"Failed to send misconfiguration notification: {e}")


def send_discovery_notification(result: dict):
    """
    Send Discord notification for subdomains found by the discovery monitor.

    Args:
        result: Dict from run_discovery_monitor()
    """
    try:
        from modules.Notify import send_message

        new = result['new_subdomains']
        lines = [
            "**Subdomain Discovery**",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"\n**New Subdomains:** {len(new)} (queued for scanning)",
            "",
        ]
        for domain, subdomain in new[:15]:
            lines.append(f"• {subdomain}")
        if len(new) > 15:
            lines.append(f"• ... and {len(new) - 15} more")

        send_message('\n'.join(lines))

    except Exception as e:
        logger.error(f"Failed to send discovery notification: {e}")


POLL_SECONDS = 5


def run_monitor(name: str):
    """
    Run one Phase 3 check now (scheduled or manual). A per-check lock keeps a
    manual run from overlapping the scheduled run of the same check.
    """
    if name not in MONITORS:
        raise ValueError(f"unknown check: {name}")
    with _locks.setdefault(name, threading.Lock()):
        MONITORS[name][3]()


def interval_seconds(name: str) -> int:
    """Current interval for a check, read from settings (dashboard-editable)."""
    from utils.scan_settings import SCHEDULE, interval_value
    key, default, unit = MONITORS[name][:3]
    bounds = next(((low, high) for n, _, _, _, _, low, high in SCHEDULE if n == name), (1, 10 ** 6))
    return interval_value(key, default, *bounds) * unit


def _monitor_loop(label: str, name: str):
    """
    Run check `name` on its interval while Phase 3 is enabled.

    The enabled flag and the interval are re-read every few seconds, so
    changes made in the dashboard (web process) apply in the worker process
    without a restart. A check that already ran is not repeated before its
    interval passes.
    """
    from utils.db_utils import get_setting

    logger.info(f"{label} thread started")
    last_run = None
    while _phase3_running:
        try:
            due = last_run is None or time.monotonic() - last_run >= interval_seconds(name)
            if due and get_setting('phase3_enabled') == '1':
                last_run = time.monotonic()
                logger.info(f"Running {label}...")
                run_monitor(name)
        except Exception as e:
            logger.error(f"{label} error: {e}")
        time.sleep(POLL_SECONDS)
    logger.info(f"{label} thread stopped")


def _run_liveness():
    from utils.liveness_checker import check_all_liveness
    result = check_all_liveness()
    if result['down'] or result['recovered']:
        send_liveness_notification(result)


def _run_ctlogs():
    from utils.ct_monitor import poll_all_domains
    result = poll_all_domains()
    if result['new_subdomains'] or any(result.get('expiry_alerts', {}).values()) or result.get('signature_changes'):
        send_ctlogs_notification(result)


def _run_wappalyzer():
    from utils.wappalyzer_monitor import run_wappalyzer_scan
    result = run_wappalyzer_scan()
    if result.get('new_cves'):
        send_wappalyzer_notification(result)


def _run_takeover():
    from utils.takeover_checker import run_takeover_check
    result = run_takeover_check()
    if result.get('new_findings'):
        send_takeover_notification(result)


def _run_intel():
    from utils.threat_intel import refresh_threat_intel
    result = refresh_threat_intel()
    if result.get('newly_kev'):
        send_kev_notification(result)


def _run_misconfig():
    from utils.misconfig_checker import run_misconfig_check
    result = run_misconfig_check()
    if result.get('new_findings'):
        send_misconfig_notification(result)


def _run_discovery():
    from utils.subdomain_discovery import run_discovery_monitor
    result = run_discovery_monitor()
    if result.get('new_subdomains'):
        send_discovery_notification(result)


def _run_screenshots():
    from utils.screenshots import run_screenshots, screenshots_enabled
    result = run_screenshots()
    # Turned off in settings is fine; a browser that cannot start must show as a failed run
    if result.get('error') and screenshots_enabled():
        raise RuntimeError(result['error'])


def _run_maintenance():
    from utils.db_utils import prune_changes
    removed = prune_changes(days=365)
    if removed:
        logger.info(f"Pruned {removed} change history entries older than 365 days")


# name -> (setting key, default, seconds per unit, run function)
MONITORS = {
    'liveness': ('liveness_interval_min', 5, 60, _run_liveness),
    'ctlogs': ('ctlogs_interval_hr', 1, 3600, _run_ctlogs),
    'wappalyzer': ('wappalyzer_interval_hr', 24, 3600, _run_wappalyzer),
    'takeover': ('takeover_interval_hr', 24, 3600, _run_takeover),
    'intel': ('intel_interval_hr', 24, 3600, _run_intel),
    'misconfig': ('misconfig_interval_hr', 24, 3600, _run_misconfig),
    'discovery': ('discovery_interval_hr', 24, 3600, _run_discovery),
    'screenshots': ('screenshot_interval_hr', 24, 3600, _run_screenshots),
    'maintenance': ('maintenance_interval_hr', 24, 3600, _run_maintenance),
}

_threads = {}
_locks = {}


def start_phase3_workers():
    """
    Start all Phase 3 monitoring threads (worker process only).

    Threads always start; each one runs only while phase3_enabled is '1'.
    Intervals are re-read every cycle, so dashboard changes apply live.
    """
    global _phase3_running

    if _phase3_running:
        logger.warning("Phase 3 workers already running")
        return
    _phase3_running = True

    intervals = {}
    for name in MONITORS:
        intervals[name] = interval_seconds(name)
        _threads[name] = threading.Thread(
            target=_monitor_loop,
            args=(f"Phase 3 {name}", name),
            daemon=True,
            name=f'Phase3-{name}'
        )
        _threads[name].start()

    logger.info(f"Phase 3 workers started (intervals in seconds: {intervals})")


def stop_phase3_workers():
    """Stop all Phase 3 monitoring threads."""
    global _phase3_running

    logger.info("Stopping Phase 3 workers...")
    _phase3_running = False
    for thread in _threads.values():
        if thread.is_alive():
            thread.join(timeout=10)
    logger.info("Phase 3 workers stopped")


def phase3_threads_alive() -> bool:
    """True when every monitor thread is running in this process."""
    return bool(_threads) and all(t.is_alive() for t in _threads.values())


def get_phase3_status() -> dict:
    """
    Get current Phase 3 status (works from any process).

    'running' means the worker process is alive and monitoring is enabled.
    """
    from utils.db_utils import get_setting
    from utils.worker_runtime import get_worker_status

    enabled = get_setting('phase3_enabled') == '1'
    worker = get_worker_status()
    return {
        'running': enabled and worker['alive'] and worker['components'].get('phase3', False),
        'enabled': enabled,
        'last_liveness_check': get_setting('last_liveness_check') or '-',
        'last_ctlogs_check': get_setting('last_ctlogs_check') or '-',
        'last_wappalyzer_check': get_setting('last_wappalyzer_check') or '-',
        'last_takeover_check': get_setting('last_takeover_check') or '-',
        'last_intel_check': get_setting('last_intel_check') or '-',
        'last_misconfig_check': get_setting('last_misconfig_check') or '-',
        'last_discovery_check': get_setting('last_discovery_check') or '-',
        'last_screenshot_check': get_setting('last_screenshot_check') or '-',
        'liveness_interval_min': int(get_setting('liveness_interval_min') or '5'),
        'ctlogs_interval_hr': int(get_setting('ctlogs_interval_hr') or '1'),
        'wappalyzer_interval_hr': int(get_setting('wappalyzer_interval_hr') or '24'),
        'takeover_interval_hr': int(get_setting('takeover_interval_hr') or '24'),
        'intel_interval_hr': int(get_setting('intel_interval_hr') or '24'),
        'misconfig_interval_hr': int(get_setting('misconfig_interval_hr') or '24'),
        'discovery_interval_hr': int(get_setting('discovery_interval_hr') or '24'),
        'screenshot_interval_hr': int(get_setting('screenshot_interval_hr') or '24'),
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
