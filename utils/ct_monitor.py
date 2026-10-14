"""
Certificates & CT logs monitor (Phase 3, default every 6 hours).

    1. CT logs: new subdomains of every monitored domain (CertSpotter, crt.sh
       as fallback; see utils/subdomain_discovery.py), queued for discovery
    2. Served certificates: the certificate every HTTPS service presents
       (utils/tls_certs.py); a replaced certificate is a 'certificate_changed'
    3. Expiry alerts at 7, 5, 3 and 1 days, from served certificates only

Exports:
    - poll_all_domains() -> dict summary for notification
"""

import logging
import time
from datetime import datetime, timezone
from typing import Dict, List

from utils.db_utils import SERVED_CERT, get_db_connection, is_cert_notified
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

EXPIRY_THRESHOLDS = (7, 5, 3, 1)


def _days_left(not_after: str, now: datetime) -> int:
    expires = datetime.strptime(not_after[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    return int((expires - now).total_seconds() // 86400)


def _cleanup_old_certs(days_expired: int = 90) -> int:
    """Delete replaced certificates that expired more than days_expired days ago."""
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            DELETE FROM certificates
            WHERE replaced_at IS NOT NULL AND julianday('now') - julianday(not_after) > ?
        ''', (days_expired,))
        deleted = cursor.rowcount
        if deleted:
            conn.execute('DELETE FROM cert_notifications WHERE cert_id NOT IN (SELECT cert_id FROM certificates)')
            logger.info(f"Cleaned up {deleted} replaced certificates expired more than {days_expired} days ago")
        conn.commit()
        return deleted
    finally:
        conn.close()


def check_certificate_expiry_thresholds() -> Dict[int, List[Dict]]:
    """
    Served certificates that reached a threshold (7, 5, 3 or 1 days left) and
    were not yet notified at it. Each certificate is placed at the tightest
    threshold it reached, so a check that does not run on a given day (long
    interval, worker down) catches up with one alert instead of missing it.

    Returns:
        {7: [{'cert_id', 'hostname', 'days'}, ...], 5: [...], 3: [...], 1: [...]}
    """
    now = datetime.now(timezone.utc)
    results = {t: [] for t in EXPIRY_THRESHOLDS}
    conn = get_db_connection()
    try:
        rows = conn.execute(f'SELECT cert_id, hostname, not_after FROM certificates WHERE {SERVED_CERT}').fetchall()
    finally:
        conn.close()
    for row in rows:
        try:
            days = _days_left(row['not_after'], now)
        except (TypeError, ValueError):
            continue
        if days < 0 or days > max(EXPIRY_THRESHOLDS):
            continue   # expired (reported by the misconfiguration check) or not due yet
        threshold = min(t for t in EXPIRY_THRESHOLDS if days <= t)
        if not is_cert_notified(row['cert_id'], threshold):
            results[threshold].append({'cert_id': row['cert_id'], 'hostname': row['hostname'], 'days': days})
    return results


def poll_all_domains() -> Dict:
    """
    Run all three steps.

    Returns:
        {
            'new_subdomains': [(domain, subdomain), ...],
            'expiry_alerts': {7: [{cert_id, hostname}, ...], 5: [...], 3: [...], 1: [...]},
            'certificate_changes': [{'hostname', 'port', 'summary'}, ...],
            'ct_errors': {domain: error}
        }
    """
    from utils.db_utils import get_all_monitored_domains, get_known_subdomains, queue_subdomain_discovery, set_setting
    from utils.subdomain_discovery import SourceError, from_ct_logs, in_scope
    from utils.tls_certs import refresh_served_certificates

    new_subdomains, ct_errors = [], {}
    domains = get_all_monitored_domains()
    if domains:
        logger.info(f"Polling CT logs for {len(domains)} domains")
        known = get_known_subdomains()
        for domain in domains:
            try:
                names = {n for n in (in_scope(raw, domain) for raw in from_ct_logs(domain)) if n}
            except (SourceError, ValueError) as e:
                ct_errors[domain] = str(e)
                logger.warning(f"CT logs unavailable for {domain}: {e}")
                continue
            for name in sorted(names - known):
                queue_subdomain_discovery(name, domain)
                new_subdomains.append((domain, name))
                known.add(name)
            time.sleep(1)  # be gentle with the CT services

    certificates = refresh_served_certificates()
    _cleanup_old_certs()
    expiry_alerts = check_certificate_expiry_thresholds()

    set_setting('last_ctlogs_check', utc_now_str())
    logger.info(
        f"Certificates & CT logs: {len(new_subdomains)} new subdomains, "
        f"{len(certificates['changed'])} certificates replaced, "
        f"{sum(len(c) for c in expiry_alerts.values())} expiry alerts, "
        f"CT logs failed for {len(ct_errors)} of {len(domains)} domains"
    )
    return {
        'new_subdomains': new_subdomains,
        'expiry_alerts': expiry_alerts,
        'certificate_changes': certificates['changed'],
        'ct_errors': ct_errors,
    }


def get_cert_expiry_summary() -> Dict:
    """
    Served certificates per hostname (soonest-expiring if its ports differ).

    Returns:
        {'expired', 'expiring_3_days', 'expiring_7_days', 'expiring_30_days', 'total_certs'}
        (the expiring buckets are cumulative)
    """
    now = datetime.now(timezone.utc)
    conn = get_db_connection()
    try:
        rows = conn.execute(f'''
            SELECT hostname, MIN(not_after) AS soonest FROM certificates
            WHERE {SERVED_CERT}
            GROUP BY hostname
        ''').fetchall()
    finally:
        conn.close()

    summary = {'expired': 0, 'expiring_3_days': 0, 'expiring_7_days': 0, 'expiring_30_days': 0, 'total_certs': 0}
    for row in rows:
        try:
            days = _days_left(row['soonest'], now)
        except (TypeError, ValueError):
            continue
        summary['total_certs'] += 1
        if days < 0:
            summary['expired'] += 1
            continue
        for bucket, limit in (('expiring_3_days', 3), ('expiring_7_days', 7), ('expiring_30_days', 30)):
            if days <= limit:
                summary[bucket] += 1
    return summary


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Certificates & CT logs monitor')
    parser.add_argument('--poll', action='store_true', help='Run the monitor once')
    parser.add_argument('--summary', action='store_true', help='Certificate expiry summary')
    args = parser.parse_args()

    if args.poll:
        print(poll_all_domains())
    elif args.summary:
        print(get_cert_expiry_summary())
    else:
        parser.print_help()
