"""
Asset pipeline steps shared by the web app and the worker process.

    submit (web)  ->  input_discovery job  ->  Phase 1 queue  ->  phase1_runner
                      (worker: ExpandAsset)    (worker: TaskQueue)

Lives outside main.py so workers never import the Flask app.
"""

import json
from datetime import datetime
import logging
import importlib

from utils.db_utils import get_db_connection
from utils.queue_manager import task_queue
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

INPUT_DISCOVERY = 'input_discovery'
MONITOR_RUN = 'monitor_run'
JOB_TYPES = (INPUT_DISCOVERY, MONITOR_RUN)


def _now() -> str:
    # Local time, like every other scan_queue timestamp (the column default is UTC)
    return utc_now_str()


def enqueue_input_discovery(targets: dict) -> int:
    """
    Queue parsed user input for discovery by the worker.

    Args:
        targets: output of utils.parsing.parse_input

    Returns:
        queue_id
    """
    payload = {k: v for k, v in targets.items() if k != 'invalid'}
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            INSERT INTO scan_queue (scan_type, cycle, target, target_type, status, queued_at)
            VALUES (?, 'standard', ?, 'input', 'pending', ?)
        ''', (INPUT_DISCOVERY, json.dumps(payload), _now()))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def enqueue_monitor_run(name: str) -> tuple:
    """
    Queue a manual run of a Phase 3 check for the worker.

    Returns:
        (job_id, created) - an already queued run of the same check is reused
    """
    conn = get_db_connection()
    try:
        existing = conn.execute('''
            SELECT queue_id FROM scan_queue
            WHERE scan_type = ? AND target = ? AND status IN ('pending', 'processing')
        ''', (MONITOR_RUN, name)).fetchone()
        if existing:
            return existing['queue_id'], False
        cursor = conn.execute('''
            INSERT INTO scan_queue (scan_type, cycle, target, target_type, status, queued_at)
            VALUES (?, 'manual', ?, 'monitor', 'pending', ?)
        ''', (MONITOR_RUN, name, _now()))
        conn.commit()
        return cursor.lastrowid, True
    finally:
        conn.close()


def get_job(job_id: int):
    """Status of an input discovery or manual check job, or None."""
    conn = get_db_connection()
    try:
        row = conn.execute(f'''
            SELECT queue_id, scan_type, target, status, queued_at, started_at, completed_at, error_message
            FROM scan_queue WHERE queue_id = ? AND scan_type IN ({','.join('?' * len(JOB_TYPES))})
        ''', (job_id, *JOB_TYPES)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    job = dict(row)
    job['job_id'] = job.pop('queue_id')
    if job['scan_type'] == INPUT_DISCOVERY:
        job['target'] = 'submitted assets'
    return job


def run_input_discovery(targets: dict) -> dict:
    """
    Discover subdomains/IPs for submitted targets, then queue new assets for Phase 1.
    Sends Discord notifications on completion or error.
    """
    from modules.Notify import send_message

    try:
        expander = importlib.import_module('modules.ExpandAsset').Phase1Expander()
        stats = expander.run_phase1(targets)

        message = (
            f"**Parsing Complete**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"**Domains added:** {stats['domains_added']}\n"
            f"**Subdomains discovered:** {stats['subdomains_discovered']}\n"
            f"**New subdomains:** {stats['subdomains_new']}\n"
            f"**IPs resolved:** {stats['ips_resolved']}\n"
            f"**Time:** {stats['time_elapsed']:.1f}s"
        )
        if stats['errors']:
            message += f"\n**Errors:** {len(stats['errors'])}"
        send_message(message)
        logger.info(f"[Discovery] Complete: {stats}")

        if stats['domains_added'] > 0 or stats['subdomains_new'] > 0 or stats['ips_resolved'] > 0:
            enqueue_assets_for_phase1()
            send_message("**Initialization Queued**: Processing assets...")
        return stats

    except Exception as e:
        send_message(f"**Parsing Failed**\nError: {str(e)}")
        logger.exception(f"[Discovery] Error: {e}")
        raise


def enqueue_assets_for_phase1():
    """
    Queue every asset that is up and has never been scanned.
    Standalone IPs (not linked to a domain/subdomain) are included.
    """
    conn = get_db_connection()
    try:
        rows = []
        rows += [(r['dom_id'], 'domain', r['domain_name']) for r in conn.execute('''
            SELECT dom_id, domain_name FROM domain_asset
            WHERE status='up' AND last_scanned IS NULL AND expand = 1
        ''')]
        rows += [(r['sub_id'], 'subdomain', r['subdomain_name']) for r in conn.execute('''
            SELECT sub_id, subdomain_name FROM subdomain_asset
            WHERE status='up' AND last_scanned IS NULL
        ''')]
        rows += [(r['ip_id'], 'ip', r['ip_value']) for r in conn.execute('''
            SELECT ip_id, ip_value FROM ip_asset
            WHERE status='up' AND last_scanned IS NULL
              AND ip_id NOT IN (SELECT ip_id FROM domain_ip UNION SELECT ip_id FROM subdomain_ip)
        ''')]
    finally:
        conn.close()

    for target_id, target_type, name in rows:
        task_queue.enqueue(target_id, target_type, name)
    logger.info(f"[Queue] Enqueued {len(rows)} assets for Phase 1")


def enqueue_single_asset_for_phase1(asset_name: str, asset_type: str):
    """Queue one asset for Phase 1 (used after Phase 0 discovers a subdomain)."""
    conn = get_db_connection()
    try:
        row = None
        if asset_type == 'domain':
            row = conn.execute('SELECT dom_id AS id FROM domain_asset WHERE domain_name = ?', (asset_name,)).fetchone()
        elif asset_type == 'subdomain':
            row = conn.execute('SELECT sub_id AS id FROM subdomain_asset WHERE subdomain_name = ?', (asset_name,)).fetchone()
        elif asset_type == 'ip':
            row = conn.execute('SELECT ip_id AS id FROM ip_asset WHERE ip_value = ?', (asset_name,)).fetchone()
    finally:
        conn.close()

    task_queue.enqueue(row['id'] if row else None, asset_type, asset_name)
