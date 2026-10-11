"""
Asset pipeline steps shared by the web app and the worker process.

    submit (web)  ->  input_discovery job  ->  Phase 1 queue  ->  phase1_runner
                      (worker: ExpandAsset)    (worker: TaskQueue)

Lives outside main.py so workers never import the Flask app.
"""

import json
import logging
import importlib

from utils.db_utils import get_db_connection
from utils.queue_manager import task_queue

logger = logging.getLogger(__name__)

INPUT_DISCOVERY = 'input_discovery'


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
            INSERT INTO scan_queue (scan_type, cycle, target, target_type, status)
            VALUES (?, 'standard', ?, 'input', 'pending')
        ''', (INPUT_DISCOVERY, json.dumps(payload)))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


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
            WHERE status='up' AND last_scanned IS NULL
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
