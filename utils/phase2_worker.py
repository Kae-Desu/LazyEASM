"""
Phase 2 Queue Worker

Processes deep scan requests from scan_queue.
One at a time to conserve resources (1 core 1GB RAM VPS).
"""

import logging
import time
import sqlite3
from datetime import datetime
import importlib
import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.db_utils import get_db_connection

logger = logging.getLogger(__name__)

# Global thread reference for health check
_phase2_thread = None


def get_next_queued_scan():
    """
    Get the next pending Phase 2 scan from queue.
    
    Returns:
        Dict with queue_id, target, target_id, target_type
        None if no pending scans
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT queue_id, target, target_id, target_type, queued_at
        FROM scan_queue
        WHERE scan_type = 'phase2_deep_scan'
          AND status = 'pending'
        ORDER BY queued_at ASC
        LIMIT 1
    ''')
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return dict(result)
    return None


def update_queue_status(queue_id: int, status: str, **kwargs):
    """Update scan queue status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    updates = ['status = ?']
    values = [status]
    
    if status == 'processing':
        updates.append('started_at = ?')
        values.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    if status == 'completed':
        updates.append('completed_at = ?')
        values.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        if 'ports_found' in kwargs:
            updates.append('ports_found = ?')
            values.append(kwargs['ports_found'])
        
        if 'dirs_found' in kwargs:
            updates.append('dirs_found = ?')
            values.append(kwargs['dirs_found'])
    
    if status == 'failed':
        updates.append('completed_at = ?')
        values.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        if 'error_message' in kwargs:
            updates.append('error_message = ?')
            values.append(kwargs['error_message'])
    
    values.append(queue_id)
    
    cursor.execute(f'''
        UPDATE scan_queue 
        SET {', '.join(updates)}
        WHERE queue_id = ?
    ''', values)
    
    conn.commit()
    conn.close()


def run_phase2_on_asset(target: str, target_id: int, target_type: str) -> dict:
    """
    Run full Phase 2 on a single asset (nmap + dirsearch).
    
    Args:
        target: Asset hostname
        target_id: Database ID
        target_type: 'domain' or 'subdomain'
    
    Returns:
        Dict with 'success', 'dirs_found', 'ports_found', 'nmap_skipped', 'skip_reason', 'error'
    """
    try:
        from modules.phase2_dirsearch import run_phase2_asset
        asset = {
            'asset_id': target_id,
            'asset_type': target_type,
            'name': target
        }
        result = run_phase2_asset(asset)
        
        nmap = result.get('nmap', {})
        dirsearch = result.get('dirsearch', {})
        
        return {
            'success': dirsearch.get('success', False),
            'dirs_found': dirsearch.get('directories_found', 0),
            'ports_found': nmap.get('ports_found', 0),
            'nmap_skipped': nmap.get('skipped', False),
            'skip_reason': nmap.get('reason'),
            'error': dirsearch.get('error')
        }
    except Exception as e:
        logger.error(f"Phase 2 failed for {target}: {e}")
        return {
            'success': False,
            'dirs_found': 0,
            'ports_found': 0,
            'nmap_skipped': False,
            'skip_reason': None,
            'error': str(e)
        }


def update_asset_last_scan(target: str, target_type: str, timestamp: str):
    """Update last_deep_scan timestamp on asset."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if target_type == 'domain':
        cursor.execute('''
            UPDATE domain_asset 
            SET last_deep_scan = ? 
            WHERE domain_name = ?
        ''', (timestamp, target))
    else:
        cursor.execute('''
            UPDATE subdomain_asset 
            SET last_deep_scan = ? 
            WHERE subdomain_name = ?
        ''', (timestamp, target))
    
    conn.commit()
    conn.close()


def send_discord_notification(message: str):
    """Send Discord notification."""
    try:
        from modules.Notify import send_message
        send_message(message)
    except Exception as e:
        logger.error(f"Discord notification failed: {e}")


def process_phase2_queue():
    """
    Process one item from the Phase 2 queue.
    Designed to be called periodically from a background thread.
    
    Returns:
        True if an item was processed
        False if queue was empty
    """
    scan = get_next_queued_scan()
    
    if not scan:
        return False
    
    queue_id = scan['queue_id']
    target = scan['target']
    target_id = scan['target_id']
    target_type = scan['target_type']
    
    logger.info(f"Processing Phase 2 scan for {target}")
    
    update_queue_status(queue_id, 'processing')
    
    send_discord_notification(
        f"**Phase 2 Deep Scan Started**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Asset: {target}\n"
        f"Type: {target_type}"
    )
    
    result = run_phase2_on_asset(target, target_id, target_type)
    
    if result['success']:
        update_queue_status(
            queue_id, 
            'completed',
            dirs_found=result['dirs_found'],
            ports_found=result.get('ports_found', 0)
        )
        
        update_asset_last_scan(
            target, 
            target_type, 
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        nmap_info = ""
        if result.get('nmap_skipped'):
            nmap_info = f"Nmap: Skipped ({result.get('skip_reason', 'CDN/Shared')})\n"
        else:
            nmap_info = f"Ports found: {result.get('ports_found', 0)}\n"
        
        send_discord_notification(
            f"**Phase 2 Deep Scan Complete**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Asset: {target}\n"
            f"{nmap_info}"
            f"Directories found: {result['dirs_found']}"
        )
        
        logger.info(f"Phase 2 scan completed for {target}: {result['dirs_found']} directories")
    else:
        update_queue_status(
            queue_id, 
            'failed',
            error_message=result.get('error', 'Unknown error')
        )
        
        send_discord_notification(
            f"**Phase 2 Deep Scan Failed**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Asset: {target}\n"
            f"Error: {result.get('error', 'Unknown error')}"
        )
        
        logger.error(f"Phase 2 scan failed for {target}: {result.get('error')}")
    
    return True


def phase2_worker_loop(interval: int = 5):
    """
    Background worker loop.
    
    Args:
        interval: Seconds to wait between checks
    
    This is designed to run in a background thread.
    """
    global _phase2_thread
    
    logger.info("Phase 2 worker started")
    
    while True:
        try:
            processed = process_phase2_queue()
            
            if not processed:
                time.sleep(interval)
        except Exception as e:
            logger.error(f"Phase 2 worker error: {e}")
            time.sleep(interval)


def get_phase2_status() -> dict:
    """
    Get Phase 2 worker status.
    
    Returns:
        {
            'running': bool,
            'thread_alive': bool,
            'pending': int,
            'processing': int
        }
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT COUNT(*) as count FROM scan_queue
        WHERE scan_type = 'phase2_deep_scan' AND status = 'pending'
    ''')
    
    pending = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT COUNT(*) as count FROM scan_queue
        WHERE scan_type = 'phase2_deep_scan' AND status = 'processing'
    ''')
    
    processing = cursor.fetchone()['count']
    
    conn.close()
    
    return {
        'running': _phase2_thread is not None,
        'thread_alive': _phase2_thread.is_alive() if _phase2_thread else False,
        'pending': pending,
        'processing': processing
    }