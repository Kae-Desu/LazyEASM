"""
Phase 0 Worker - Background worker for processing discovered subdomains.

Monitors scan_queue for 'phase0_discovery' items and processes them.
Runs DNS resolution, ping check, and stores IPs for each subdomain.
After Phase 0, enqueues assets for Phase 1.

Exports:
    - start_phase0_worker()
    - stop_phase0_worker()
    - get_phase0_status()
"""

import logging
import threading
import time
import importlib

logger = logging.getLogger(__name__)

_phase0_running = False
_phase0_thread = None


def get_pending_phase0_item():
    """
    Get the next pending phase0_discovery item from queue.
    
    Returns:
        Dict with queue info or None if no pending items.
    """
    from utils.db_utils import get_db_connection
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT queue_id, target, target_type, queued_at
        FROM scan_queue
        WHERE scan_type = 'phase0_discovery' AND status = 'pending'
        ORDER BY queued_at ASC
        LIMIT 1
    ''')
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return dict(row)
    return None


def reset_stuck_processing_items(timeout_minutes: int = 30):
    """
    Reset items stuck in 'processing' status for too long.
    
    Items that started processing but never completed (due to crash, timeout, etc.)
    are reset to 'pending' so they can be retried.
    
    Args:
        timeout_minutes: Minutes after which to consider item stuck (default: 30)
    
    Returns:
        Number of items reset
    """
    from utils.db_utils import get_db_connection
    from datetime import datetime, timedelta
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Calculate cutoff time in Python (handles timezone correctly)
    cutoff = (datetime.now() - timedelta(minutes=timeout_minutes)).strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        UPDATE scan_queue 
        SET status = 'pending', started_at = NULL
        WHERE scan_type = 'phase0_discovery'
          AND status = 'processing'
          AND started_at < ?
    ''', (cutoff,))
    
    reset_count = cursor.rowcount
    conn.commit()
    conn.close()
    
    if reset_count > 0:
        logger.info(f"[Phase0] Reset {reset_count} stuck processing items (cutoff: {cutoff})")
    
    return reset_count


def mark_queue_item_processing(queue_id: int):
    """Mark queue item as processing."""
    from utils.db_utils import get_db_connection
    from datetime import datetime
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        UPDATE scan_queue SET status = ?, started_at = ? WHERE queue_id = ?
    ''', ('processing', now, queue_id))
    
    conn.commit()
    conn.close()


def mark_queue_item_completed(queue_id: int):
    """Mark queue item as completed."""
    from utils.db_utils import get_db_connection
    from datetime import datetime
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        UPDATE scan_queue SET status = ?, completed_at = ? WHERE queue_id = ?
    ''', ('completed', now, queue_id))
    
    conn.commit()
    conn.close()


def mark_queue_item_failed(queue_id: int, error_message: str):
    """Mark queue item as failed."""
    from utils.db_utils import get_db_connection
    from datetime import datetime
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        UPDATE scan_queue SET status = ?, completed_at = ?, error_message = ? WHERE queue_id = ?
    ''', ('failed', now, error_message, queue_id))
    
    conn.commit()
    conn.close()


def process_phase0_item(item: dict):
    """
    Process a single phase0_discovery item.
    
    Args:
        item: Dict with queue_id, target, target_type
    
    Returns:
        True if successful, False otherwise
    """
    from utils.parsing import extract_root_domain
    from utils.db_utils import get_domain_id, get_db_connection
    from modules.Notify import send_message
    
    subdomain = item['target']
    queue_id = item['queue_id']
    
    logger.info(f"[Phase0] Processing: {subdomain}")
    
    # Check if already exists in subdomain_asset
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?', (subdomain,))
    if cursor.fetchone():
        conn.close()
        logger.info(f"[Phase0] Skipping {subdomain} - already exists in subdomain_asset")
        mark_queue_item_completed(queue_id)
        return True
    
    # Check if it's a root domain in domain_asset
    cursor.execute('SELECT dom_id FROM domain_asset WHERE domain_name = ?', (subdomain,))
    if cursor.fetchone():
        conn.close()
        logger.info(f"[Phase0] Skipping {subdomain} - is a root domain")
        mark_queue_item_completed(queue_id)
        return True
    conn.close()
    
    # Extract root domain
    root_domain = extract_root_domain(subdomain)
    
    if not root_domain:
        logger.error(f"[Phase0] Could not extract root domain from {subdomain}")
        mark_queue_item_failed(queue_id, f"Could not extract root domain")
        return False
    
    logger.debug(f"[Phase0] Extracted root domain: {root_domain} from {subdomain}")
    
    # Look up domain ID
    dom_id = get_domain_id(root_domain)
    
    if not dom_id:
        logger.error(f"[Phase0] Root domain {root_domain} not found in database")
        mark_queue_item_failed(queue_id, f"Root domain {root_domain} not found")
        return False
    
    logger.debug(f"[Phase0] Found domain ID: {dom_id} for {root_domain}")
    
    # Mark as processing
    mark_queue_item_processing(queue_id)
    
    try:
        # Import Phase1Expander
        phase1_module = importlib.import_module('modules.03-asset-expansion')
        expander = phase1_module.Phase1Expander()
        
        # Run Phase 0 discovery for subdomain
        stats = expander.process_subdomain(subdomain, root_domain)
        
        if stats.get('error'):
            logger.error(f"[Phase0] Error processing {subdomain}: {stats['error']}")
            mark_queue_item_failed(queue_id, stats['error'])
            return False
        
        # Mark as completed
        mark_queue_item_completed(queue_id)
        
        logger.info(f"[Phase0] Completed: {subdomain} - {stats.get('ips_resolved', 0)} IPs resolved")
        
        # Enqueue for Phase 1
        from main import enqueue_single_asset_for_phase1
        enqueue_single_asset_for_phase1(subdomain, 'subdomain')
        
        return True
        
    except Exception as e:
        logger.error(f"[Phase0] Exception processing {subdomain}: {e}")
        import traceback
        traceback.print_exc()
        mark_queue_item_failed(queue_id, str(e))
        return False


def phase0_worker_loop(interval_sec: int = 5):
    """
    Main loop for Phase 0 worker.
    
    Args:
        interval_sec: Seconds to wait between queue checks
    """
    global _phase0_running
    
    logger.info("[Phase0] Worker started")
    
    while _phase0_running:
        try:
            # Reset stuck processing items (crash recovery)
            reset_stuck_processing_items(timeout_minutes=30)
            
            # Get next pending item
            item = get_pending_phase0_item()
            
            if item:
                # Process it
                process_phase0_item(item)
            else:
                # No items, wait
                time.sleep(interval_sec)
        
        except Exception as e:
            logger.error(f"[Phase0] Worker error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(interval_sec)
    
    logger.info("[Phase0] Worker stopped")


def start_phase0_worker():
    """Start the Phase 0 worker thread."""
    global _phase0_running, _phase0_thread
    
    if _phase0_running:
        logger.warning("[Phase0] Worker already running")
        return
    
    _phase0_running = True
    
    _phase0_thread = threading.Thread(
        target=phase0_worker_loop,
        args=(5,),
        daemon=True,
        name='Phase0-Worker'
    )
    _phase0_thread.start()
    
    logger.info("[Phase0] Worker thread started")


def stop_phase0_worker():
    """Stop the Phase 0 worker thread."""
    global _phase0_running
    
    logger.info("[Phase0] Stopping worker...")
    _phase0_running = False
    
    if _phase0_thread and _phase0_thread.is_alive():
        _phase0_thread.join(timeout=10)
    
    logger.info("[Phase0] Worker stopped")


def get_phase0_status() -> dict:
    """
    Get Phase 0 worker status.
    
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
        WHERE scan_type = 'phase0_discovery' AND status = 'pending'
    ''')
    
    pending = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT COUNT(*) as count FROM scan_queue
        WHERE scan_type = 'phase0_discovery' AND status = 'processing'
    ''')
    
    processing = cursor.fetchone()['count']
    
    conn.close()
    
    return {
        'running': _phase0_running,
        'thread_alive': _phase0_thread.is_alive() if _phase0_thread else False,
        'pending': pending,
        'processing': processing
    }


if __name__ == '__main__':
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Phase 0 Worker')
    parser.add_argument('--start', action='store_true', help='Start worker (foreground)')
    parser.add_argument('--status', action='store_true', help='Get worker status')
    
    args = parser.parse_args()
    
    if args.start:
        print("Starting Phase 0 worker (press Ctrl+C to stop)...")
        start_phase0_worker()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
            stop_phase0_worker()
    elif args.status:
        status = get_phase0_status()
        print(f"Running: {status['running']}")
        print(f"Pending: {status['pending']}")
        print(f"Processing: {status['processing']}")
    else:
        parser.print_help()