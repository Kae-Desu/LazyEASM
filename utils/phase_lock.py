"""
Phase Lock - Track and manage running phases.

Prevents conflicting operations during Phase 2 by tracking
what's currently running in the database (works in Docker).
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Phase constants
PHASE_NONE = 0
PHASE_0_RUNNING = 1
PHASE_1_RUNNING = 2
PHASE_2_RUNNING = 3


def get_db_connection():
    """Import here to avoid circular dependency."""
    from utils.db_utils import get_db_connection as _get_db_connection
    return _get_db_connection()


def get_current_phase() -> int:
    """
    Get current running phase.
    
    Returns:
        PHASE_NONE (0), PHASE_0_RUNNING (1), PHASE_1_RUNNING (2), or PHASE_2_RUNNING (3)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT current_phase FROM phase_status WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    
    return result['current_phase'] if result else PHASE_NONE


def set_phase(phase: int, total_assets: int = 0):
    """
    Set current running phase.
    
    Args:
        phase: PHASE_0_RUNNING, PHASE_1_RUNNING, or PHASE_2_RUNNING
        total_assets: Total assets to process (for Phase 2)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        UPDATE phase_status 
        SET current_phase = ?, 
            started_at = ?, 
            total_assets = ?, 
            processed_assets = 0
        WHERE id = 1
    ''', (phase, now, total_assets))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Phase {phase} started at {now} with {total_assets} assets")


def clear_phase():
    """Clear current phase lock."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE phase_status 
        SET current_phase = 0,
            started_at = NULL,
            total_assets = 0,
            processed_assets = 0,
            eta_minutes = NULL
        WHERE id = 1
    ''')
    
    conn.commit()
    conn.close()
    
    logger.info("Phase lock cleared")


def is_phase2_running() -> bool:
    """Check if Phase 2 is currently running."""
    return get_current_phase() == PHASE_2_RUNNING


def get_phase2_progress() -> Dict:
    """
    Get Phase 2 progress information.
    
    Returns:
        Dict with 'total', 'processed', 'eta_minutes', 'phase'
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM phase_status WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    
    if not result or result['current_phase'] != PHASE_2_RUNNING:
        return {
            'total': 0,
            'processed': 0,
            'eta_minutes': 0,
            'phase': PHASE_NONE
        }
    
    total = result['total_assets'] or 0
    processed = result['processed_assets'] or 0
    
    # Calculate ETA based on progress
    eta_minutes = 0
    if processed > 0 and total > processed:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT started_at FROM phase_status WHERE id = 1')
        started = cursor.fetchone()
        conn.close()
        
        if started and started['started_at']:
            started_time = datetime.strptime(started['started_at'], '%Y-%m-%d %H:%M:%S')
            elapsed = (datetime.now() - started_time).total_seconds()
            avg_time_per_asset = elapsed / processed
            remaining = total - processed
            eta_minutes = int((avg_time_per_asset * remaining) / 60)
    
    return {
        'total': total,
        'processed': processed,
        'eta_minutes': eta_minutes,
        'phase': result['current_phase']
    }


def update_phase2_progress(processed: int):
    """
    Update Phase 2 progress.
    
    Args:
        processed: Number of assets processed so far
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE phase_status 
        SET processed_assets = ?
        WHERE id = 1
    ''', (processed,))
    
    conn.commit()
    conn.close()


def get_next_phase2_time() -> str:
    """
    Get next scheduled Phase 2 run time.
    
    Phase 2 runs every 2 days at midnight.
    
    Returns:
        ISO format string of next run time
    """
    now = datetime.now()
    
    # Find next midnight
    next_run = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # If it's already past midnight today, start from tomorrow
    if now.hour >= 0 and (now.hour > 0 or now.minute > 0 or now.second > 0):
        next_run += timedelta(days=1)
    
    # Find the next 2-day cycle (days 1, 3, 5, 7, etc. or days 2, 4, 6, 8, etc.)
    # We'll use odd-numbered days (1, 3, 5, 7...)
    while next_run.day % 2 != 1:
        next_run += timedelta(days=1)
    
    return next_run.strftime('%Y-%m-%d %H:%M')


def get_seconds_until_phase2() -> int:
    """Get seconds until next Phase 2 run."""
    now = datetime.now()
    next_run = datetime.strptime(get_next_phase2_time(), '%Y-%m-%d %H:%M')
    return int((next_run - now).total_seconds())