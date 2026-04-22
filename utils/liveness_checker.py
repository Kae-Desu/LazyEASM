"""
Liveness Checker - ICMP/TCP status checks for all assets.

Phase 3 continuous monitoring component.
Runs every 5 minutes to check if assets are up/down.

Exports:
    - check_single_asset(asset) -> str ('up' or 'down')
    - check_all_liveness() -> dict summary for notification
"""

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.db_utils import (
    get_db_connection,
    get_all_assets_for_liveness,
    update_asset_status,
    set_setting
)
from utils.utility import ping_host, is_content

logger = logging.getLogger(__name__)

# TCP ports to try if ICMP fails
TCP_FALLBACK_PORTS = [80, 443, 22]


def check_single_asset(asset: dict) -> str:
    """
    Check if a single asset is up or down.
    
    Strategy:
        1. Try ICMP ping
        2. If ICMP fails, try TCP ports (80, 443, 22)
        3. Return 'up' if any succeed, 'down' otherwise
    
    Args:
        asset: Dict with 'name', 'asset_id', 'asset_type', 'status'
    
    Returns:
        'up' or 'down'
    """
    hostname = asset['name']
    
    # Try ICMP ping first
    if ping_host(hostname, count=1):
        return 'up'
    
    # Try TCP ports as fallback
    for port in TCP_FALLBACK_PORTS:
        try:
            result = is_content(hostname, port)
            if result and 'Error:' not in result:
                return 'up'
        except Exception:
            continue
    
    return 'down'


def check_all_liveness() -> dict:
    """
    Check liveness for all assets in database.
    
    Bundles status changes for notification.
    Updates status column in database.
    Updates last_liveness_check timestamp.
    
    Returns:
        {
            'down': [asset_name, ...],       # Newly down (was up)
            'recovered': [asset_name, ...],  # Now up (was down, confirmed)
            'still_down': [asset_name, ...], # Still down
            'unchanged': int,                # No status change
            'new_up': [asset_name, ...],     # First check, now up
            'new_down': [asset_name, ...]    # First check, now down
        }
    """
    from datetime import datetime
    from utils.db_utils import get_db_connection
    
    assets = get_all_assets_for_liveness()
    
    if not assets:
        logger.info("No assets to check for liveness")
        return {'down': [], 'recovered': [], 'still_down': [], 'unchanged': 0, 'new_up': [], 'new_down': []}
    
    logger.info(f"Checking liveness for {len(assets)} assets")
    
    result = {
        'down': [],
        'recovered': [],
        'still_down': [],
        'unchanged': 0,
        'new_up': [],
        'new_down': []
    }
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    updates_to_make = []  # (asset_id, asset_type, new_status)
    
    for asset in assets:
        asset_name = asset['name']
        old_status = asset.get('status') or 'up'
        last_check = asset.get('last_liveness_check')
        is_first_check = last_check is None
        
        # Check current status
        new_status = check_single_asset(asset)
        
        if new_status != old_status:
            # Status changed - queue update
            updates_to_make.append((asset['asset_id'], asset['asset_type'], new_status))
            
            if is_first_check:
                # First check - report as new asset, not recovered/down
                if new_status == 'up':
                    result['new_up'].append(asset_name)
                    logger.info(f"{asset_name}: NEW asset, now UP")
                else:
                    result['new_down'].append(asset_name)
                    logger.info(f"{asset_name}: NEW asset, now DOWN")
            else:
                # Status change from confirmed state
                if new_status == 'down':
                    result['down'].append(asset_name)
                    logger.info(f"{asset_name}: went DOWN (was {old_status})")
                else:
                    result['recovered'].append(asset_name)
                    logger.info(f"{asset_name}: RECOVERED (was {old_status})")
        else:
            # No change
            if old_status == 'down':
                result['still_down'].append(asset_name)
            else:
                result['unchanged'] += 1
    
    # Batch update statuses and last_liveness_check
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        for asset_id, asset_type, new_status in updates_to_make:
            table = 'domain_asset' if asset_type == 'domain' else 'subdomain_asset'
            id_col = 'dom_id' if asset_type == 'domain' else 'sub_id'
            cursor.execute(f'''
                UPDATE {table} SET status = ?, last_liveness_check = ? WHERE {id_col} = ?
            ''', (new_status, now, asset_id))
        
        # Update last_liveness_check for all assets (even if status unchanged)
        for asset in assets:
            table = 'domain_asset' if asset['asset_type'] == 'domain' else 'subdomain_asset'
            id_col = 'dom_id' if asset['asset_type'] == 'domain' else 'sub_id'
            cursor.execute(f'''
                UPDATE {table} SET last_liveness_check = ? WHERE {id_col} = ?
            ''', (now, asset['asset_id']))
        
        conn.commit()
    finally:
        conn.close()
    
    # Update last check timestamp
    set_setting('last_liveness_check', now)
    
    logger.info(
        f"Liveness check complete: "
        f"{len(result['down'])} down, "
        f"{len(result['recovered'])} recovered, "
        f"{len(result['still_down'])} still down, "
        f"{result['unchanged']} unchanged, "
        f"{len(result['new_up'])} new up, "
        f"{len(result['new_down'])} new down"
    )
    
    return result


def get_liveness_summary() -> dict:
    """
    Get summary of asset liveness status.
    
    Returns:
        {
            'total': int,
            'up': int,
            'down': int,
            'unknown': int
        }
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    summary = {'total': 0, 'up': 0, 'down': 0, 'unknown': 0}
    
    # Count domains
    cursor.execute("SELECT status FROM domain_asset")
    for row in cursor.fetchall():
        summary['total'] += 1
        status = row['status'] or 'unknown'
        if status in summary:
            summary[status] += 1
        else:
            summary['unknown'] += 1
    
    # Count subdomains
    cursor.execute("SELECT status FROM subdomain_asset")
    for row in cursor.fetchall():
        summary['total'] += 1
        status = row['status'] or 'unknown'
        if status in summary:
            summary[status] += 1
        else:
            summary['unknown'] += 1
    
    conn.close()
    
    return summary


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description='Liveness checker')
    parser.add_argument('--check-all', action='store_true', help='Check all assets')
    parser.add_argument('--summary', action='store_true', help='Get liveness summary')
    
    args = parser.parse_args()
    
    if args.check_all:
        result = check_all_liveness()
        print(f"Down: {result['down']}")
        print(f"Recovered: {result['recovered']}")
        print(f"Still down: {result['still_down']}")
        print(f"Unchanged: {result['unchanged']}")
    elif args.summary:
        summary = get_liveness_summary()
        print(f"Total: {summary['total']}")
        print(f"Up: {summary['up']}")
        print(f"Down: {summary['down']}")
        print(f"Unknown: {summary['unknown']}")
    else:
        parser.print_help()