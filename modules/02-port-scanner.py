"""
Module: 02-port-scanner.py
Purpose: Nmap-based port scanning for all cycles (initial, medium, long)

Cycles:
    - initial: Fast scan (--top-ports 100)
    - medium:  Standard scan (--top-ports 250)
    - long:    Full scan (-p-, all 65535 ports)

Dependencies:
    - nmap (system installation)
    - utils/db_utils.py
    
Database tables used:
    - ip_asset (read targets, update last_scanned)
    - ports (write results)
    - scan_queue (queue management)
    - scan_history (audit trail)
"""

import sys
import os
import subprocess
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.db_utils import (
    get_db_connection,
    log_scan
)

# Constants
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, 'db', 'lazyeasm.db')
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')

# Nmap scan profiles
SCAN_PROFILES = {
    'initial': {
        'ports': '--top-ports 100',
        'options': '-sV -T3',
        'description': 'Fast scan (top 100 ports)',
        'timeout': 120
    },
    'medium': {
        'ports': '--top-ports 250',
        'options': '-sV -T3',
        'description': 'Standard scan (top 250 ports)',
        'timeout': 300
    },
    'long': {
        'ports': '-p-',
        'options': '-sV -T5',
        'description': 'Full scan (all 65535 ports)',
        'timeout': 1800
    }
}

# Cloudflare IP ranges to always skip
CLOUDFLARE_RANGES = [
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
]


class PortScanner:
    """
    Nmap-based port scanner with multi-cycle support.
    """
    
    def __init__(self, cycle: str = 'medium', skip_shared: bool = True, 
                 skip_cloudflare: bool = True, skip_down: bool = True):
        """
        Initialize port scanner.
        
        Args:
            cycle: 'initial', 'medium', or 'long'
            skip_shared: Skip shared hosting IPs
            skip_cloudflare: Always skip Cloudflare IPs
            skip_down: Skip IPs with status='down'
        """
        if cycle not in SCAN_PROFILES:
            raise ValueError(f"Invalid cycle: {cycle}. Must be one of: {list(SCAN_PROFILES.keys())}")
        
        self.cycle = cycle
        self.skip_shared = skip_shared
        self.skip_cloudflare = skip_cloudflare
        self.skip_down = skip_down
        self.logger = self._setup_logging()
        self.db_path = DB_PATH
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging to file and console."""
        os.makedirs(LOGS_DIR, exist_ok=True)
        log_file = os.path.join(LOGS_DIR, f'port-scanner-{datetime.now().strftime("%Y-%m-%d")}.log')
        
        logger = logging.getLogger('PortScanner')
        logger.setLevel(logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        if logger.handlers:
            logger.handlers.clear()
        
        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        
        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def check_nmap_installed(self) -> Tuple[bool, str]:
        """
        Check if nmap is installed on the system.
        
        Returns:
            (is_installed: bool, version: str or None)
        """
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Extract version from output
                version_line = result.stdout.split('\n')[0]
                return True, version_line
            return False, None
        except FileNotFoundError:
            return False, "Nmap is not installed"
        except subprocess.TimeoutExpired:
            return False, "Nmap version check timed out"
        except Exception as e:
            return False, f"Error checking nmap: {str(e)}"
    
    def get_targets(self) -> List[Dict]:
        """
        Get IPs/domains to scan from database.
        
        Filters:
            - status='up' (if skip_down)
            - NOT shared hosting (if skip_shared)
            - NOT cloudflare (always, if skip_cloudflare)
        
        Returns:
            List of dicts with target info
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT ip_id, ip_value, is_shared, shared_provider, status, last_scanned
            FROM ip_asset
            WHERE 1=1
        """
        params = []
        
        # Skip down IPs
        if self.skip_down:
            query += " AND status = 'up'"
        
        # Skip shared hosting
        if self.skip_shared:
            query += " AND (is_shared = 0 OR is_shared IS NULL)"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        targets = []
        for row in results:
            target = dict(row)
            
            # Always skip Cloudflare (hardcoded check)
            if self.skip_cloudflare:
                if target.get('shared_provider') and 'cloudflare' in target.get('shared_provider', '').lower():
                    self.logger.info(f"Skipping Cloudflare IP: {target['ip_value']}")
                    continue
            
            targets.append(target)
        
        return targets
    
    def run_nmap(self, target: str, profile: str = 'medium') -> Tuple[bool, Optional[str], List[Dict]]:
        """
        Run nmap scan on a single target.
        
        Args:
            target: IP address to scan
            profile: 'initial', 'medium', or 'long'
        
        Returns:
            (success: bool, error: str or None, ports: list)
        """
        installed, version_or_error = self.check_nmap_installed()
        if not installed:
            return False, version_or_error, []
        
        scan_config = SCAN_PROFILES.get(profile, SCAN_PROFILES['medium'])
        timeout = scan_config['timeout']
        
        # Build command - ports argument needs to be split if it contains spaces
        ports_args = scan_config['ports'].split()
        
        cmd = [
            'nmap',
            '-sV',
            '-T3'
        ] + ports_args + [
            '-oX', '-',
            target
        ]
        
        self.logger.info(f"Running nmap on {target} ({scan_config['description']})")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown nmap error"
                self.logger.error(f"Nmap failed for {target}: {error_msg}")
                return False, error_msg, []
            
            # Parse XML output
            ports = self._parse_nmap_xml(result.stdout)
            return True, None, ports
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap timeout for {target} after {timeout}s")
            return False, f"Scan timeout after {timeout}s", []
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {str(e)}")
            return False, str(e), []
    
    def _parse_nmap_xml(self, xml_output: str) -> List[Dict]:
        """
        Parse nmap XML output to extract port information.
        
        Args:
            xml_output: Raw XML from nmap
        
        Returns:
            List of port dicts
        """
        ports = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall('host'):
                # Check host status
                status = host.find('status')
                if status is not None and status.get('state') == 'down':
                    continue
                
                ports_elem = host.find('ports')
                if ports_elem is None:
                    continue
                
                for port in ports_elem.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol', 'tcp')
                    
                    # Get port state
                    state = port.find('state')
                    if state is not None and state.get('state') != 'open':
                        continue
                    
                    # Get service info
                    service = port.find('service')
                    service_name = 'unknown'
                    banner = None
                    
                    if service is not None:
                        service_name = service.get('name', 'unknown')
                        product = service.get('product', '')
                        version = service.get('version', '')
                        extrainfo = service.get('extrainfo', '')
                        
                        # Build banner string
                        banner_parts = []
                        if product:
                            banner_parts.append(product)
                        if version:
                            banner_parts.append(version)
                        if extrainfo:
                            banner_parts.append(extrainfo)
                        banner = ' '.join(banner_parts) if banner_parts else None
                    
                    ports.append({
                        'port_num': int(port_id),
                        'protocol': protocol,
                        'service': service_name,
                        'banner': banner
                    })
        
        except ET.ParseError as e:
            self.logger.error(f"XML parse error: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing nmap output: {e}")
        
        return ports
    
    def save_ports(self, ip_id: int, ports: List[Dict]) -> int:
        """
        Save discovered ports to database.
        
        Args:
            ip_id: IP ID in database
            ports: List of port dicts from _parse_nmap_xml
        
        Returns:
            Number of ports saved
        """
        if not ports:
            return 0
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        saved_count = 0
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for port in ports:
            try:
                # Check if port already exists
                cursor.execute('''
                    SELECT port_id FROM ports 
                    WHERE ip_id = ? AND port_num = ? AND protocol = ?
                ''', (ip_id, port['port_num'], port['protocol']))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing port
                    cursor.execute('''
                        UPDATE ports 
                        SET service_name = ?, banner = ?
                        WHERE port_id = ?
                    ''', (port['service'], port['banner'], existing['port_id']))
                else:
                    # Insert new port
                    cursor.execute('''
                        INSERT INTO ports (ip_id, port_num, protocol, service_name, banner, first_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (ip_id, port['port_num'], port['protocol'], port['service'], port['banner'], timestamp))
                
                saved_count += 1
                
            except Exception as e:
                self.logger.error(f"Error saving port {port['port_num']} for ip_id {ip_id}: {e}")
        
        conn.commit()
        conn.close()
        
        return saved_count
    
    def update_scan_timestamp(self, ip_id: int):
        """Update last_scanned timestamp for an IP."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
            UPDATE ip_asset 
            SET last_scanned = ? 
            WHERE ip_id = ?
        ''', (timestamp, ip_id))
        
        conn.commit()
        conn.close()
    
    def scan_single_ip(self, ip_id: int, ip_value: str) -> Dict:
        """
        Full scan pipeline for a single IP.
        
        Args:
            ip_id: Database IP ID
            ip_value: IP address string
        
        Returns:
            Result dict with stats
        """
        result = {
            'ip_id': ip_id,
            'ip_value': ip_value,
            'success': False,
            'ports_found': 0,
            'error': None
        }
        
        # Run nmap scan
        success, error, ports = self.run_nmap(ip_value, self.cycle)
        
        if not success:
            result['error'] = error
            self.logger.error(f"Scan failed for {ip_value}: {error}")
            return result
        
        # Save ports to database
        saved_count = self.save_ports(ip_id, ports)
        
        # Update scan timestamp
        self.update_scan_timestamp(ip_id)
        
        result['success'] = True
        result['ports_found'] = saved_count
        
        self.logger.info(f"Scanned {ip_value}: found {saved_count} open ports")
        
        return result
    
    def run(self, targets: Optional[List[Dict]] = None) -> Dict:
        """
        Main entry point. Run port scanner.
        
        Args:
            targets: Optional list of targets to scan. If None, get from DB.
        
        Returns:
            Stats dict
        """
        self.logger.info("=" * 60)
        self.logger.info(f"Starting port scanner (cycle: {self.cycle})")
        self.logger.info(f"Skip shared: {self.skip_shared}, Skip cloudflare: {self.skip_cloudflare}, Skip down: {self.skip_down}")
        
        # Check nmap installation
        installed, version = self.check_nmap_installed()
        if not installed:
            self.logger.error(version)
            return {
                'total_targets': 0,
                'scanned': 0,
                'skipped': 0,
                'failed': 0,
                'ports_found': 0,
                'errors': [version]
            }
        
        self.logger.info(f"Nmap version: {version}")
        
        # Get targets
        if targets is None:
            targets = self.get_targets()
        
        total_targets = len(targets)
        self.logger.info(f"Found {total_targets} targets to scan")
        
        if total_targets == 0:
            self.logger.info("No targets to scan")
            return {
                'total_targets': 0,
                'scanned': 0,
                'skipped': 0,
                'failed': 0,
                'ports_found': 0,
                'errors': []
            }
        
        stats = {
            'total_targets': total_targets,
            'scanned': 0,
            'skipped': 0,
            'failed': 0,
            'ports_found': 0,
            'errors': []
        }
        
        scan_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Scan each target
        for i, target in enumerate(targets, 1):
            ip_id = target['ip_id']
            ip_value = target['ip_value']
            
            self.logger.info(f"Progress: {i}/{total_targets} - Scanning {ip_value}")
            
            # Run scan
            result = self.scan_single_ip(ip_id, ip_value)
            
            if result['success']:
                stats['scanned'] += 1
                stats['ports_found'] += result['ports_found']
            else:
                stats['failed'] += 1
                if result['error']:
                    stats['errors'].append(f"{ip_value}: {result['error']}")
        
        scan_completed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log to scan_history
        log_scan(
            scan_type=f'nmap_{self.cycle}',
            target=f'batch:{total_targets}',
            status='completed',
            items_found=stats['ports_found'],
            started_at=scan_started,
            completed_at=scan_completed
        )
        
        self.logger.info("=" * 60)
        self.logger.info(f"Scan complete")
        self.logger.info(f"  Total: {stats['total_targets']}")
        self.logger.info(f"  Scanned: {stats['scanned']}")
        self.logger.info(f"  Failed: {stats['failed']}")
        self.logger.info(f"  Ports found: {stats['ports_found']}")
        if stats['errors']:
            self.logger.info(f"  Errors: {len(stats['errors'])}")
            for error in stats['errors'][:5]:  # Show first 5 errors
                self.logger.info(f"    - {error}")
        self.logger.info("=" * 60)
        
        return stats


def run_scanner(cycle: str = 'medium', skip_shared: bool = True, 
                skip_cloudflare: bool = True, skip_down: bool = True) -> Dict:
    """
    Convenience function for CLI/cron.
    
    Args:
        cycle: 'initial', 'medium', or 'long'
        skip_shared: Skip shared hosting IPs
        skip_cloudflare: Always skip Cloudflare
        skip_down: Skip down IPs
    
    Returns:
        Stats dict
    """
    scanner = PortScanner(
        cycle=cycle,
        skip_shared=skip_shared,
        skip_cloudflare=skip_cloudflare,
        skip_down=skip_down
    )
    return scanner.run()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Port scanner for LazyEASM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python modules/02-port-scanner.py                      # Default: medium scan
  python modules/02-port-scanner.py --cycle initial     # Fast scan (100 ports)
  python modules/02-port-scanner.py --cycle long        # Full scan (all ports)
  python modules/02-port-scanner.py --no-skip-shared     # Include shared hosting
  python modules/02-port-scanner.py --skip-down          # Skip down IPs
        """
    )
    
    parser.add_argument(
        '--cycle', '-c',
        choices=['initial', 'medium', 'long'],
        default='medium',
        help='Scan cycle type (default: medium)'
    )
    parser.add_argument(
        '--skip-shared',
        action='store_true',
        default=True,
        help='Skip shared hosting IPs (default: True)'
    )
    parser.add_argument(
        '--no-skip-shared',
        dest='skip_shared',
        action='store_false',
        help='Include shared hosting IPs'
    )
    parser.add_argument(
        '--skip-down',
        action='store_true',
        default=True,
        help='Skip IPs with status=down (default: True)'
    )
    parser.add_argument(
        '--no-skip-down',
        dest='skip_down',
        action='store_false',
        help='Include down IPs'
    )
    
    args = parser.parse_args()
    
    result = run_scanner(
        cycle=args.cycle,
        skip_shared=args.skip_shared,
        skip_down=args.skip_down
    )
    
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Status: {'Success' if result['failed'] == 0 else 'Partial'}")
    print(f"\nStats:")
    print(f"  Total targets: {result['total_targets']}")
    print(f"  Scanned: {result['scanned']}")
    print(f"  Skipped: {result.get('skipped', 0)}")
    print(f"  Failed: {result['failed']}")
    print(f"  Ports found: {result['ports_found']}")
    
    if result['errors']:
        print(f"\nErrors ({len(result['errors'])}):")
        for error in result['errors'][:10]:
            print(f"  - {error}")
    
    sys.exit(0 if result['failed'] == 0 else 1)