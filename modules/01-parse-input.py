"""
Module: 01-parse-input.py
Purpose: Parse and validate input targets for LazyEASM
Functions:
    - InputParser: Main parser class
    - run_parser: Convenience function for CLI/Flask

Pipeline:
    1. Read input (textarea/file)
    2. Normalize targets (strip protocol, path, port)
    3. Categorize (IP, CIDR, Domain, Subdomain)
    4. Expand CIDR/ranges
    5. Check duplicates in DB
    6. DNS resolution
    7. Wildcard detection
    8. Shared hosting detection
    9. Ping check
    10. Save to database
    11. Log results
"""

import sys
import os
import re
import ipaddress
import logging
import random
import string
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

from utils.utility import (
    ping_host,
    dns_lookup,
    is_private_ip,
    is_wildcard_domain,
    is_shared_hosting,
    get_domain_from_subdomain
)
from utils.db_utils import (
    domain_exists,
    subdomain_exists,
    ip_exists,
    upsert_domain,
    upsert_subdomain,
    upsert_ip,
    create_domain_resolution,
    create_subdomain_resolution,
    save_scan_hint,
    log_scan
)

MAX_CIDR_EXPANSION = 20
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')


class InputParser:
    """
    Parse and validate input targets for EASM.
    """
    
    def __init__(self, allow_private: bool = False, max_cidr: int = MAX_CIDR_EXPANSION):
        self.allow_private = allow_private
        self.max_cidr = max_cidr
        self.logs_dir = LOGS_DIR
        self.setup_logging()
    
    def setup_logging(self):
        """Initialize logging to file."""
        os.makedirs(self.logs_dir, exist_ok=True)
        log_file = os.path.join(self.logs_dir, f'parser-{datetime.now().strftime("%Y-%m-%d")}.log')
        
        self.logger = logging.getLogger('LazyEASM-Parser')
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
    
    def normalize_target(self, raw: str) -> dict:
        """
        Normalize a single target string.
        
        Returns:
            {
                'original': raw input,
                'host': normalized host,
                'type': 'ip', 'cidr', 'domain', 'subdomain',
                'port_hint': None or int,
                'path_hint': None or str
            }
        """
        original = raw.strip()
        target = original.lower()
        
        port_hint = None
        path_hint = None
        
        protocol_pattern = r'^https?://'
        target = re.sub(protocol_pattern, '', target)
        
        cidr_pattern = r'/\d{1,2}$'
        if not re.search(cidr_pattern, target):
            path_pattern = r'/[^\d].*$'
            path_match = re.search(path_pattern, target)
            if path_match:
                path_hint = path_match.group(0)
                target = re.sub(path_pattern, '', target)
        
        port_pattern = r':(\d+)$'
        port_match = re.search(port_pattern, target)
        if port_match:
            try:
                port_hint = int(port_match.group(1))
                if 1 <= port_hint <= 65535:
                    pass
                else:
                    port_hint = None
            except ValueError:
                port_hint = None
            target = re.sub(port_pattern, '', target)
        
        target = target.rstrip('.')
        
        target = target.strip()
        
        target_type = self._determine_type(target)
        
        return {
            'original': original,
            'host': target,
            'type': target_type,
            'port_hint': port_hint,
            'path_hint': path_hint
        }
    
    def _determine_type(self, target: str) -> str:
        """Determine if target is IP, CIDR, Domain, or Subdomain."""
        cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
        if re.match(cidr_pattern, target):
            return 'cidr'
        
        range_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
        if re.match(range_pattern, target):
            return 'range'
        
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass
        
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(target)
            if extracted.suffix:
                if extracted.subdomain:
                    return 'subdomain'
                else:
                    return 'domain'
        
        domain_pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
        if re.match(domain_pattern, target):
            parts = target.split('.')
            if len(parts) >= 3:
                return 'subdomain'
            else:
                return 'domain'
        
        return 'invalid'
    
    def expand_cidr(self, cidr: str) -> tuple:
        """
        Expand CIDR to list of IPs.
        
        Returns:
            (success: bool, ips: list, error: str or None)
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            prefix_len = network.prefixlen
            if prefix_len < self.max_cidr:
                max_hosts = 2 ** (32 - self.max_cidr)
                return False, [], f"CIDR too large. Maximum expansion is /{self.max_cidr} ({max_hosts} IPs). Got /{prefix_len}"
            
            ips = [str(ip) for ip in network.hosts()]
            return True, ips, None
        except ValueError as e:
            return False, [], f"Invalid CIDR: {str(e)}"
    
    def expand_range(self, start_ip: str, end_ip: str) -> tuple:
        """
        Expand IP range to list of IPs.
        
        Returns:
            (success: bool, ips: list, error: str or None)
        """
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            if start > end:
                return False, [], f"Start IP {start_ip} is greater than end IP {end_ip}"
            
            ips = []
            current = start
            count = 0
            max_count = 2 ** (32 - self.max_cidr)
            
            while current <= end:
                ips.append(str(current))
                current += 1
                count += 1
                
                if count > max_count:
                    return False, [], f"Range too large. Maximum is {max_count} IPs"
            
            return True, ips, None
        except ValueError as e:
            return False, [], f"Invalid IP in range: {str(e)}"
    
    def validate_ip(self, ip: str) -> tuple:
        """
        Validate IP address format and check if private.
        
        Returns:
            (is_valid: bool, reason: str or None)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.version != 4:
                return False, "Only IPv4 addresses are supported"
            
            if not self.allow_private and is_private_ip(ip):
                return False, f"Private/reserved IP range: {ip}"
            
            if ip_obj.is_loopback:
                return False, f"Loopback address: {ip}"
            
            if ip_obj.is_multicast:
                return False, f"Multicast address: {ip}"
            
            if ip_obj.is_unspecified:
                return False, f"Unspecified address: {ip}"
            
            return True, None
        except ValueError as e:
            return False, f"Invalid IP format: {str(e)}"
    
    def validate_domain(self, domain: str) -> tuple:
        """
        Validate domain format.
        
        Returns:
            (is_valid: bool, reason: str or None)
        """
        if not domain or len(domain) < 2:
            return False, "Domain too short"
        
        if len(domain) > 253:
            return False, "Domain too long (max 253 characters)"
        
        domain_pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
        if not re.match(domain_pattern, domain):
            return False, f"Invalid domain format: {domain}"
        
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            if not extracted.suffix:
                return False, f"Invalid or unknown TLD: {domain}"
        
        return True, None
    
    def categorize_targets(self, normalized_list: list) -> dict:
        """
        Categorize normalized targets into IPs, domains, subdomains, etc.
        
        Returns:
            {
                'ips': [...],
                'cidrs': [{'cidr': '...', 'count': N}, ...],
                'ranges': [{'start': '...', 'end': '...'}, ...],
                'domains': [...],
                'subdomains': [{'subdomain': '...', 'parent': '...'}, ...],
                'invalid': [{'input': '...', 'reason': '...'}, ...],
                'hints': {'domain': {'ports': [...], 'paths': [...]}, ...}
            }
        """
        categorized = {
            'ips': [],
            'cidrs': [],
            'ranges': [],
            'domains': [],
            'subdomains': [],
            'invalid': [],
            'hints': {}
        }
        
        for item in normalized_list:
            host = item['host']
            target_type = item['type']
            
            if target_type == 'ip':
                is_valid, reason = self.validate_ip(host)
                if is_valid:
                    categorized['ips'].append(host)
                else:
                    categorized['invalid'].append({'input': item['original'], 'reason': reason})
            
            elif target_type == 'cidr':
                success, ips, error = self.expand_cidr(host)
                if success:
                    valid_ips = []
                    for ip in ips:
                        is_valid, _ = self.validate_ip(ip)
                        if is_valid:
                            valid_ips.append(ip)
                    categorized['ips'].extend(valid_ips)
                else:
                    categorized['invalid'].append({'input': item['original'], 'reason': error})
            
            elif target_type == 'range':
                parts = host.split('-')
                if len(parts) == 2:
                    success, ips, error = self.expand_range(parts[0], parts[1])
                    if success:
                        valid_ips = []
                        for ip in ips:
                            is_valid, _ = self.validate_ip(ip)
                            if is_valid:
                                valid_ips.append(ip)
                        categorized['ips'].extend(valid_ips)
                    else:
                        categorized['invalid'].append({'input': item['original'], 'reason': error})
                else:
                    categorized['invalid'].append({'input': item['original'], 'reason': 'Invalid range format'})
            
            elif target_type == 'domain':
                is_valid, reason = self.validate_domain(host)
                if is_valid:
                    categorized['domains'].append(host)
                else:
                    categorized['invalid'].append({'input': item['original'], 'reason': reason})
            
            elif target_type == 'subdomain':
                is_valid, reason = self.validate_domain(host)
                if is_valid:
                    parent_domain, subdomain = get_domain_from_subdomain(host)
                    categorized['subdomains'].append({
                        'subdomain': subdomain,
                        'parent': parent_domain
                    })
                else:
                    categorized['invalid'].append({'input': item['original'], 'reason': reason})
            
            else:
                categorized['invalid'].append({'input': item['original'], 'reason': 'Unknown target type'})
            
            if item['port_hint'] or item['path_hint']:
                target_key = host
                if target_key not in categorized['hints']:
                    categorized['hints'][target_key] = {'ports': [], 'paths': []}
                
                if item['port_hint']:
                    if item['port_hint'] not in categorized['hints'][target_key]['ports']:
                        categorized['hints'][target_key]['ports'].append(item['port_hint'])
                
                if item['path_hint']:
                    if item['path_hint'] not in categorized['hints'][target_key]['paths']:
                        categorized['hints'][target_key]['paths'].append(item['path_hint'])
        
        return categorized
    
    def check_duplicates(self, categorized: dict) -> dict:
        """
        Check database for existing assets.
        
        Returns:
            {
                'new_ips': [...],
                'new_domains': [...],
                'new_subdomains': [{'subdomain': '...', 'parent': '...'}, ...],
                'existing_ips': [...],
                'existing_domains': [...],
                'existing_subdomains': [{'subdomain': '...', 'parent': '...'}, ...]
            }
        """
        result = {
            'new_ips': [],
            'new_domains': [],
            'new_subdomains': [],
            'existing_ips': [],
            'existing_domains': [],
            'existing_subdomains': [],
            'hints': categorized.get('hints', {})
        }
        
        for ip in categorized.get('ips', []):
            if ip_exists(ip):
                result['existing_ips'].append(ip)
                self.logger.info(f"Existing IP: {ip}")
            else:
                result['new_ips'].append(ip)
        
        for domain in categorized.get('domains', []):
            if domain_exists(domain):
                result['existing_domains'].append(domain)
                self.logger.info(f"Existing domain: {domain}")
            else:
                result['new_domains'].append(domain)
        
        for sub in categorized.get('subdomains', []):
            if subdomain_exists(sub['subdomain']):
                result['existing_subdomains'].append(sub)
                self.logger.info(f"Existing subdomain: {sub['subdomain']}")
            else:
                result['new_subdomains'].append(sub)
        
        return result
    
    def resolve_domain(self, domain: str) -> tuple:
        """
        DNS resolve a domain.
        
        Returns:
            (resolved_ips: list, wildcard_info: dict or None)
        """
        ips = dns_lookup(domain, 'A')
        
        if not ips:
            return [], None
        
        is_wildcard, wildcard_ip = is_wildcard_domain(domain)
        
        wildcard_info = None
        if is_wildcard:
            wildcard_info = {
                'is_wildcard': True,
                'wildcard_ip': wildcard_ip
            }
            self.logger.warning(f"Wildcard DNS detected for {domain}: resolves to {wildcard_ip}")
        
        return ips, wildcard_info
    
    def check_liveness(self, targets: list) -> dict:
        """
        Ping check for assets.
        
        Returns:
            {
                'up': [...],
                'down': [...]
            }
        """
        result = {
            'up': [],
            'down': []
        }
        
        for target in targets:
            if ping_host(target, count=2):
                result['up'].append(target)
            else:
                result['down'].append(target)
        
        return result
    
    def process_input(self, raw_input: str) -> dict:
        """
        Full processing pipeline.
        
        Args:
            raw_input: Newline/comma separated targets
        
        Returns:
            Result dict with stats and asset lists
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting parser")
        self.logger.info(f"Allow private IPs: {self.allow_private}")
        self.logger.info(f"Max CIDR: /{self.max_cidr}")
        
        scan_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        lines = re.split(r'[\n,]+', raw_input)
        raw_list = [line.strip() for line in lines if line.strip()]
        
        self.logger.info(f"Total input lines: {len(raw_list)}")
        
        normalized_list = []
        for raw in raw_list:
            normalized = self.normalize_target(raw)
            normalized_list.append(normalized)
        
        self.logger.info(f"Normalized {len(normalized_list)} targets")
        
        categorized = self.categorize_targets(normalized_list)
        
        self.logger.info(f"Categorized: {len(categorized['ips'])} IPs, {len(categorized['domains'])} domains, {len(categorized['subdomains'])} subdomains")
        self.logger.info(f"Invalid targets: {len(categorized['invalid'])}")
        
        for invalid in categorized['invalid']:
            self.logger.warning(f"Invalid: {invalid['input']} - {invalid['reason']}")
        
        deduped = self.check_duplicates(categorized)
        
        self.logger.info(f"New: {len(deduped['new_ips'])} IPs, {len(deduped['new_domains'])} domains, {len(deduped['new_subdomains'])} subdomains")
        self.logger.info(f"Existing: {len(deduped['existing_ips'])} IPs, {len(deduped['existing_domains'])} domains, {len(deduped['existing_subdomains'])} subdomains")
        
        stats = {
            'total_input': len(raw_list),
            'new_ips': 0,
            'new_domains': 0,
            'new_subdomains': 0,
            'existing_ips': len(deduped['existing_ips']),
            'existing_domains': len(deduped['existing_domains']),
            'existing_subdomains': len(deduped['existing_subdomains']),
            'invalid': len(categorized['invalid']),
            'saved_up': 0,
            'saved_down': 0
        }
        
        new_assets = {
            'domains': [],
            'subdomains': [],
            'ips': [],
            'wildcard_domains': []
        }
        
        down_assets = {
            'domains': [],
            'subdomains': [],
            'ips': []
        }
        
        saved_ids = {
            'domains': {},
            'subdomains': {},
            'ips': {}
        }
        
        for domain in deduped['new_domains']:
            self.logger.info(f"Processing new domain: {domain}")
            
            ips, wildcard_info = self.resolve_domain(domain)
            
            is_wildcard = 1 if wildcard_info else 0
            wildcard_ip = wildcard_info['wildcard_ip'] if wildcard_info else None
            
            status = 'up' if ping_host(domain, count=2) else 'down'
            
            dom_id = upsert_domain(domain, is_wildcard=is_wildcard, wildcard_ip=wildcard_ip, status=status)
            saved_ids['domains'][domain] = dom_id
            
            if is_wildcard:
                new_assets['wildcard_domains'].append({
                    'domain': domain,
                    'wildcard_ip': wildcard_ip
                })
            
            new_assets['domains'].append(domain)
            stats['new_domains'] += 1
            
            if status == 'up':
                stats['saved_up'] += 1
            else:
                stats['saved_down'] += 1
                down_assets['domains'].append(domain)
            
            if ips:
                ip_ids = []
                for ip in ips:
                    is_shared, provider = is_shared_hosting(ip)
                    ip_id = upsert_ip(ip, is_shared=1 if is_shared else 0, shared_provider=provider, status='up')
                    ip_ids.append(ip_id)
                    saved_ids['ips'][ip] = ip_id
                
                create_domain_resolution(dom_id, ip_ids)
            
            if domain in deduped['hints']:
                hints = deduped['hints'][domain]
                for port in hints.get('ports', []):
                    save_scan_hint(domain, 'port', str(port))
                for path in hints.get('paths', []):
                    save_scan_hint(domain, 'path', path)
        
        for sub in deduped['new_subdomains']:
            subdomain_name = sub['subdomain']
            parent_domain = sub['parent']
            
            self.logger.info(f"Processing new subdomain: {subdomain_name} (parent: {parent_domain})")
            
            if not domain_exists(parent_domain):
                parent_id = upsert_domain(parent_domain, status='up')
                saved_ids['domains'][parent_domain] = parent_id
                new_assets['domains'].append(parent_domain)
                stats['new_domains'] += 1
            else:
                parent_id = saved_ids['domains'].get(parent_domain)
                if not parent_id:
                    parent_data = domain_exists(parent_domain)
                    parent_id = parent_data
            
            resolved_ips, wildcard_info = self.resolve_domain(subdomain_name)
            
            if wildcard_info:
                self.logger.warning(f"Subdomain {subdomain_name} resolves to wildcard IP {wildcard_info['wildcard_ip']}")
            
            status = 'up' if ping_host(subdomain_name, count=2) else 'down'
            
            sub_id = upsert_subdomain(subdomain_name, parent_id, status=status)
            saved_ids['subdomains'][subdomain_name] = sub_id
            
            new_assets['subdomains'].append(subdomain_name)
            stats['new_subdomains'] += 1
            
            if status == 'down':
                down_assets['subdomains'].append(subdomain_name)
            
            if resolved_ips:
                ip_ids = []
                for ip in resolved_ips:
                    is_shared, provider = is_shared_hosting(ip)
                    ip_id = upsert_ip(ip, is_shared=1 if is_shared else 0, shared_provider=provider, status='up')
                    ip_ids.append(ip_id)
                    saved_ids['ips'][ip] = ip_id
                
                create_subdomain_resolution(sub_id, ip_ids)
            
            if subdomain_name in deduped['hints']:
                hints = deduped['hints'][subdomain_name]
                for port in hints.get('ports', []):
                    save_scan_hint(subdomain_name, 'port', str(port))
                for path in hints.get('paths', []):
                    save_scan_hint(subdomain_name, 'path', path)
        
        for ip in deduped['new_ips']:
            self.logger.info(f"Processing new IP: {ip}")
            
            is_shared, provider = is_shared_hosting(ip)
            
            status = 'up' if ping_host(ip, count=2) else 'down'
            
            ip_id = upsert_ip(ip, is_shared=1 if is_shared else 0, shared_provider=provider, status=status)
            saved_ids['ips'][ip] = ip_id
            
            new_assets['ips'].append(ip)
            stats['new_ips'] += 1
            
            if status == 'down':
                down_assets['ips'].append(ip)
                stats['saved_down'] += 1
            else:
                stats['saved_up'] += 1
            
            if ip in deduped['hints']:
                hints = deduped['hints'][ip]
                for port in hints.get('ports', []):
                    save_scan_hint(ip, 'port', str(port))
        
        scan_completed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        total_items = stats['new_domains'] + stats['new_subdomains'] + stats['new_ips']
        log_scan('parser', f"batch:{len(raw_list)}", 'completed', items_found=total_items, started_at=scan_started, completed_at=scan_completed)
        
        self.logger.info("=" * 60)
        self.logger.info("Parser completed")
        self.logger.info(f"Stats: {stats}")
        self.logger.info("=" * 60)
        
        return {
            'status': 'success' if total_items > 0 else 'no_new_assets',
            'stats': stats,
            'new_assets': new_assets,
            'existing_assets': {
                'domains': deduped['existing_domains'],
                'subdomains': [s['subdomain'] for s in deduped['existing_subdomains']],
                'ips': deduped['existing_ips']
            },
            'down_assets': down_assets,
            'invalid': categorized['invalid'],
            'hints_saved': [
                {'target': k, 'type': 'port', 'values': v['ports']} for k, v in deduped.get('hints', {}).items() if v.get('ports')
            ] + [
                {'target': k, 'type': 'path', 'values': v['paths']} for k, v in deduped.get('hints', {}).items() if v.get('paths')
            ]
        }


def run_parser(raw_input: str, allow_private: bool = False) -> dict:
    """
    Convenience function for CLI or Flask.
    
    Args:
        raw_input: Newline/comma separated targets
        allow_private: Allow private IP ranges
    
    Returns:
        Result dict
    """
    parser = InputParser(allow_private=allow_private)
    return parser.process_input(raw_input)


if __name__ == '__main__':
    import argparse
    
    arg_parser = argparse.ArgumentParser(description='Parse input targets for LazyEASM')
    arg_parser.add_argument('--file', '-f', help='Input file path')
    arg_parser.add_argument('--target', '-t', help='Single target')
    arg_parser.add_argument('--allow-private', action='store_true', help='Allow private IPs')
    
    args = arg_parser.parse_args()
    
    if args.file:
        with open(args.file, 'r') as f:
            raw_input = f.read()
    elif args.target:
        raw_input = args.target
    else:
        print("Enter targets (one per line, Ctrl+D to finish):")
        raw_input = sys.stdin.read()
    
    result = run_parser(raw_input, allow_private=args.allow_private)
    
    print("\n" + "=" * 60)
    print("RESULT")
    print("=" * 60)
    print(f"Status: {result['status']}")
    print(f"\nStats:")
    for key, value in result['stats'].items():
        print(f"  {key}: {value}")
    
    if result['new_assets']['domains']:
        print(f"\nNew Domains ({len(result['new_assets']['domains'])}):")
        for domain in result['new_assets']['domains']:
            print(f"  - {domain}")
    
    if result['new_assets']['subdomains']:
        print(f"\nNew Subdomains ({len(result['new_assets']['subdomains'])}):")
        for sub in result['new_assets']['subdomains']:
            print(f"  - {sub}")
    
    if result['new_assets']['ips']:
        print(f"\nNew IPs ({len(result['new_assets']['ips'])}):")
        for ip in result['new_assets']['ips']:
            print(f"  - {ip}")
    
    if result['invalid']:
        print(f"\nInvalid ({len(result['invalid'])}):")
        for inv in result['invalid']:
            print(f"  - {inv['input']}: {inv['reason']}")
    
    if result['down_assets']['domains'] or result['down_assets']['subdomains'] or result['down_assets']['ips']:
        print(f"\nDown Assets:")
        for domain in result['down_assets']['domains']:
            print(f"  - Domain: {domain}")
        for sub in result['down_assets']['subdomains']:
            print(f"  - Subdomain: {sub}")
        for ip in result['down_assets']['ips']:
            print(f"  - IP: {ip}")