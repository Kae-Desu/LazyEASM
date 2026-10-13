"""
Module: ExpandAsset.py
Purpose: Phase 1 - Asset Discovery and Initialization

Flow:
    1. Parse user input (domains, subdomains, IPs, CIDRs)
    2. For each domain/subdomain:
        a. Extract root domain
        b. Check if root exists in DB
        c. If NOT exists: Expand via CTLogs + SecurityTrails
        d. If EXISTS: Add subdomain only (skip expansion)
        e. DNS resolve + Ping check (parallel)
        f. Store in database
    3. For each IP/CIDR:
        a. Ping check
        b. Store in database
    4. Return stats

Target: 15 minutes per domain
"""

import os
import sys
import logging
import requests
import time
import platform
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env, get_log_dir
from utils.parsing import (
    parse_input, normalize_hostname, extract_root_domain,
    validate_ip, validate_cidr, expand_cidr, categorize_targets,
    is_valid_domain
)
from utils.db_utils import (
    get_db_connection,
    domain_exists, subdomain_exists, ip_exists,
    filter_new_subdomains, filter_new_ips,
    get_domain_id, get_subdomain_id, get_ip_id,
    upsert_domain, upsert_subdomain, upsert_ip,
    create_subdomain_resolution, create_domain_resolution,
    update_domain_status, update_subdomain_status, update_ip_status,
    add_container_domain, is_domain_expanded, set_domain_expanded,
    log_scan
)
from utils.utility import (
    dns_lookup, dns_batch, ping_batch, resolve_and_ping_batch,
    is_private_ip, is_shared_hosting, is_wildcard_domain
)

LOGS_DIR = get_log_dir()

log_file = os.path.join(LOGS_DIR, f"phase1-{datetime.now().strftime('%Y-%m-%d')}.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class Phase1Expander:
    """
    Phase 1: Asset Discovery and Initialization
    
    Handles:
        - CT logs, passive DNS and DNS brute force (utils/subdomain_discovery.py)
        - SecurityTrails subdomain discovery (requires API key)
        - DNS resolution (parallel)
        - Ping check (parallel)
        - Hosting detection
        - Database storage
    """
    
    SECURITYTRAILS_URL = "https://api.securitytrails.com/v1"
    
    def __init__(self, 
                 securitytrails_api_key: Optional[str] = None,
                 max_dns_workers: int = 20,
                 max_ping_workers: int = 10,
                 ping_timeout: int = 2,
                 rate_limit_delay: float = 1.5):
        """
        Initialize Phase 1 expander.
        
        Args:
            securitytrails_api_key: SecurityTrails API key (optional)
            max_dns_workers: Max concurrent DNS queries
            max_ping_workers: Max concurrent ping checks
            ping_timeout: Ping timeout in seconds
            rate_limit_delay: Delay between API calls
        """
        self.securitytrails_api_key = securitytrails_api_key or get_env('SECURITYTRAILS_API_KEY')
        self.max_dns_workers = max_dns_workers
        self.max_ping_workers = max_ping_workers
        self.ping_timeout = ping_timeout
        self.rate_limit_delay = rate_limit_delay
        
        self.session = requests.Session()
        if self.securitytrails_api_key:
            self.session.headers.update({
                'APIKey': self.securitytrails_api_key,
                'Accept': 'application/json'
            })
        
        self.stats = {
            'domains_added': 0,
            'subdomains_discovered': 0,
            'subdomains_new': 0,
            'ips_resolved': 0,
            'ips_new': 0,
            'errors': [],
            'time_elapsed': 0
        }
    
    # ============================================
    # SECURITYTRAILS
    # ============================================
    
    def get_securitytrails_subdomains(self, domain: str) -> List[str]:
        """
        Query SecurityTrails API for subdomains.
        
        Args:
            domain: Root domain (e.g., 'example.com')
        
        Returns:
            List of subdomain strings
        """
        if not self.securitytrails_api_key:
            logger.debug("No SecurityTrails API key configured")
            return []
        
        url = f"{self.SECURITYTRAILS_URL}/domain/{domain}/subdomains"
        
        try:
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                fqdns = [f"{sub}.{domain}" for sub in subdomains]
                logger.info(f"SecurityTrails found {len(fqdns)} subdomains for {domain}")
                return fqdns
            
            elif response.status_code == 401:
                logger.error("SecurityTrails API: Invalid API key")
            elif response.status_code == 403:
                logger.error("SecurityTrails API: Access forbidden")
            elif response.status_code == 429:
                logger.warning("SecurityTrails API: Rate limited, waiting 60s...")
                time.sleep(60)
                return self.get_securitytrails_subdomains(domain)
            else:
                logger.error(f"SecurityTrails API error: {response.status_code}")
        
        except requests.exceptions.Timeout:
            logger.error(f"SecurityTrails timeout for {domain}")
        except requests.exceptions.RequestException as e:
            logger.error(f"SecurityTrails request error: {e}")
        
        return []
    
    # ============================================
    # SUBDOMAIN DISCOVERY
    # ============================================
    
    def discover_subdomains(self, domain: str) -> List[str]:
        """
        Discover subdomains from SecurityTrails and the sources in
        utils/subdomain_discovery.py (CT logs, passive DNS, DNS brute force).

        Certificates are not taken from CT logs: expiry and changes come from
        the certificate each HTTPS service presents (utils/tls_certs.py).
        
        Args:
            domain: Root domain
        
        Returns:
            Subdomain names
        """
        subdomains = set()
        
        # SecurityTrails (requires API key)
        st_subs = self.get_securitytrails_subdomains(domain)
        subdomains.update(st_subs)
        
        # CT logs, HackerTarget, Wayback, OTX, DNS brute force/permutations
        try:
            from utils.subdomain_discovery import discover
            extra, stats = discover(domain, {s.lower() for s in subdomains})
            subdomains.update(extra)
        except Exception as e:
            logger.error(f"Extra subdomain discovery failed for {domain}: {e}")
        
        # Normalize and parse
        parsed = []
        for sub in subdomains:
            normalized = normalize_hostname(sub)
            if normalized and is_valid_domain(normalized) and normalized != domain:
                parsed.append(normalized)
        
        # Deduplicate
        parsed = list(set(parsed))
        
        logger.info(f"Discovered {len(parsed)} unique subdomains for {domain}")
        return parsed
    
    # ============================================
    # PROCESSING FUNCTIONS
    # ============================================
    
    def process_domain(self, domain: str) -> Dict:
        """
        Process a NEW root domain (doesn't exist in DB).
        
        Args:
            domain: Root domain name
        
        Returns:
            Stats dict
        """
        stats = {
            'subdomains_discovered': 0,
            'subdomains_new': 0,
            'ips_resolved': 0,
            'error': None
        }
        
        try:
            # 1. Discover subdomains
            subdomains = self.discover_subdomains(domain)
            
            # 2. Filter duplicates (already in DB)
            new_subdomains = filter_new_subdomains(subdomains)
            stats['subdomains_discovered'] = len(subdomains)
            stats['subdomains_new'] = len(new_subdomains)
            
            # 3. Add root domain to DB (or expand an existing container)
            dom_id = upsert_domain(domain, status='pending')
            set_domain_expanded(dom_id)
            self.stats['domains_added'] += 1
            
            # 4. DNS resolve root domain itself
            root_results = resolve_and_ping_batch(
                [domain],
                max_workers=self.max_dns_workers,
                ping_timeout=self.ping_timeout
            )
            
            # 5. Store root domain IPs
            root_ips = root_results.get(domain, {}).get('ips', [])
            root_ip_ids = []
            for ip in root_ips:
                if is_private_ip(ip):
                    continue
                is_shared, provider = is_shared_hosting(ip)
                ip_id = upsert_ip(
                    ip_value=ip,
                    is_private=0,
                    is_shared=1 if is_shared else 0,
                    shared_provider=provider or '',
                    status='up' if ip in root_results.get(domain, {}).get('live_ips', []) else 'down'
                )
                root_ip_ids.append(ip_id)
            
            create_domain_resolution(dom_id, root_ip_ids)
            stats['ips_resolved'] += len(root_ips)
            
            # 6. DNS resolve + Ping check subdomains (parallel)
            if new_subdomains:
                logger.info(f"Resolving DNS for {len(new_subdomains)} subdomains of {domain}...")
                results = resolve_and_ping_batch(
                    new_subdomains,
                    max_workers=self.max_dns_workers,
                    ping_timeout=self.ping_timeout
                )
                resolved_count = sum(1 for v in results.values() if v.get('ips'))
                logger.info(f"DNS resolved: {resolved_count}/{len(new_subdomains)} subdomains have IPs for {domain}")
                
                # 7. Store subdomains and IPs
                logger.info(f"Storing {len(new_subdomains)} subdomains in database...")
                for idx, subdomain in enumerate(new_subdomains):
                    self._store_subdomain(subdomain, domain, dom_id, results)
                    stats['ips_resolved'] += len(results.get(subdomain, {}).get('ips', []))
                    if (idx + 1) % 50 == 0:
                        logger.info(f"Stored {idx + 1}/{len(new_subdomains)} subdomains for {domain}")
            
            # 9. Update domain status
            update_domain_status(dom_id, 'up')
            
            logger.info(f"Processed domain {domain}: {stats['subdomains_new']} new subdomains, {stats['ips_resolved']} IPs")
        
        except Exception as e:
            stats['error'] = str(e)
            self.stats['errors'].append(f"{domain}: {e}")
            logger.error(f"Error processing domain {domain}: {e}")
        
        return stats
    
    def process_subdomain(self, subdomain: str, root_domain: str) -> Dict:
        """
        Process a subdomain when root domain already exists.
        
        Args:
            subdomain: Subdomain name
            root_domain: Parent root domain
        
        Returns:
            Stats dict
        """
        stats = {
            'ips_resolved': 0,
            'error': None
        }
        
        try:
            # 1. Check if subdomain already exists
            if subdomain_exists(subdomain):
                logger.debug(f"Subdomain {subdomain} already exists, skipping")
                return stats
            
            # 2. Get domain ID
            dom_id = get_domain_id(root_domain)
            if not dom_id:
                logger.error(f"Root domain {root_domain} not found in DB")
                stats['error'] = f"Root domain {root_domain} not found"
                return stats
            
            # 3. DNS resolve + Ping check
            results = resolve_and_ping_batch(
                [subdomain],
                max_workers=self.max_dns_workers,
                ping_timeout=self.ping_timeout
            )
            
            # 4. Store subdomain and IPs
            self._store_subdomain(subdomain, root_domain, dom_id, results)
            stats['ips_resolved'] = len(results.get(subdomain, {}).get('ips', []))
            self.stats['subdomains_new'] += 1
            
            logger.info(f"Processed subdomain {subdomain}: {stats['ips_resolved']} IPs")
        
        except Exception as e:
            stats['error'] = str(e)
            self.stats['errors'].append(f"{subdomain}: {e}")
            logger.error(f"Error processing subdomain {subdomain}: {e}")
        
        return stats
    
    def process_ip(self, ip: str) -> Dict:
        """
        Process a single IP address.
        
        Args:
            ip: IP address
        
        Returns:
            Stats dict
        """
        stats = {'status': 'down', 'error': None}
        
        try:
            is_live, is_shared, provider = self._check_ip(ip)
            self._store_ip(ip, is_live, is_shared, provider)
            stats['status'] = 'up' if is_live else 'down'
        
        except Exception as e:
            stats['error'] = str(e)
            self.stats['errors'].append(f"{ip}: {e}")
            logger.error(f"Error processing IP {ip}: {e}")
        
        return stats
    
    def _check_ip(self, ip: str) -> Tuple[bool, bool, Optional[str]]:
        """Network checks for an IP (thread-safe, no DB access)."""
        from utils.utility import is_ip_live
        
        is_live = is_ip_live(ip, timeout=self.ping_timeout)
        is_shared, provider = is_shared_hosting(ip)
        return is_live, is_shared, provider
    
    def _store_ip(self, ip: str, is_live: bool, is_shared: bool, provider: Optional[str]) -> None:
        """Persist IP check results. Call from the main thread only (SQLite)."""
        upsert_ip(
            ip_value=ip,
            is_private=1 if is_private_ip(ip) else 0,
            is_shared=1 if is_shared else 0,
            shared_provider=provider or '',
            status='up' if is_live else 'down'
        )
        self.stats['ips_new'] += 1
        logger.info(f"Processed IP {ip}: {'up' if is_live else 'down'}")
    
    def process_cidr(self, cidr: str) -> Dict:
        """
        Process a CIDR range.
        
        Args:
            cidr: CIDR notation (e.g., '192.168.1.0/24')
        
        Returns:
            Stats dict
        """
        stats = {'ips_processed': 0, 'ips_live': 0, 'error': None}
        
        try:
            # Expand CIDR to IPs
            ips = expand_cidr(cidr)
            
            if not ips:
                logger.warning(f"CIDR {cidr} expanded to 0 IPs")
                return stats
            
            logger.info(f"Processing CIDR {cidr}: {len(ips)} IPs")
            
            # Liveness checks run concurrently; DB writes stay on this thread
            with ThreadPoolExecutor(max_workers=self.max_ping_workers) as executor:
                futures = {executor.submit(self._check_ip, ip): ip for ip in ips}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        is_live, is_shared, provider = future.result()
                        self._store_ip(ip, is_live, is_shared, provider)
                    except Exception as e:
                        self.stats['errors'].append(f"{ip}: {e}")
                        logger.error(f"Error processing IP {ip}: {e}")
                        continue
                    if is_live:
                        stats['ips_live'] += 1
                    stats['ips_processed'] += 1
            
            logger.info(f"CIDR {cidr}: {stats['ips_live']}/{stats['ips_processed']} IPs live")
        
        except Exception as e:
            stats['error'] = str(e)
            self.stats['errors'].append(f"{cidr}: {e}")
            logger.error(f"Error processing CIDR {cidr}: {e}")
        
        return stats
    
    # ============================================
    # HELPER FUNCTIONS
    # ============================================
    
    def _store_subdomain(self, subdomain: str, root_domain: str, dom_id: int, dns_results: Dict) -> int:
        """
        Store subdomain and its IPs in database.
        
        Args:
            subdomain: Subdomain name
            root_domain: Parent root domain
            dom_id: Domain ID
            dns_results: Results from resolve_and_ping_batch
        
        Returns:
            sub_id of stored subdomain
        """
        result = dns_results.get(subdomain, {'ips': [], 'live_ips': [], 'status': 'down'})
        
        # Determine status
        status = result.get('status', 'down')
        
        # Store subdomain
        sub_id = upsert_subdomain(subdomain, dom_id, status=status)
        
        # Store IPs and create junctions
        for ip in result.get('ips', []):
            # Skip private IPs
            if is_private_ip(ip):
                continue
            
            # Check hosting
            is_shared, provider = is_shared_hosting(ip)
            
            # Store IP
            ip_id = upsert_ip(
                ip_value=ip,
                is_private=0,
                is_shared=1 if is_shared else 0,
                shared_provider=provider,
                status='up' if ip in result.get('live_ips', []) else 'down'
            )
            
            # Create junction
            create_subdomain_resolution(sub_id, [ip_id])
        
        return sub_id
    
    # ============================================
    # MAIN RUN FUNCTION
    # ============================================
    
    def run_phase1(self, targets: Dict) -> Dict:
        """
        Run Phase 1: Asset Discovery and Initialization.
        
        Args:
            targets: {
                'domains': ['example.com'],
                'subdomains': ['api.test.com'],
                'ips': ['192.168.1.1'],
                'cidrs': ['10.0.0.0/24']
            }
        
        Returns:
            Stats dict
        """
        start_time = datetime.now()
        
        logger.info("=" * 60)
        logger.info("Starting Phase 1: Asset Discovery")
        logger.info(f"Domains: {len(targets.get('domains', []))}")
        logger.info(f"Subdomains: {len(targets.get('subdomains', []))}")
        logger.info(f"IPs: {len(targets.get('ips', []))}")
        logger.info(f"CIDRs: {len(targets.get('cidrs', []))}")
        logger.info("=" * 60)
        
        # Scope: a submitted domain is expanded (everything under it is
        # discovered, scanned and monitored); a submitted subdomain is scanned
        # on its own. Its parent is only stored as a container, so access to
        # one host never turns into scanning the whole organization.
        single_hosts = list(targets.get('subdomains', []))
        
        # 1. Process domains
        for domain in targets.get('domains', []):
            domain = normalize_hostname(domain)
            if not domain:
                continue
            
            root = extract_root_domain(domain)
            if domain != root:
                single_hosts.append(domain)   # a subdomain typed as a domain
                continue
            
            if is_domain_expanded(root):
                logger.info(f"Domain {domain} already exists, skipping")
            else:
                # New domain, or the container of an earlier single subdomain
                result = self.process_domain(root)
                self.stats['subdomains_discovered'] += result.get('subdomains_discovered', 0)
                self.stats['subdomains_new'] += result.get('subdomains_new', 0)
                self.stats['ips_resolved'] += result.get('ips_resolved', 0)
                time.sleep(self.rate_limit_delay)
        
        # 2. Process subdomains: only the host itself
        for subdomain in single_hosts:
            subdomain = normalize_hostname(subdomain)
            if not subdomain:
                continue
            
            root = extract_root_domain(subdomain)
            if not domain_exists(root):
                add_container_domain(root)
            result = self.process_subdomain(subdomain, root)
            self.stats['subdomains_new'] += 1
            self.stats['ips_resolved'] += result.get('ips_resolved', 0)
        
        # 3. Process IPs
        for ip in targets.get('ips', []):
            ip = ip.strip()
            if not validate_ip(ip):
                logger.warning(f"Invalid IP: {ip}")
                continue
            
            # Check if IP already exists
            if ip_exists(ip):
                logger.debug(f"IP {ip} already exists, skipping")
                continue
            
            self.process_ip(ip)
            self.stats['ips_resolved'] += 1
        
        # 4. Process CIDRs
        for cidr in targets.get('cidrs', []):
            cidr = cidr.strip()
            if not validate_cidr(cidr):
                logger.warning(f"Invalid CIDR: {cidr}")
                continue
            
            result = self.process_cidr(cidr)
            self.stats['ips_resolved'] += result.get('ips_processed', 0)
        
        # Calculate elapsed time
        elapsed = (datetime.now() - start_time).total_seconds()
        self.stats['time_elapsed'] = elapsed
        
        # Log summary
        logger.info("=" * 60)
        logger.info("Phase 1 Complete")
        logger.info(f"Domains added: {self.stats['domains_added']}")
        logger.info(f"Subdomains discovered: {self.stats['subdomains_discovered']}")
        logger.info(f"Subdomains new: {self.stats['subdomains_new']}")
        logger.info(f"IPs resolved: {self.stats['ips_resolved']}")
        logger.info(f"Errors: {len(self.stats['errors'])}")
        logger.info(f"Time elapsed: {elapsed:.2f}s")
        logger.info("=" * 60)
        
        return self.stats


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Phase 1: Asset Discovery and Initialization')
    parser.add_argument('--domain', type=str, help='Single domain to process')
    parser.add_argument('--subdomain', type=str, help='Single subdomain to process')
    parser.add_argument('--ip', type=str, help='Single IP to process')
    parser.add_argument('--cidr', type=str, help='Single CIDR to process')
    parser.add_argument('--securitytrails-key', type=str, help='SecurityTrails API key')
    parser.add_argument('--max-dns-workers', type=int, default=20, help='Max concurrent DNS queries')
    parser.add_argument('--max-ping-workers', type=int, default=10, help='Max concurrent ping checks')
    
    args = parser.parse_args()
    
    # Build targets
    targets = {
        'domains': [args.domain] if args.domain else [],
        'subdomains': [args.subdomain] if args.subdomain else [],
        'ips': [args.ip] if args.ip else [],
        'cidrs': [args.cidr] if args.cidr else []
    }
    
    if not any(targets.values()):
        parser.print_help()
        return
    
    expander = Phase1Expander(
        securitytrails_api_key=args.securitytrails_key,
        max_dns_workers=args.max_dns_workers,
        max_ping_workers=args.max_ping_workers
    )
    
    stats = expander.run_phase1(targets)
    
    print("\nPhase 1 Results:")
    print(f"  Domains added: {stats['domains_added']}")
    print(f"  Subdomains discovered: {stats['subdomains_discovered']}")
    print(f"  Subdomains new: {stats['subdomains_new']}")
    print(f"  IPs resolved: {stats['ips_resolved']}")
    print(f"  Time: {stats['time_elapsed']:.2f}s")


if __name__ == '__main__':
    main()