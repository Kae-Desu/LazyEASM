"""
Module: Wappalyzer.py
Purpose: Technology fingerprinting and CVE matching for web services
Flow:
    1. Read domains/subdomains with HTTP ports from DB (status='up')
    2. For each target:
       - Construct URL (http/https based on port)
       - Call Wappalyzer to detect tech stack
       - Create/update http_services entry
       - Store technologies in DB
       - Search CVEs for each technology (0.5s delay)
       - Store vulnerabilities in DB
    3. Log results to scan_history
    4. Return stats with CVE data grouped by asset
"""

import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False
    Wappalyzer = None
    WebPage = None

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

import logging
import socket
import ssl
from datetime import datetime
from typing import List, Dict, Optional, Tuple

from utils.db_utils import (
    get_db_connection,
    get_http_targets,
    upsert_http_service,
    upsert_technology,
    upsert_vulnerability,
    log_scan
)

from modules.CVEmatch import find_cve
from modules.Notify import send_vulnerability_alert

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
log_file = os.path.join(LOGS_DIR, f"wappalyzer-{datetime.now().strftime('%Y-%m-%d')}.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class WappalyzerScanner:
    """Technology fingerprinting using Wappalyzer."""
    
    def __init__(self, enable_cve: bool = True, cvss_min: float = 5.0, cve_delay: float = 0.5):
        if not WAPPALYZER_AVAILABLE:
            raise ImportError("python-Wappalyzer not installed. Run: pip install python-Wappalyzer")
        
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests not installed. Run: pip install requests")
        
        self.wappalyzer = Wappalyzer.latest()
        self.enable_cve = enable_cve
        self.cvss_min = cvss_min
        self.cve_delay = cve_delay
        self.stats = {
            'total': 0,
            'scanned': 0,
            'failed': 0,
            'technologies_found': 0,
            'cves_found': 0,
            'http_services_created': 0,
            'failures_by_category': {}
        }
    
    def categorize_error(self, exception: Exception) -> dict:
        """
        Categorize exception into error type with retry recommendation.
        
        Args:
            exception: The caught exception
        
        Returns:
            Dict with error_category, should_retry, http_status
        """
        error_info = {
            'error_category': 'unknown',
            'error_type': type(exception).__name__,
            'error_message': str(exception),
            'should_retry': False,
            'http_status': None
        }
        
        if isinstance(exception, (requests.exceptions.Timeout,
                                  requests.exceptions.ReadTimeout,
                                  requests.exceptions.ConnectTimeout)):
            error_info['error_category'] = 'timeout'
            error_info['should_retry'] = True
        
        elif isinstance(exception, (requests.exceptions.ConnectionError,
                                     ConnectionRefusedError,
                                     ConnectionResetError)):
            error_info['error_category'] = 'network_error'
            error_info['should_retry'] = True
        
        elif isinstance(exception, (socket.gaierror, socket.herror)):
            error_info['error_category'] = 'dns_error'
            error_info['should_retry'] = False
        
        elif isinstance(exception, (ssl.SSLCertVerificationError,
                                     ssl.SSLError,
                                     requests.exceptions.SSLError)):
            error_info['error_category'] = 'ssl_error'
            error_info['should_retry'] = False
        
        elif isinstance(exception, requests.exceptions.HTTPError):
            error_info['error_category'] = 'http_error'
            if hasattr(exception, 'response') and exception.response is not None:
                error_info['http_status'] = exception.response.status_code
            
            if error_info['http_status'] and error_info['http_status'] >= 500:
                error_info['should_retry'] = True
        
        elif isinstance(exception, requests.exceptions.TooManyRedirects):
            error_info['error_category'] = 'redirect_error'
            error_info['should_retry'] = False
        
        elif isinstance(exception, (requests.exceptions.ContentDecodingError,
                                     UnicodeDecodeError)):
            error_info['error_category'] = 'content_error'
            error_info['should_retry'] = False
        
        return error_info
    
    def scan_url(self, url: str, timeout: int = 30) -> Tuple[bool, Optional[Dict], Optional[Dict]]:
        """
        Scan a URL using Wappalyzer with comprehensive error handling.
        
        Args:
            url: Full URL (http:// or https://)
            timeout: Request timeout in seconds
        
        Returns:
            Tuple of (success, technologies_dict or None, error_info or None)
        """
        try:
            logger.info(f"Scanning {url}")
            
            webpage = WebPage.new_from_url(url, timeout=timeout)
            technologies = self.wappalyzer.analyze_with_versions_and_categories(webpage)
            
            return True, technologies, None
        
        except requests.exceptions.HTTPError as e:
            error_info = self.categorize_error(e)
            error_info['url'] = url
            status_msg = f" {error_info['http_status']}" if error_info.get('http_status') else ""
            logger.warning(f"HTTP error scanning {url}{status_msg}")
            return False, None, error_info
        
        except requests.exceptions.Timeout as e:
            error_info = self.categorize_error(e)
            error_info['url'] = url
            logger.warning(f"Timeout scanning {url}")
            return False, None, error_info
        
        except requests.exceptions.ConnectionError as e:
            error_info = self.categorize_error(e)
            error_info['url'] = url
            logger.warning(f"Connection error scanning {url}: {str(e)[:100]}")
            return False, None, error_info
        
        except requests.exceptions.SSLError as e:
            error_info = self.categorize_error(e)
            error_info['url'] = url
            logger.warning(f"SSL error scanning {url}")
            return False, None, error_info
        
        except Exception as e:
            error_info = self.categorize_error(e)
            error_info['url'] = url
            logger.error(f"Unexpected error scanning {url}: {type(e).__name__}: {str(e)[:150]}")
            return False, None, error_info
    
    def extract_web_server(self, technologies: Dict) -> Optional[str]:
        """
        Extract web server from technologies.
        
        Args:
            technologies: Wappalyzer output dict
        
        Returns:
            Web server name or None
        """
        web_server_techs = ['nginx', 'Apache', 'Apache HTTP Server', 'IIS', 
                           'lighttpd', 'OpenResty', 'LiteSpeed']
        
        for tech_name in technologies.keys():
            if tech_name in web_server_techs:
                return tech_name
        
        categories = ['Web servers', 'Reverse proxies']
        for tech_name, tech_data in technologies.items():
            tech_cats = tech_data.get('categories', [])
            for cat in categories:
                if cat in tech_cats:
                    return tech_name
        
        return None
    
    def scan_target(self, host: str, port: int, ip_id: int | None = None, is_https: int = 0) -> Dict:
        """
        Scan a single target and store results.
        
        Args:
            host: Domain/subdomain name
            port: Port number
            ip_id: IP ID from database (optional, None for Cloudflare/CDN sites)
            is_https: 1 for HTTPS, 0 for HTTP
        
        Returns:
            Result dict with technologies found and CVEs
        """
        scheme = 'https' if is_https else 'http'
        url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
        
        result = {
            'host': host,
            'url': url,
            'technologies': [],
            'cves': [],
            'success': False,
            'error_info': None
        }
        
        success, technologies, error_info = self.scan_url(url)
        
        if not success:
            self.stats['failed'] += 1
            
            if error_info:
                category = error_info.get('error_category', 'unknown')
                self.stats['failures_by_category'][category] = \
                    self.stats['failures_by_category'].get(category, 0) + 1
            
            result['error_info'] = error_info
            return result
        
        web_server = self.extract_web_server(technologies)
        
        http_id = upsert_http_service(
            host=host,
            port_num=port,
            ip_id=ip_id,
            is_https=is_https,
            title=None,
            web_server=web_server
        )
        
        self.stats['http_services_created'] += 1
        
        for tech_name, tech_data in technologies.items():
            versions = tech_data.get('versions', [])
            tech_version = versions[0] if versions else None
            
            tech_id = upsert_technology(
                http_id=http_id,
                tech_name=tech_name,
                tech_version=tech_version
            )
            
            result['technologies'].append({
                'name': tech_name,
                'version': tech_version,
                'categories': tech_data.get('categories', []),
                'tech_id': tech_id
            })
            
            self.stats['technologies_found'] += 1
            
            if self.enable_cve and tech_version:
                tech_string = f"{tech_name} {tech_version}"
                
                time.sleep(self.cve_delay)
                
                cve_result = find_cve(tech_string, min_cvss=self.cvss_min)
                
                for cve in cve_result.get('cves', []):
                    vuln_id = upsert_vulnerability(
                        tech_id=tech_id,
                        cve_id=cve['cve_id'],
                        cve_score=cve['cvss'],
                        description=cve['description']
                    )
                    
                    result['cves'].append({
                        'cve_id': cve['cve_id'],
                        'cvss': cve['cvss'],
                        'description': cve['description'],
                        'tech_name': tech_name,
                        'vuln_id': vuln_id
                    })
                    
                    self.stats['cves_found'] += 1
        
        result['success'] = True
        self.stats['scanned'] += 1
        
        logger.info(f"Found {len(result['technologies'])} technologies, {len(result['cves'])} CVEs for {url}")
        
        return result
    
    def run(self, targets: List[Dict] = None) -> Dict:
        """
        Run Wappalyzer scan on targets with CVE matching.
        
        Args:
            targets: Optional list of target dicts. If None, get from DB.
        
        Returns:
            Stats dict with results grouped by asset
        """
        logger.info("Starting Wappalyzer + CVEmatch scan")
        scan_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if targets is None:
            targets = get_http_targets()
        
        self.stats['total'] = len(targets)
        
        if self.stats['total'] == 0:
            logger.warning("No HTTP targets found in database")
            return {
                'status': 'no_targets',
                'stats': self.stats,
                'results': []
            }
        
        logger.info(f"Found {len(targets)} targets to scan")
        logger.info(f"CVE matching: {'Enabled' if self.enable_cve else 'Disabled'}")
        if self.enable_cve:
            logger.info(f"CVSS threshold: {self.cvss_min}")
            logger.info(f"API delay: {self.cve_delay}s")
        
        results = []
        for target in targets:
            host = target['host']
            ip_id = target['ip_id']
            port = target['port_num']
            is_https = target['is_https']
            
            result = self.scan_target(host, ip_id, port, is_https)
            results.append(result)
        
        scan_completed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_scan(
            'wappalyzer_cve',
            f"batch:{len(targets)}",
            'completed',
            items_found=self.stats['cves_found'],
            started_at=scan_started,
            completed_at=scan_completed
        )
        
        logger.info("=" * 60)
        logger.info("Wappalyzer + CVEmatch scan completed")
        logger.info("=" * 60)
        logger.info(f"Total targets:      {self.stats['total']}")
        logger.info(f"Successful:        {self.stats['scanned']}")
        logger.info(f"Failed:            {self.stats['failed']}")
        
        if self.stats['failures_by_category']:
            logger.info("")
            logger.info("Failure breakdown:")
            for category, count in sorted(self.stats['failures_by_category'].items()):
                logger.info(f"  - {category:20s} {count}")
        
        logger.info("")
        logger.info(f"Technologies found: {self.stats['technologies_found']}")
        logger.info(f"CVEs found:         {self.stats['cves_found']}")
        logger.info(f"HTTP services created: {self.stats['http_services_created']}")
        logger.info("=" * 60)
        
        assets_with_cves = {}
        for result in results:
            if result.get('cves'):
                host = result['host']
                assets_with_cves[host] = {
                    'host': host,
                    'url': result['url'],
                    'technologies': result['technologies'],
                    'cves': result['cves']
                }
        
        if assets_with_cves:
            logger.info("")
            logger.info("CVE Summary by Asset:")
            for host, data in assets_with_cves.items():
                logger.info(f"  {host}: {len(data['cves'])} CVEs")
        
        return {
            'status': 'success' if self.stats['failed'] == 0 else 'partial',
            'stats': self.stats,
            'results': results,
            'assets_with_cves': assets_with_cves
        }


def format_for_cvematch(technologies: Dict) -> List[str]:
    """
    Convert Wappalyzer output to CVEmatch input format.
    
    Args:
        technologies: {'tech_name': {'categories': [...], 'versions': ['1.0']}}
    
    Returns:
        List of strings: ['nginx 1.18.0', 'jQuery 3.6.0', 'PHP']
    """
    result = []
    
    for tech_name, tech_data in technologies.items():
        versions = tech_data.get('versions', [])
        
        if versions:
            for version in versions:
                result.append(f"{tech_name} {version}")
        else:
            result.append(tech_name)
    
    return result


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Technology fingerprinting with CVE matching')
    parser.add_argument('--domain', type=str, help='Scan specific domain only')
    parser.add_argument('--port', type=int, help='Specific port to scan')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--no-cve', action='store_true', help='Disable CVE matching')
    parser.add_argument('--cvss-min', type=float, default=5.0, help='Minimum CVSS score (default: 5.0)')
    parser.add_argument('--cve-delay', type=float, default=0.5, help='Delay between CVE API calls (default: 0.5)')
    parser.add_argument('--no-alert', action='store_true', help='Disable Discord alert')
    
    args = parser.parse_args()
    
    if not WAPPALYZER_AVAILABLE:
        print("Error: python-Wappalyzer not installed")
        print("Install with: pip install python-Wappalyzer")
        sys.exit(1)
    
    scanner = WappalyzerScanner(
        enable_cve=not args.no_cve,
        cvss_min=args.cvss_min,
        cve_delay=args.cve_delay
    )
    
    if args.domain:
        targets = get_http_targets()
        targets = [t for t in targets if args.domain in t['host']]
        
        if args.port:
            targets = [t for t in targets if t['port_num'] == args.port]
        
        if not targets:
            print(f"No HTTP targets found for {args.domain}")
            sys.exit(1)
        
        logger.info(f"Filtered to {len(targets)} targets")
    else:
        targets = None
    
    result = scanner.run(targets)
    
    if not args.no_alert and result.get('assets_with_cves'):
        logger.info("Sending Discord alert...")
        success, msg = send_vulnerability_alert(result['assets_with_cves'], min_cvss=args.cvss_min)
        
        if success:
            logger.info(f"Discord alert sent: {msg}")
        else:
            logger.error(f"Discord alert failed: {msg}")
    
    sys.exit(0 if result['status'] in ('success', 'no_targets') else 1)


if __name__ == '__main__':
    main()