"""
Module: utility.py
Purpose: Utility functions for LazyEASM
Functions:
    - ping_host: ICMP ping check
    - is_content: HTTP HEAD request
    - dns_lookup: DNS resolution using dnspython
    - reverse_dns_lookup: Reverse DNS (PTR) lookup
    - is_private_ip: Check if IP is private/loopback/link-local
    - is_wildcard_domain: Detect wildcard DNS
    - is_shared_hosting: Detect shared hosting/CDN/cloud provider
"""

import subprocess
import platform
import socket
import random
import string
import re
import ipaddress
from typing import List, Dict, Optional

try:
    import dns.resolver
    import dns.reversename
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


SHARED_HOSTING_PATTERNS = [
    (r'\.amazonaws\.com$', 'AWS'),
    (r'\.compute\.amazonaws\.com$', 'AWS EC2'),
    (r'\.cloudfront\.net$', 'AWS CloudFront'),
    (r'\.elasticbeanstalk\.com$', 'AWS Elastic Beanstalk'),
    (r'\.s3\.amazonaws\.com$', 'AWS S3'),
    (r'\.cloudflare\.com$', 'Cloudflare'),
    (r'\.cloudflare-dns\.com$', 'Cloudflare'),
    (r'\.googleusercontent\.com$', 'Google Cloud'),
    (r'\.gstatic\.com$', 'Google'),
    (r'\.appspot\.com$', 'Google App Engine'),
    (r'\.googleapis\.com$', 'Google Cloud'),
    (r'\.azurewebsites\.net$', 'Azure'),
    (r'\.cloudapp\.net$', 'Azure'),
    (r'\.azurecontainer\.io$', 'Azure'),
    (r'\.azureedge\.net$', 'Azure CDN'),
    (r'\.hostgator\.com$', 'HostGator'),
    (r'\.bluehost\.com$', 'Bluehost'),
    (r'\.siteground\.com$', 'SiteGround'),
    (r'\.godaddy\.com$', 'GoDaddy'),
    (r'\.dreamhost\.com$', 'DreamHost'),
    (r'\.inmotionhosting\.com$', 'InMotion'),
    (r'\.a2hosting\.com$', 'A2 Hosting'),
    (r'\.wpengine\.com$', 'WP Engine'),
    (r'\.kinsta\.com$', 'Kinsta'),
    (r'\.pagely\.com$', 'Pagely'),
    (r'\.fastly\.net$', 'Fastly'),
    (r'\.akamaiedge\.net$', 'Akamai'),
    (r'\.akamai\.net$', 'Akamai'),
    (r'\.cdn\b', 'CDN'),
    (r'\.edge\b', 'Edge Network'),
    (r'\.digitalocean\.com$', 'DigitalOcean'),
    (r'\.do\.co$', 'DigitalOcean'),
    (r'\.linode\.com$', 'Linode'),
    (r'\.vultr\.com$', 'Vultr'),
    (r'\.hetzner\.com$', 'Hetzner'),
    (r'\.ovh\.net$', 'OVH'),
    (r'\.herokuapp\.com$', 'Heroku'),
    (r'\.vercel\.app$', 'Vercel'),
    (r'\.netlify\.app$', 'Netlify'),
    (r'\.github\.io$', 'GitHub Pages'),
    (r'\.gitlab\.io$', 'GitLab Pages'),
]

SHARED_HOSTING_IP_RANGES = [
    (ipaddress.ip_network('104.16.0.0/13'), 'Cloudflare'),
    (ipaddress.ip_network('104.24.0.0/14'), 'Cloudflare'),
    (ipaddress.ip_network('172.64.0.0/13'), 'Cloudflare'),
    (ipaddress.ip_network('162.158.0.0/15'), 'Cloudflare'),
    (ipaddress.ip_network('198.41.128.0/17'), 'Cloudflare'),
    (ipaddress.ip_network('141.101.64.0/18'), 'Cloudflare'),
    (ipaddress.ip_network('162.159.0.0/16'), 'Cloudflare'),
    (ipaddress.ip_network('188.114.96.0/20'), 'Cloudflare'),
    (ipaddress.ip_network('190.93.240.0/20'), 'Cloudflare'),
    (ipaddress.ip_network('199.27.128.0/21'), 'Cloudflare'),
    (ipaddress.ip_network('2400:cb00::/32'), 'Cloudflare IPv6'),
    (ipaddress.ip_network('1.0.0.0/24'), 'Cloudflare'),
    (ipaddress.ip_network('1.1.1.0/24'), 'Cloudflare'),
    (ipaddress.ip_network('8.8.4.0/24'), 'Google DNS'),
    (ipaddress.ip_network('8.8.8.0/24'), 'Google DNS'),
    (ipaddress.ip_network('8.34.208.0/20'), 'Google Cloud'),
    (ipaddress.ip_network('8.35.192.0/20'), 'Google Cloud'),
    (ipaddress.ip_network('35.184.0.0/13'), 'Google Cloud'),
    (ipaddress.ip_network('35.192.0.0/14'), 'Google Cloud'),
    (ipaddress.ip_network('35.196.0.0/15'), 'Google Cloud'),
    (ipaddress.ip_network('35.198.0.0/16'), 'Google Cloud'),
    (ipaddress.ip_network('35.199.0.0/17'), 'Google Cloud'),
    (ipaddress.ip_network('35.235.192.0/20'), 'Google Cloud'),
    (ipaddress.ip_network('130.211.0.0/16'), 'Google Cloud'),
    (ipaddress.ip_network('13.32.0.0/15'), 'AWS CloudFront'),
    (ipaddress.ip_network('13.224.0.0/14'), 'AWS CloudFront'),
    (ipaddress.ip_network('13.249.0.0/16'), 'AWS CloudFront'),
    (ipaddress.ip_network('52.46.0.0/15'), 'AWS CloudFront'),
    (ipaddress.ip_network('52.84.0.0/14'), 'AWS CloudFront'),
    (ipaddress.ip_network('52.200.0.0/13'), 'AWS'),
    (ipaddress.ip_network('54.0.0.0/8'), 'AWS'),
    (ipaddress.ip_network('52.0.0.0/8'), 'AWS'),
    (ipaddress.ip_network('99.77.0.0/17'), 'AWS'),
    (ipaddress.ip_network('52.93.0.0/16'), 'AWS'),
    (ipaddress.ip_network('13.52.0.0/15'), 'AWS'),
    (ipaddress.ip_network('40.0.0.0/8'), 'Azure'),
    (ipaddress.ip_network('52.96.0.0/12'), 'Azure'),
    (ipaddress.ip_network('104.40.0.0/13'), 'Azure'),
    (ipaddress.ip_network('137.116.0.0/16'), 'Azure'),
    (ipaddress.ip_network('138.91.0.0/16'), 'Azure'),
    (ipaddress.ip_network('157.55.0.0/16'), 'Azure'),
    (ipaddress.ip_network('168.61.0.0/16'), 'Azure'),
    (ipaddress.ip_network('191.232.0.0/13'), 'Azure'),
    (ipaddress.ip_network('64:ff9b::/96'), 'Azure IPv6'),
    (ipaddress.ip_network('46.137.0.0/17'), 'DigitalOcean'),
    (ipaddress.ip_network('64.227.0.0/17'), 'DigitalOcean'),
    (ipaddress.ip_network('134.209.0.0/17'), 'DigitalOcean'),
    (ipaddress.ip_network('142.93.0.0/17'), 'DigitalOcean'),
    (ipaddress.ip_network('159.65.0.0/17'), 'DigitalOcean'),
    (ipaddress.ip_network('165.22.0.0/16'), 'DigitalOcean'),
    (ipaddress.ip_network('167.99.0.0/17'), 'DigitalOcean'),
    (ipaddress.ip_network('206.189.0.0/17'), 'DigitalOcean'),
    (ipaddress.ip_network('23.94.0.0/16'), 'Vultr'),
    (ipaddress.ip_network('45.32.0.0/16'), 'Vultr'),
    (ipaddress.ip_network('45.63.0.0/16'), 'Vultr'),
    (ipaddress.ip_network('45.76.0.0/16'), 'Vultr'),
    (ipaddress.ip_network('64.176.0.0/16'), 'Vultr'),
    (ipaddress.ip_network('95.179.0.0/17'), 'Vultr'),
    (ipaddress.ip_network('104.156.224.0/20'), 'Vultr'),
    (ipaddress.ip_network('149.28.0.0/16'), 'Vultr'),
    (ipaddress.ip_network('185.92.220.0/22'), 'Vultr'),
    (ipaddress.ip_network('192.241.128.0/17'), 'Vultr'),
    (ipaddress.ip_network('198.13.0.0/17'), 'Vultr'),
    (ipaddress.ip_network('207.148.0.0/17'), 'Vultr'),
    (ipaddress.ip_network('208.83.232.0/22'), 'Vultr'),
]


def ping_host(host: str, count: int = 4) -> bool:
    """
    Ping a host to check if it's alive.
    
    Args:
        host: Hostname or IP address
        count: Number of ping packets
    
    Returns:
        True if host responds, False otherwise
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, str(count), host]
    
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        return process.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def is_content(url: str, port: int = 80) -> str:
    """
    HTTP HEAD request to get server response.
    
    Args:
        url: Hostname
        port: Port number
    
    Returns:
        First line of HTTP response or error message
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((url, port))

        request = f"HEAD / HTTP/1.1\r\nHost: {url}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())

        response = s.recv(11024).decode('utf-8', 'ignore')
        s.close()

        first_line = response.split('\n')[0]
        return first_line
    except Exception as e:
        return f"Error: {e}"


def dns_lookup(domain: str, record_type: str = 'A', resolver: list = None) -> list:
    """
    Resolve DNS records for a domain using dnspython.
    
    Args:
        domain: Domain name to resolve
        record_type: 'A', 'AAAA', 'CNAME', 'NS', 'MX', 'PTR'
        resolver: List of DNS server IPs (default: system DNS)
    
    Returns:
        List of resolved values (IPs for A/AAAA, strings for others)
    """
    if not DNSPYTHON_AVAILABLE:
        return _fallback_dns_lookup(domain, record_type)
    
    try:
        res = dns.resolver.Resolver()
        
        if resolver:
            res.nameservers = resolver
        
        record_type_upper = record_type.upper()
        
        if record_type_upper == 'PTR':
            return reverse_dns_lookup(domain)
        
        answers = res.resolve(domain, record_type_upper)
        
        results = []
        for rdata in answers:
            if record_type_upper in ('A', 'AAAA'):
                results.append(str(rdata))
            elif record_type_upper == 'CNAME':
                results.append(str(rdata.target))
            elif record_type_upper == 'NS':
                results.append(str(rdata.target))
            elif record_type_upper == 'MX':
                results.append(str(rdata.exchange))
            else:
                results.append(str(rdata))
        
        return results
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NoNameservers:
        return []
    except Exception:
        return []


def _fallback_dns_lookup(domain: str, record_type: str = 'A') -> list:
    """
    Fallback DNS lookup using socket.getaddrinfo.
    
    Args:
        domain: Domain name to resolve
        record_type: 'A' or 'AAAA'
    
    Returns:
        List of resolved IPs
    """
    try:
        if record_type.upper() == 'A':
            results = socket.getaddrinfo(domain, None, socket.AF_INET)
            return list(set([addr[4][0] for addr in results]))
        elif record_type.upper() == 'AAAA':
            results = socket.getaddrinfo(domain, None, socket.AF_INET6)
            return list(set([addr[4][0] for addr in results]))
        else:
            results = socket.getaddrinfo(domain, None)
            return list(set([addr[4][0] for addr in results]))
    except socket.gaierror:
        return []
    except Exception:
        return []


def reverse_dns_lookup(ip: str) -> list:
    """
    Perform reverse DNS lookup (PTR record).
    
    Args:
        ip: IP address to look up
    
    Returns:
        List of hostnames
    """
    if DNSPYTHON_AVAILABLE:
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, 'PTR')
            return [str(rdata.target) for rdata in answers]
        except Exception:
            return []
    else:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return [hostname]
        except socket.herror:
            return []
        except Exception:
            return []


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private/loopback/link-local/multicast.
    
    Covers:
        - 10.0.0.0/8 (Private Class A)
        - 172.16.0.0/12 (Private Class B)
        - 192.168.0.0/16 (Private Class C)
        - 127.0.0.0/8 (Loopback)
        - 169.254.0.0/16 (Link-local)
        - 224.0.0.0/4 (Multicast)
        - 240.0.0.0/4 (Reserved)
        - 0.0.0.0/8 (Current network)
    
    Args:
        ip: IP address string
    
    Returns:
        True if private/reserved, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_unspecified
        )
    except ValueError:
        return False


def is_wildcard_domain(domain: str) -> tuple:
    """
    Detect if domain has wildcard DNS.
    
    Method:
        1. Generate random subdomain
        2. Resolve random subdomain
        3. If resolves, test 2-3 more random subdomains
        4. If all resolve to same IP(s), confirm wildcard
    
    Args:
        domain: Domain to test
    
    Returns:
        (is_wildcard: bool, wildcard_ip: str or None)
    """
    def generate_random_subdomain():
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    
    test_results = []
    
    for _ in range(3):
        random_sub = generate_random_subdomain()
        test_domain = f"{random_sub}.{domain}"
        ips = dns_lookup(test_domain, 'A')
        
        if not ips:
            return False, None
        
        test_results.append(set(ips))
    
    first_set = test_results[0]
    all_same = all(ips == first_set for ips in test_results)
    
    if all_same and first_set:
        return True, list(first_set)[0]
    
    return False, None


def is_shared_hosting(ip: str) -> tuple:
    """
    Detect if IP belongs to shared hosting/CDN/cloud provider.
    
    Method:
        1. Check if IP is in known CDN/cloud IP ranges
        2. Reverse DNS lookup
        3. Check for hosting provider patterns in hostname
    
    Args:
        ip: IP address to check
    
    Returns:
        (is_shared: bool, provider: str or None)
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        for network, provider in SHARED_HOSTING_IP_RANGES:
            if ip_obj in network:
                return True, provider
    except ValueError:
        pass
    
    hostnames = reverse_dns_lookup(ip)
    
    if not hostnames:
        return False, None
    
    for hostname in hostnames:
        hostname_lower = hostname.lower()
        
        for pattern, provider in SHARED_HOSTING_PATTERNS:
            if re.search(pattern, hostname_lower):
                return True, provider
    
    return False, None


def get_domain_from_subdomain(subdomain: str) -> tuple:
    """
    Extract parent domain from subdomain.
    
    Args:
        subdomain: Full subdomain (e.g., 'api.nutelyn.com')
    
    Returns:
        (parent_domain: str, subdomain_part: str)
        Example: ('nutelyn.com', 'api.nutelyn.com')
    """
    parts = subdomain.split('.')
    
    if len(parts) < 2:
        return subdomain, subdomain
    
    parent_domain = '.'.join(parts[-2:])
    
    return parent_domain, subdomain


# ============================================
# BATCH PROCESSING FUNCTIONS
# ============================================

import concurrent.futures
from typing import Dict, List


def ping_host_fast(host: str, timeout: int = 2) -> bool:
    """
    Fast ping check with shorter timeout.
    
    Args:
        host: IP address or hostname
        timeout: Timeout in seconds (default: 2)
    
    Returns:
        True if host responds, False otherwise
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_ms = timeout * 1000 if platform.system().lower() == "windows" else str(timeout)
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    
    command = ["ping", param, "1", timeout_param, str(timeout_ms), host]
    
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1
        )
        return process.returncode == 0
    except:
        return False


def check_tcp_port(ip: str, ports: Optional[List[int]] = None, timeout: int = 3) -> bool:
    """
    Check if any TCP port is open on an IP.
    
    Args:
        ip: IP address
        ports: List of ports to check (default: common ports)
        timeout: Connection timeout in seconds
    
    Returns:
        True if any port is open, False otherwise
    """
    if ports is None:
        ports = [80, 443, 8080, 8443, 22, 21, 3306, 5432]
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except:
            pass
    return False


def is_ip_live(ip: str, timeout: int = 3) -> bool:
    """
    Check if an IP is live using ICMP ping first, then TCP fallback.
    
    Args:
        ip: IP address
        timeout: Timeout in seconds
    
    Returns:
        True if IP is live, False otherwise
    """
    if ping_host_fast(ip, timeout):
        return True
    return check_tcp_port(ip, timeout=timeout)


def ping_batch(hosts: List[str], max_workers: int = 10, timeout: int = 2) -> Dict[str, bool]:
    """
    Ping check multiple hosts in parallel.
    
    Args:
        hosts: List of IP addresses or hostnames
        max_workers: Maximum concurrent threads (default: 10)
        timeout: Timeout per ping in seconds (default: 2)
    
    Returns:
        Dict of {host: is_live}
    
    Example:
        >>> results = ping_batch(['8.8.8.8', '1.1.1.1', '192.168.1.1'])
        >>> results
        {'8.8.8.8': True, '1.1.1.1': True, '192.168.1.1': False}
    """
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(ping_host_fast, host, timeout): host
            for host in hosts
        }
        
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                results[host] = future.result()
            except:
                results[host] = False
    
    return results


def dns_batch(hostnames: List[str], record_type: str = 'A', max_workers: int = 20) -> Dict[str, List[str]]:
    """
    DNS resolve multiple hostnames in parallel.
    
    Args:
        hostnames: List of domain names
        record_type: DNS record type ('A', 'AAAA', 'ALL')
        max_workers: Maximum concurrent threads (default: 20)
    
    Returns:
        Dict of {hostname: [ips]}
    
    Example:
        >>> results = dns_batch(['google.com', 'github.com'])
        >>> results
        {'google.com': ['142.250.80.46', '142.250.80.14'], 'github.com': ['140.82.121.3']}
    """
    results = {}
    
    def resolve_single(hostname):
        try:
            if record_type == 'ALL':
                ips = dns_lookup(hostname, 'A') + dns_lookup(hostname, 'AAAA')
            else:
                ips = dns_lookup(hostname, record_type)
            return hostname, list(set(ips))
        except:
            return hostname, []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(resolve_single, hostname): hostname
            for hostname in hostnames
        }
        
        for future in concurrent.futures.as_completed(future_to_host):
            hostname = future_to_host[future]
            try:
                _, ips = future.result()
                results[hostname] = ips
            except:
                results[hostname] = []
    
    return results


def resolve_and_ping_batch(hostnames: List[str], max_workers: int = 10, ping_timeout: int = 2) -> Dict[str, Dict]:
    """
    Combined DNS resolve and ping check for multiple hostnames.
    
    Args:
        hostnames: List of domain names
        max_workers: Maximum concurrent threads (default: 10)
        ping_timeout: Timeout per ping in seconds (default: 2)
    
    Returns:
        Dict of {hostname: {'ips': [str], 'live_ips': [str], 'status': 'up'/'down'}}
    
    Example:
        >>> results = resolve_and_ping_batch(['google.com', 'example.com'])
        >>> results['google.com']
        {
            'ips': ['142.250.80.46', '142.250.80.14'],
            'live_ips': ['142.250.80.46'],
            'status': 'up'
        }
    """
    results = {}
    
    dns_results = dns_batch(hostnames, record_type='A', max_workers=max_workers)
    
    all_ips = []
    ip_to_hostnames = {}
    
    for hostname, ips in dns_results.items():
        results[hostname] = {'ips': ips, 'live_ips': [], 'status': 'down'}
        for ip in ips:
            if ip not in all_ips:
                all_ips.append(ip)
            if ip not in ip_to_hostnames:
                ip_to_hostnames[ip] = []
            ip_to_hostnames[ip].append(hostname)
    
    if all_ips:
        ping_results = ping_batch(all_ips, max_workers=max_workers, timeout=ping_timeout)
        
        offline_ips = []
        for ip, is_live in ping_results.items():
            if is_live and ip in ip_to_hostnames:
                for hostname in ip_to_hostnames[ip]:
                    results[hostname]['live_ips'].append(ip)
            else:
                offline_ips.append(ip)
        
        if offline_ips:
            for ip in offline_ips:
                if check_tcp_port(ip, timeout=ping_timeout):
                    for hostname in ip_to_hostnames[ip]:
                        results[hostname]['live_ips'].append(ip)
        
        for hostname in hostnames:
            if results[hostname]['live_ips']:
                results[hostname]['status'] = 'up'
            elif results[hostname]['ips']:
                results[hostname]['status'] = 'down'
            else:
                results[hostname]['status'] = 'down'
    
    return results


if __name__ == '__main__':
    print("Testing utility functions...")
    
    print("\n[1] Testing is_private_ip:")
    test_ips = ['192.168.1.1', '10.0.0.1', '127.0.0.1', '8.8.8.8', '1.1.1.1']
    for ip in test_ips:
        result = is_private_ip(ip)
        print(f"  {ip}: {'Private' if result else 'Public'}")
    
    print("\n[2] Testing dns_lookup (requires dnspython):")
    if DNSPYTHON_AVAILABLE:
        test_domains = ['google.com', 'github.com']
        for domain in test_domains:
            ips = dns_lookup(domain, 'A')
            print(f"  {domain}: {ips}")
    else:
        print("  dnspython not installed, skipping")
    
    print("\n[3] Testing reverse_dns_lookup:")
    test_ips_reverse = ['8.8.8.8', '1.1.1.1']
    for ip in test_ips_reverse:
        hostnames = reverse_dns_lookup(ip)
        print(f"  {ip}: {hostnames}")
    
    print("\n[4] Testing is_shared_hosting:")
    test_ips_shared = ['52.216.48.90', '104.16.132.229']
    for ip in test_ips_shared:
        is_shared, provider = is_shared_hosting(ip)
        print(f"  {ip}: {provider if is_shared else 'Not shared hosting'}")
    
    print("\nDone.")