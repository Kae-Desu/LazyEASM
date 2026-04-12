"""
Shared parsing functions for LazyEASM.
Used by:
    - 01-parse-input.py (main entry)
    - 03-asset-expansion.py (subdomain parsing)
    - main.py (unified phase1)
"""

import re
import ipaddress
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False


def normalize_hostname(hostname: str) -> str:
    """
    Normalize hostname by stripping protocol, path, port.
    
    Examples:
        'https://example.com/' → 'example.com'
        'example.com:8080' → 'example.com'
        'example.com/api' → 'example.com'
        '  EXAMPLE.COM  ' → 'example.com'
    """
    if not hostname:
        return ''
    
    hostname = hostname.strip()
    
    # Strip protocol
    if '://' in hostname:
        try:
            parsed = urlparse(hostname)
            hostname = parsed.netloc or hostname
        except:
            pass
    
    # Strip path
    if '/' in hostname:
        hostname = hostname.split('/')[0]
    
    # Strip port
    if ':' in hostname:
        # Handle IPv6 addresses
        if hostname.startswith('['):
            # IPv6 format: [::1]:8080
            if ']:' in hostname:
                hostname = hostname.split(']:')[0] + ']'
        else:
            # IPv4 or hostname: example.com:8080
            hostname = hostname.split(':')[0]
    
    # Lowercase
    hostname = hostname.lower().strip()
    
    return hostname


def extract_root_domain(hostname: str) -> str:
    """
    Extract root domain from hostname.
    
    Examples:
        'www.example.com' → 'example.com'
        'api.sub.example.com' → 'example.com'
        'example.com' → 'example.com'
        'example.co.uk' → 'example.co.uk'
    
    Args:
        hostname: Domain name
    
    Returns:
        Root domain (eTLD + 1)
    """
    hostname = normalize_hostname(hostname)
    
    if not hostname:
        return ''
    
    # Check if it's an IP address
    if validate_ip(hostname):
        return hostname
    
    # Use tldextract if available
    if TLDEXTRACT_AVAILABLE:
        try:
            extracted = tldextract.extract(hostname)
            if extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
            return extracted.domain or hostname
        except:
            pass
    
    # Fallback: simple extraction
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname


def validate_ip(ip: str) -> bool:
    """
    Validate IP address (IPv4 or IPv6).
    
    Args:
        ip: String to validate
    
    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation.
    
    Args:
        cidr: String to validate (e.g., '192.168.1.0/24')
    
    Returns:
        True if valid CIDR
    """
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> List[str]:
    """
    Expand CIDR to list of IP addresses.
    
    Args:
        cidr: CIDR notation (e.g., '192.168.1.0/30')
    
    Returns:
        List of IP addresses (excluding network and broadcast for /31 and below)
        For /31 and /32, returns all addresses in range
    
    Examples:
        '192.168.1.0/30' → ['192.168.1.1', '192.168.1.2']
        '10.0.0.0/31' → ['10.0.0.0', '10.0.0.1']
        '192.168.1.1/32' → ['192.168.1.1']
    """
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        
        # For small networks (>= /31), return all addresses
        if network.prefixlen >= 31:
            return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        
        # For larger networks, return usable hosts
        return [str(ip) for ip in network.hosts()]
    
    except ValueError:
        return []


def categorize_targets(items: List[str]) -> Dict[str, List[str]]:
    """
    Categorize items into domains, subdomains, IPs, CIDRs.
    
    Args:
        items: List of raw input strings
    
    Returns:
        {
            'domains': ['example.com'],
            'subdomains': ['api.example.com'],
            'ips': ['192.168.1.1'],
            'cidrs': ['10.0.0.0/24'],
            'invalid': ['invalid input']
        }
    """
    domains = []
    subdomains = []
    ips = []
    cidrs = []
    invalid = []
    
    for item in items:
        item = normalize_hostname(item)
        
        if not item:
            continue
        
        # Check if CIDR
        if validate_cidr(item):
            cidrs.append(item)
            continue
        
        # Check if IP
        if validate_ip(item):
            ips.append(item)
            continue
        
        # Check if valid domain/subdomain
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', item):
            invalid.append(item)
            continue
        
        # Determine if domain or subdomain
        root = extract_root_domain(item)
        
        if not root:
            invalid.append(item)
            continue
        
        if item == root:
            domains.append(item)
        else:
            subdomains.append(item)
    
    return {
        'domains': list(set(domains)),
        'subdomains': list(set(subdomains)),
        'ips': list(set(ips)),
        'cidrs': list(set(cidrs)),
        'invalid': list(set(invalid))
    }


def parse_input(input_text: str) -> Dict[str, List[str]]:
    """
    Parse raw input text into categorized targets.
    
    Args:
        input_text: Multiline string with domains, IPs, CIDRs
    
    Returns:
        {
            'domains': ['example.com'],
            'subdomains': ['api.example.com'],
            'ips': ['192.168.1.1'],
            'cidrs': ['10.0.0.0/24'],
            'invalid': ['invalid input']
        }
    
    Example:
        >>> text = '''
        ... example.com
        ... api.test.com
        ... 192.168.1.1
        ... 10.0.0.0/24
        ... '''
        >>> parse_input(text)
        {
            'domains': ['example.com'],
            'subdomains': ['api.test.com'],
            'ips': ['192.168.1.1'],
            'cidrs': ['10.0.0.0/24'],
            'invalid': []
        }
    """
    if not input_text:
        return {
            'domains': [],
            'subdomains': [],
            'ips': [],
            'cidrs': [],
            'invalid': []
        }
    
    # Split by newline
    lines = input_text.strip().split('\n')
    
    # Clean and normalize
    items = []
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Handle comma-separated values on single line
        if ',' in line:
            items.extend([item.strip() for item in line.split(',')])
        else:
            items.append(line)
    
    return categorize_targets(items)


def is_valid_domain(domain: str) -> bool:
    """
    Check if string is a valid domain name.
    
    Args:
        domain: String to validate
    
    Returns:
        True if valid domain format
    """
    domain = domain.strip().lower()
    
    if not domain:
        return False
    
    # Check length
    if len(domain) > 253:
        return False
    
    # Check format
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not re.match(pattern, domain):
        return False
    
    # Check each label
    labels = domain.split('.')
    for label in labels:
        if len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    
    return True


def is_valid_subdomain(subdomain: str) -> bool:
    """
    Check if string is a valid subdomain (same as domain validation).
    
    Args:
        subdomain: String to validate
    
    Returns:
        True if valid subdomain format
    """
    return is_valid_domain(subdomain)