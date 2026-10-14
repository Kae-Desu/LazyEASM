"""
Subdomain discovery from third-party sources and DNS (SecurityTrails, when
configured, is queried separately in modules/ExpandAsset.py).

Passive (third-party databases; no traffic to the target):
    - CT logs         certificate transparency: CertSpotter (optional
                      CERTSPOTTER_API_KEY raises its quota), crt.sh only when
                      CertSpotter fails, with a 30-minute cooldown after
                      crt.sh errors (it returns 502s under load)
    - HackerTarget    passive DNS, no key needed (small daily quota)
    - Wayback Machine hostnames from archived URLs
    - AlienVault OTX  passive DNS, needs OTX_API_KEY

Active (DNS queries through the configured resolver):
    - Brute force with the bundled wordlist (data/subdomain_wordlist.txt)
    - Permutations of known subdomains (api -> api-dev, dev-api, api2, ...)
    Skipped for domains with wildcard DNS, where every name would resolve.
    Toggle in the dashboard (Configuration > Discovery) or DNS_BRUTEFORCE=false;
    read on every run, so a change applies to the next discovery run.

Every source is isolated: a failing or rate-limited source is reported in
the stats and the others still count.
"""

import logging
import os
import random
import string
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Iterable, Optional, Set, Tuple
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import requests

from utils.config import get_env
from utils.parsing import is_valid_domain
from utils.timeutil import utc_now, utc_now_str

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_PATH = os.path.join(PROJECT_ROOT, 'data', 'subdomain_wordlist.txt')

HTTP_TIMEOUT = 45
USER_AGENT = 'LazyEASM subdomain-discovery'
CERTSPOTTER_MAX_PAGES = 5
CRTSH_TIMEOUT = 60
CRTSH_COOLDOWN = timedelta(minutes=30)
CRTSH_COOLDOWN_KEY = 'crtsh_cooldown_until'   # settings table, shared by web and worker
WAYBACK_MAX_ROWS = 5000
WAYBACK_TIMEOUT = 90  # the CDX API is slow for large sites
DNS_WORKERS = 50
DNS_TIMEOUT = 3.0
MAX_PERMUTATIONS = 1500

PERMUTATION_WORDS = ('dev', 'test', 'staging', 'stage', 'stg', 'uat', 'qa', 'prod', 'preprod',
                     'internal', 'admin', 'old', 'new', 'beta', 'demo', 'backup', 'v2')


class SourceError(Exception):
    """A discovery source failed or refused the request."""


def in_scope(name: str, domain: str) -> Optional[str]:
    """
    Normalize a discovered name and keep it only if it is a subdomain of domain.

    Requires a label boundary, so 'notexample.com' is not a subdomain of
    'example.com'. Wildcard prefixes ('*.') are removed.
    """
    name = (name or '').strip().lower().rstrip('.')
    while name.startswith('*.'):
        name = name[2:]
    domain = domain.lower().rstrip('.')
    if not name.endswith('.' + domain) or not is_valid_domain(name):
        return None
    return name


def _get(url: str, timeout: float = HTTP_TIMEOUT, **kwargs) -> requests.Response:
    try:
        response = requests.get(url, timeout=timeout, headers={'User-Agent': USER_AGENT, **kwargs.pop('headers', {})},
                                **kwargs)
    except requests.RequestException as e:
        raise SourceError(str(e)) from e
    if response.status_code == 429:
        raise SourceError('rate limited')
    if response.status_code != 200:
        raise SourceError(f'HTTP {response.status_code}')
    return response


# ---------------------------------------------------------------------------
# Passive sources
# ---------------------------------------------------------------------------

def from_certspotter(domain: str) -> Set[str]:
    key = get_env('CERTSPOTTER_API_KEY')
    headers = {'Authorization': f'Bearer {key}'} if key else {}
    names = set()
    after = None
    for page in range(CERTSPOTTER_MAX_PAGES):
        params = {'domain': domain, 'include_subdomains': 'true', 'expand': 'dns_names'}
        if after:
            params['after'] = after
        try:
            issuances = _get('https://api.certspotter.com/v1/issuances', params=params, headers=headers).json()
        except SourceError as e:
            if page == 0:
                raise
            logger.warning(f"[Discovery] CertSpotter stopped after {page} pages for {domain}: {e}")
            break
        if not issuances:
            break
        for issuance in issuances:
            names.update(issuance.get('dns_names') or [])
        after = issuances[-1].get('id')
    return names


def _utc_now() -> str:
    return utc_now_str()


def from_crtsh(domain: str) -> Set[str]:
    """
    One query per domain, current certificates only. After an error crt.sh is
    left alone for CRTSH_COOLDOWN, since retrying a struggling crt.sh is what
    keeps it returning 502s.
    """
    from utils.db_utils import get_setting, set_setting

    until = get_setting(CRTSH_COOLDOWN_KEY)
    if until and until > _utc_now():
        raise SourceError(f'skipped, cooling down until {until} UTC after an earlier error')
    try:
        rows = _get('https://crt.sh/', timeout=CRTSH_TIMEOUT,
                    params={'q': f'%.{domain}', 'output': 'json', 'exclude': 'expired', 'deduplicate': 'Y'}).json()
    except (SourceError, ValueError):
        set_setting(CRTSH_COOLDOWN_KEY, (utc_now() + CRTSH_COOLDOWN).strftime('%Y-%m-%d %H:%M:%S'))
        raise
    names = set()
    for row in rows:
        names.add(row.get('common_name') or '')
        names.update((row.get('name_value') or '').splitlines())
    return names


def from_ct_logs(domain: str) -> Set[str]:
    """Certificate transparency: CertSpotter, falling back to crt.sh."""
    try:
        return from_certspotter(domain)
    except (SourceError, ValueError) as first:
        logger.info(f"[Discovery] CertSpotter failed for {domain} ({first}); trying crt.sh")
        try:
            return from_crtsh(domain)
        except (SourceError, ValueError) as second:
            raise SourceError(f'CertSpotter: {first}; crt.sh: {second}') from second


def from_hackertarget(domain: str) -> Set[str]:
    text = _get('https://api.hackertarget.com/hostsearch/', params={'q': domain}).text
    if 'api count exceeded' in text.lower() or text.lower().startswith('error'):
        raise SourceError(text.strip()[:100])
    return {line.split(',', 1)[0] for line in text.splitlines() if ',' in line}


def from_wayback(domain: str) -> Set[str]:
    rows = _get('https://web.archive.org/cdx/search/cdx', params={
        'url': f'*.{domain}', 'output': 'json', 'fl': 'original', 'collapse': 'urlkey', 'limit': WAYBACK_MAX_ROWS,
    }, timeout=WAYBACK_TIMEOUT).json()
    names = set()
    for row in rows[1:]:  # first row is the header
        try:
            host = urlsplit(row[0] if '://' in row[0] else f'http://{row[0]}').hostname
        except ValueError:
            continue
        if host:
            names.add(host)
    return names


def from_otx(domain: str) -> Set[str]:
    key = get_env('OTX_API_KEY')
    if not key:
        raise SourceError('OTX_API_KEY not configured')
    data = _get(f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                headers={'X-OTX-API-KEY': key}).json()
    return {entry.get('hostname', '') for entry in data.get('passive_dns', [])}


PASSIVE_SOURCES: Dict[str, Callable[[str], Set[str]]] = {
    'ct_logs': from_ct_logs,
    'hackertarget': from_hackertarget,
    'wayback': from_wayback,
    'otx': from_otx,
}


def passive_subdomains(domain: str) -> Tuple[Set[str], Dict[str, object]]:
    """
    Query every passive source.

    Returns:
        (subdomains, stats) - stats maps source -> count found, or an error string
    """
    found, stats = set(), {}
    for source, fetch in PASSIVE_SOURCES.items():
        if source == 'otx' and not get_env('OTX_API_KEY'):
            stats[source] = 'skipped (no OTX_API_KEY)'
            continue
        try:
            names = {n for n in (in_scope(raw, domain) for raw in fetch(domain)) if n}
            found |= names
            stats[source] = len(names)
        except (SourceError, ValueError, KeyError, TypeError) as e:
            stats[source] = f'error: {e}'
            logger.warning(f"[Discovery] {source} failed for {domain}: {e}")
    return found, stats


# ---------------------------------------------------------------------------
# Active DNS discovery
# ---------------------------------------------------------------------------

def make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    return resolver


def resolves(name: str, resolver: dns.resolver.Resolver) -> Optional[bool]:
    """True if name has an A/AAAA record, False if it does not exist, None on DNS errors."""
    for rtype in ('A', 'AAAA'):
        try:
            resolver.resolve(name, rtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return None
    return False


def has_wildcard_dns(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """
    True if random names under domain resolve. Any doubt counts as wildcard,
    because brute forcing a wildcard domain would 'discover' every candidate.
    """
    for _ in range(2):
        label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        if resolves(f'{label}.{domain}', resolver) is not False:
            return True
    return False


def load_wordlist(path: str = WORDLIST_PATH) -> list:
    with open(path, encoding='utf8') as f:
        return [w.strip().lower() for w in f if w.strip() and not w.startswith('#')]


def permutation_candidates(domain: str, known: Iterable[str]) -> Set[str]:
    """Variations of the first label of known subdomains."""
    candidates = set()
    for name in sorted(known):
        if not name.endswith('.' + domain):
            continue
        first, _, rest = name.partition('.')
        for word in PERMUTATION_WORDS:
            if word == first:
                continue
            for label in (f'{first}-{word}', f'{word}-{first}', f'{first}{word}'):
                candidates.add(f'{label}.{rest}')
        for n in ('1', '2', '3'):
            candidates.add(f'{first}{n}.{rest}')
        if len(candidates) >= MAX_PERMUTATIONS:
            break
    return set(sorted(candidates)[:MAX_PERMUTATIONS])


def active_subdomains(domain: str, known: Iterable[str] = ()) -> Tuple[Set[str], Dict[str, object]]:
    """
    Brute force and permutations, resolved concurrently.

    Returns:
        (subdomains that resolve, stats)
    """
    if (get_env('DNS_BRUTEFORCE') or 'true').strip().lower() in ('0', 'false', 'no', 'off'):
        return set(), {'active': 'disabled (DNS_BRUTEFORCE=false)'}

    resolver = make_resolver()
    if has_wildcard_dns(domain, resolver):
        return set(), {'active': 'skipped (wildcard DNS)'}

    known = set(known)
    brute = {f'{word}.{domain}' for word in load_wordlist()}
    perms = permutation_candidates(domain, known)
    candidates = sorted({c for c in (brute | perms) - known if in_scope(c, domain)})

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
        results = list(executor.map(lambda name: (name, resolves(name, resolver)), candidates))

    found = {name for name, ok in results if ok}
    errors = sum(1 for _, ok in results if ok is None)
    return found, {
        'bruteforce': len(found & brute),
        'permutations': len(found & perms),
        'candidates': len(candidates),
        'dns_errors': errors,
    }


def discover(domain: str, known: Iterable[str] = ()) -> Tuple[Set[str], Dict[str, object]]:
    """Passive sources plus active DNS discovery for one root domain."""
    passive, stats = passive_subdomains(domain)
    active, active_stats = active_subdomains(domain, set(known) | passive)
    stats.update(active_stats)
    found = passive | active
    logger.info(f"[Discovery] {domain}: {len(found)} subdomains from extra sources {stats}")
    return found, stats


def run_discovery_monitor() -> dict:
    """
    Phase 3: run extra discovery for every monitored root domain and queue
    new subdomains for Phase 0 (DNS resolution, then a full scan).

    Returns:
        {'domains': int, 'new_subdomains': [(domain, subdomain)], 'stats': {domain: stats}}
    """
    from datetime import datetime, timezone
    from utils.db_utils import get_all_monitored_domains, get_known_subdomains, queue_subdomain_discovery, set_setting

    known = get_known_subdomains()
    result = {'domains': 0, 'new_subdomains': [], 'stats': {}}
    for domain in get_all_monitored_domains():
        result['domains'] += 1
        found, stats = discover(domain, {k for k in known if k.endswith('.' + domain)})
        result['stats'][domain] = stats
        for name in sorted(found - known):
            queue_subdomain_discovery(name, domain)
            result['new_subdomains'].append((domain, name))
            known.add(name)

    set_setting('last_discovery_check', utc_now_str())
    logger.info(f"[Discovery] Monitor complete: {result['domains']} domains, "
                f"{len(result['new_subdomains'])} new subdomains")
    return result


if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Discover subdomains (no DB changes)')
    parser.add_argument('domain')
    parser.add_argument('--passive-only', action='store_true')
    args = parser.parse_args()

    if args.passive_only:
        names, info = passive_subdomains(args.domain)
    else:
        names, info = discover(args.domain)
    print(info)
    for n in sorted(names):
        print(n)
