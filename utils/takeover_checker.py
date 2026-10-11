"""
Subdomain takeover checker for Phase 3.

For each known domain/subdomain:
    1. Follow the CNAME chain
    2. If a CNAME points at a service known to allow takeover
       (data/takeover_fingerprints.json, from can-i-take-over-xyz):
         - NXDOMAIN-based services: vulnerable if the target does not exist
         - HTTP-based services: vulnerable if the service's "unclaimed"
           page fingerprint is served for the hostname
    3. A CNAME whose target does not exist, on an unknown service, is
       reported as a dangling CNAME (lower severity)

DNS timeouts and unreachable HTTP endpoints make a check inconclusive:
inconclusive hosts never open or close findings.
"""

import os
import re
import json
import logging
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

import requests
import dns.resolver
import dns.exception
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINGERPRINTS_PATH = os.path.join(PROJECT_ROOT, 'data', 'takeover_fingerprints.json')

TAKEOVER = 'subdomain_takeover'
DANGLING = 'dangling_cname'
FINDING_TYPES = (TAKEOVER, DANGLING)

MAX_CNAME_DEPTH = 10
HTTP_TIMEOUT = 10
MAX_BODY_BYTES = 1024 * 1024
USER_AGENT = 'LazyEASM takeover-check'


@dataclass
class Service:
    name: str
    cname_suffixes: List[str]
    nxdomain: bool = False
    fingerprint: Optional[re.Pattern] = None
    http_status: Optional[int] = None

    def matches(self, hostname: str) -> bool:
        return any(hostname == s or hostname.endswith('.' + s) for s in self.cname_suffixes)


@dataclass
class CheckResult:
    host: str
    conclusive: bool
    findings: List[dict] = field(default_factory=list)
    error: Optional[str] = None


class DNSLookupError(Exception):
    """DNS failed in a way that says nothing about whether the name exists."""


def _is_ip(value: str) -> bool:
    return bool(re.fullmatch(r'[\d.]+|[0-9a-fA-F:]+:[0-9a-fA-F:]*', value))


def load_services(path: str = FINGERPRINTS_PATH) -> List[Service]:
    """Load the vulnerable services that can be identified by CNAME."""
    with open(path, encoding='utf8') as f:
        entries = json.load(f)

    services = []
    for entry in entries:
        if not entry.get('vulnerable'):
            continue
        suffixes = [c.lower().strip('.') for c in entry.get('cname', []) if c and not _is_ip(c)]
        if not suffixes:
            # Without a CNAME pattern the only signal is page text, which is
            # too generic (e.g. "404 Not Found") to trust on its own.
            continue

        service = Service(name=entry['service'], cname_suffixes=suffixes)
        fingerprint = (entry.get('fingerprint') or '').strip()

        if entry.get('nxdomain'):
            service.nxdomain = True
        elif fingerprint.startswith('HTTP_STATUS='):
            service.http_status = int(entry.get('http_status') or fingerprint.split('=', 1)[1])
        elif fingerprint:
            # Upstream fingerprints are regex-ish and sometimes contain an
            # HTML-escaped pipe from the Markdown table they were copied from.
            pattern = fingerprint.replace('&#124;', '|')
            try:
                service.fingerprint = re.compile(pattern)
            except re.error:
                service.fingerprint = re.compile(re.escape(fingerprint))
        else:
            continue
        services.append(service)
    return services


def resolve_cname_chain(host: str, resolver: dns.resolver.Resolver) -> Tuple[List[str], bool]:
    """
    Follow CNAME records from host.

    Returns:
        (chain, target_missing) - chain is the list of CNAME targets in order;
        target_missing is True when the last target does not exist (NXDOMAIN)

    Raises:
        DNSLookupError: on timeouts or failing nameservers
    """
    chain = []
    current = host
    for _ in range(MAX_CNAME_DEPTH):
        try:
            answer = resolver.resolve(current, 'CNAME')
        except dns.resolver.NoAnswer:
            return chain, False  # name exists, no further CNAME
        except dns.resolver.NXDOMAIN:
            return chain, current != host
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise DNSLookupError(f"{current}: {type(e).__name__}") from e

        target = str(answer[0].target).rstrip('.').lower()
        if target in chain or target == host:
            break  # CNAME loop
        chain.append(target)
        current = target
    return chain, False


def _fetch(host: str, allow_redirects: bool) -> Optional[Tuple[int, str, str]]:
    """GET https:// then http://. Returns (status, body, url) or None if both fail."""
    for scheme in ('https', 'http'):
        url = f"{scheme}://{host}/"
        try:
            # Unclaimed-service pages usually present the provider's own
            # certificate, so verification is off for fingerprinting only.
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', InsecureRequestWarning)
                with requests.get(url, timeout=HTTP_TIMEOUT, verify=False, stream=True,
                                  allow_redirects=allow_redirects,
                                  headers={'User-Agent': USER_AGENT}) as response:
                    body = response.raw.read(MAX_BODY_BYTES, decode_content=True) or b''
                    return response.status_code, body.decode(response.encoding or 'utf-8', 'replace'), url
        except (requests.RequestException, OSError):
            continue
    return None


def check_host(host: str, services: List[Service], resolver: dns.resolver.Resolver) -> CheckResult:
    """Check one hostname for takeover / dangling CNAME."""
    host = host.lower().strip('.')
    try:
        chain, target_missing = resolve_cname_chain(host, resolver)
    except DNSLookupError as e:
        return CheckResult(host, conclusive=False, error=str(e))

    if not chain:
        return CheckResult(host, conclusive=True)

    service = next((s for s in services if any(s.matches(c) for c in chain)), None)
    evidence = {'cname_chain': chain, 'target_missing': target_missing}

    if service and service.nxdomain:
        if not target_missing:
            return CheckResult(host, conclusive=True)
        return CheckResult(host, conclusive=True, findings=[{
            'finding_type': TAKEOVER,
            'title': f"Possible subdomain takeover ({service.name})",
            'severity': 'high',
            'evidence': {**evidence, 'service': service.name, 'signal': 'CNAME target does not exist'},
        }])

    if target_missing:
        return CheckResult(host, conclusive=True, findings=[{
            'finding_type': DANGLING,
            'title': f"Dangling CNAME to {chain[-1]}",
            'severity': 'medium',
            'evidence': {**evidence, **({'service': service.name} if service else {}),
                         'signal': 'CNAME target does not exist'},
        }])

    if not service:
        return CheckResult(host, conclusive=True)

    fetched = _fetch(host, allow_redirects=service.http_status is None)
    if fetched is None:
        return CheckResult(host, conclusive=False, error=f"{host}: HTTP unreachable")

    status, body, url = fetched
    if service.http_status is not None:
        matched = status == service.http_status
        signal = f"HTTP {status}"
    else:
        hit = service.fingerprint.search(body)
        matched = hit is not None
        signal = hit.group(0)[:200] if hit else None

    if not matched:
        return CheckResult(host, conclusive=True)

    return CheckResult(host, conclusive=True, findings=[{
        'finding_type': TAKEOVER,
        'title': f"Possible subdomain takeover ({service.name})",
        'severity': 'high',
        'evidence': {**evidence, 'service': service.name, 'url': url,
                     'http_status': status, 'signal': signal},
    }])


def run_takeover_check(hosts: List[str] = None, max_workers: int = 20) -> dict:
    """
    Check all known domains/subdomains and update findings.

    Returns:
        {
            'hosts_checked': int,
            'inconclusive': int,
            'open_findings': [{'host', 'title', 'severity'}],  # all currently detected
            'new_findings': [{'host', 'title', 'severity'}],   # new or reopened
            'closed': int,
            'errors': [str]
        }
    """
    from utils.db_utils import (
        get_hostnames_for_takeover_check, upsert_finding, reconcile_findings, set_setting
    )

    if hosts is None:
        hosts = get_hostnames_for_takeover_check()

    services = load_services()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    result = {
        'hosts_checked': 0,
        'inconclusive': 0,
        'open_findings': [],
        'new_findings': [],
        'closed': 0,
        'errors': [],
    }

    logger.info(f"Starting takeover check for {len(hosts)} hosts ({len(services)} service fingerprints)")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        checks = list(executor.map(lambda h: check_host(h, services, resolver), hosts))

    # DB writes on this thread only (SQLite)
    for check in checks:
        result['hosts_checked'] += 1
        if not check.conclusive:
            result['inconclusive'] += 1
            if check.error:
                result['errors'].append(check.error)
            continue

        seen = []
        for finding in check.findings:
            finding_id, alert = upsert_finding(
                finding['finding_type'], check.host, finding['title'],
                finding['severity'], finding['evidence']
            )
            seen.append(finding_id)
            summary = {'host': check.host, 'title': finding['title'], 'severity': finding['severity']}
            result['open_findings'].append(summary)
            if alert:
                result['new_findings'].append(summary)

        result['closed'] += reconcile_findings(check.host, FINDING_TYPES, seen)

    set_setting('last_takeover_check', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))

    logger.info(
        f"Takeover check complete: {result['hosts_checked']} hosts, "
        f"{len(result['open_findings'])} detected, {len(result['new_findings'])} new, "
        f"{result['closed']} closed, {result['inconclusive']} inconclusive"
    )
    return result


if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Subdomain takeover check')
    parser.add_argument('hosts', nargs='*', help='Hosts to check (default: all known assets, updates DB)')
    args = parser.parse_args()

    if args.hosts:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        services = load_services()
        for h in args.hosts:
            r = check_host(h, services, resolver)
            print(f"{r.host}: conclusive={r.conclusive} error={r.error}")
            for f in r.findings:
                print(f"  [{f['severity']}] {f['title']} {f['evidence']}")
    else:
        print(run_takeover_check())
