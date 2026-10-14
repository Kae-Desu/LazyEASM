"""
Misconfiguration checks for Phase 3.

Web checks run against every HTTP service found by Wappalyzer
(http_services). Port checks run against risky ports recorded by Nmap on
public, non-CDN IPs, and re-confirm the port is still open with a TCP connect.

All requests are single GETs without following redirects, so a login
redirect or a soft-404 page is never mistaken for an exposed file: every
file check requires a content signature, not just HTTP 200.

Each check reports which finding types it could evaluate. Timeouts leave a
type unevaluated, so a slow host never closes or reopens findings.
"""

import re
import socket
import ssl
import logging
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple

import requests
from urllib3.exceptions import InsecureRequestWarning
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 10
TCP_TIMEOUT = 3
MAX_BODY_BYTES = 256 * 1024
USER_AGENT = 'LazyEASM misconfig-check'

REFUSED = 'refused'   # connection refused: the service is definitely not there
UNSERVED = 'unserved_hostname'
UNSERVED_STRIKES_KEY = 'unserved_hostname_strikes'   # settings: {host: consecutive detections}
UNSERVED_CONFIRMATIONS = 2


@dataclass
class FileCheck:
    finding_type: str
    path: str
    title: str
    severity: str
    matches: Callable[[bytes], bool]
    detail: str


def _text(body: bytes) -> str:
    return body.decode('utf-8', 'replace')


def _looks_like_env(body: bytes) -> bool:
    text = _text(body)
    if '<html' in text.lower() or '<!doctype' in text.lower():
        return False
    assignments = re.findall(r'^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=', text, re.MULTILINE)
    return len(assignments) >= 2


def _looks_like_git_head(body: bytes) -> bool:
    text = _text(body).strip()
    return text.startswith('ref: refs/') or bool(re.fullmatch(r'[0-9a-f]{40}', text))


def _looks_like_htpasswd(body: bytes) -> bool:
    return bool(re.search(r'^[\w.@-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[56]\$|[./0-9A-Za-z]{13}$)',
                          _text(body), re.MULTILINE))


FILE_CHECKS = [
    FileCheck('exposed_git', '/.git/HEAD', 'Git repository exposed', 'high', _looks_like_git_head,
              'The .git directory is served; source code and history can be downloaded.'),
    FileCheck('exposed_env', '/.env', 'Environment file exposed', 'high', _looks_like_env,
              'A .env file is served; it typically contains credentials and API keys.'),
    FileCheck('exposed_htpasswd', '/.htpasswd', 'Password file exposed', 'high', _looks_like_htpasswd,
              'An .htpasswd file with password hashes is served.'),
    FileCheck('apache_server_status', '/server-status', 'Apache server-status exposed', 'medium',
              lambda b: 'Apache Server Status for' in _text(b),
              'mod_status reveals client IPs, requested URLs and server internals.'),
    FileCheck('phpinfo_exposed', '/phpinfo.php', 'phpinfo() page exposed', 'medium',
              lambda b: 'phpinfo()' in _text(b) and 'PHP Version' in _text(b),
              'phpinfo() reveals configuration, paths, modules and environment variables.'),
    FileCheck('exposed_ds_store', '/.DS_Store', '.DS_Store file exposed', 'low',
              lambda b: b[:8] == b'\x00\x00\x00\x01Bud1',
              'A macOS .DS_Store file reveals file and directory names.'),
]

# port -> (service, severity, why it matters)
RISKY_PORTS: Dict[int, Tuple[str, str, str]] = {
    23: ('Telnet', 'high', 'cleartext remote login'),
    21: ('FTP', 'medium', 'cleartext credentials'),
    445: ('SMB', 'high', 'frequent target of wormable exploits and ransomware'),
    3389: ('RDP', 'high', 'top initial-access vector for ransomware'),
    5900: ('VNC', 'high', 'remote desktop often protected by a weak password'),
    2375: ('Docker API (unencrypted)', 'critical', 'unauthenticated control of the Docker host'),
    2379: ('etcd', 'high', 'often unauthenticated; may hold cluster secrets'),
    10250: ('Kubelet API', 'high', 'can allow command execution in pods'),
    6379: ('Redis', 'high', 'often runs without authentication'),
    27017: ('MongoDB', 'high', 'often runs without authentication'),
    9200: ('Elasticsearch', 'high', 'often runs without authentication'),
    11211: ('Memcached', 'high', 'unauthenticated; abused for DDoS amplification'),
    5984: ('CouchDB', 'high', 'often misconfigured with admin party access'),
    3306: ('MySQL', 'medium', 'database exposed to the internet'),
    5432: ('PostgreSQL', 'medium', 'database exposed to the internet'),
    1433: ('Microsoft SQL Server', 'medium', 'database exposed to the internet'),
    1521: ('Oracle Database', 'medium', 'database exposed to the internet'),
}

TLS_CERT = 'tls_invalid_certificate'
TLS_LEGACY = 'tls_legacy_protocol'
NO_HTTPS_REDIRECT = 'http_no_https_redirect'
MISSING_HEADERS = 'missing_security_headers'
DIRECTORY_LISTING = 'directory_listing'

WEB_FINDING_TYPES = tuple(c.finding_type for c in FILE_CHECKS) + (
    TLS_CERT, TLS_LEGACY, NO_HTTPS_REDIRECT, MISSING_HEADERS, DIRECTORY_LISTING)


def port_finding_type(port: int) -> str:
    return f'exposed_port_{port}'


PORT_FINDING_TYPES = tuple(port_finding_type(p) for p in RISKY_PORTS)

ALERT_SEVERITIES = ('critical', 'high', 'medium')


@dataclass
class HostResult:
    host: str
    evaluated: set = field(default_factory=set)
    findings: Dict[str, dict] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add(self, finding_type: str, title: str, severity: str, detail: str, url: str = None, **extra):
        finding = self.findings.setdefault(finding_type, {
            'finding_type': finding_type, 'title': title, 'severity': severity,
            'evidence': {'detail': detail, 'urls': [], **extra},
        })
        if url and url not in finding['evidence']['urls']:
            finding['evidence']['urls'].append(url)


def _base_url(host: str, port: int, is_https: bool) -> str:
    scheme = 'https' if is_https else 'http'
    default = 443 if is_https else 80
    return f"{scheme}://{host}" + ('' if port == default else f":{port}")


def http_get(url: str):
    """
    GET without redirects. Returns (status, headers, body) or REFUSED, or None
    when the result is inconclusive (timeout, TLS failure, other errors).
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            with requests.get(url, timeout=HTTP_TIMEOUT, verify=False, stream=True, allow_redirects=False,
                              headers={'User-Agent': USER_AGENT}) as response:
                body = response.raw.read(MAX_BODY_BYTES, decode_content=True) or b''
                return response.status_code, response.headers, body
    except requests.exceptions.ConnectionError as e:
        if isinstance(e, requests.exceptions.ConnectTimeout):
            return None
        return REFUSED if 'refused' in str(e).lower() else None
    except (requests.RequestException, OSError):
        return None


def tcp_open(host: str, port: int) -> Optional[bool]:
    """True if open, False if refused, None if inconclusive (timeout)."""
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except ConnectionRefusedError:
        return False
    except OSError:
        return None


def check_certificate(host: str, port: int) -> Tuple[Optional[bool], Optional[str]]:
    """
    Returns:
        (True, None) valid; (False, reason) invalid; (None, error) inconclusive
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, e.verify_message or str(e)
    except (ssl.SSLError, OSError) as e:
        return None, str(e)


def legacy_tls_versions(host: str, port: int) -> Optional[List[str]]:
    """
    TLS versions below 1.2 that the server accepts, or None if this could not
    be tested (local OpenSSL refuses them, or the host did not answer).
    """
    accepted = []
    for name, version in (('TLS 1.0', ssl.TLSVersion.TLSv1), ('TLS 1.1', ssl.TLSVersion.TLSv1_1)):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
            context.set_ciphers('DEFAULT:@SECLEVEL=0')
        except (ValueError, ssl.SSLError):
            return None
        try:
            sock = socket.create_connection((host, port), timeout=HTTP_TIMEOUT)
        except OSError:
            return None  # host unreachable: inconclusive
        try:
            with context.wrap_socket(sock, server_hostname=host):
                accepted.append(name)
        except ssl.SSLError as e:
            if 'no protocols available' in str(e).lower():
                return None  # this machine cannot offer the version at all
            # otherwise the server rejected the version
        except OSError:
            pass  # servers often reject an old version by resetting the connection
        finally:
            sock.close()
    return accepted


def check_web(host: str, services: List[Tuple[int, bool]]) -> HostResult:
    """Run web checks for one hostname across its HTTP services."""
    result = HostResult(host)
    if not services:
        return result

    # Exposed files and directory listing, on every service.
    # A service that refuses once is not probed again for the other paths.
    refused = set()
    for check in FILE_CHECKS + [None]:
        conclusive = True
        for port, is_https in services:
            if port in refused:
                continue
            base = _base_url(host, port, is_https)
            url = base + (check.path if check else '/')
            response = http_get(url)
            if response is None:
                conclusive = False
                continue
            if response == REFUSED:
                refused.add(port)
                continue
            status, headers, body = response
            if status != 200:
                continue
            if check and check.matches(body):
                result.add(check.finding_type, check.title, check.severity, check.detail, url)
            elif check is None and re.search(rb'<title>\s*Index of /', body, re.IGNORECASE):
                result.add(DIRECTORY_LISTING, 'Directory listing enabled', 'medium',
                           'The web server lists directory contents, exposing file names.', url)
        if conclusive:
            result.evaluated.add(check.finding_type if check else DIRECTORY_LISTING)

    https_ports = [port for port, is_https in services if is_https]

    # TLS certificate and protocol versions
    cert_conclusive = legacy_conclusive = bool(https_ports)
    for port in https_ports:
        url = _base_url(host, port, True)
        valid, reason = check_certificate(host, port)
        if valid is None:
            cert_conclusive = False
        elif not valid:
            result.add(TLS_CERT, 'Invalid TLS certificate', 'medium',
                       f'Browsers will show a security warning: {reason}.', url, reason=reason)

        versions = legacy_tls_versions(host, port)
        if versions is None:
            legacy_conclusive = False
        elif versions:
            result.add(TLS_LEGACY, 'Legacy TLS versions enabled', 'medium',
                       f"Server accepts {', '.join(versions)}, which are deprecated and insecure.",
                       url, versions=versions)
    if cert_conclusive:
        result.evaluated.add(TLS_CERT)
    if legacy_conclusive:
        result.evaluated.add(TLS_LEGACY)

    if https_ports:
        # HTTP on port 80 should redirect when HTTPS is available
        response = http_get(f"http://{host}/")
        if response is not None:
            result.evaluated.add(NO_HTTPS_REDIRECT)
            if response != REFUSED and 200 <= response[0] < 300:
                result.add(NO_HTTPS_REDIRECT, 'HTTP served without redirect to HTTPS', 'low',
                           'Content is available over unencrypted HTTP although HTTPS works.',
                           f"http://{host}/")

        # Security headers on the HTTPS homepage
        url = _base_url(host, https_ports[0], True) + '/'
        response = http_get(url)
        if response is not None and response != REFUSED:
            result.evaluated.add(MISSING_HEADERS)
            headers = {k.lower() for k in response[1].keys()}
            missing = []
            if 'strict-transport-security' not in headers:
                missing.append('Strict-Transport-Security')
            if 'x-content-type-options' not in headers:
                missing.append('X-Content-Type-Options')
            if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
                missing.append('X-Frame-Options or Content-Security-Policy')
            if missing:
                result.add(MISSING_HEADERS, 'Missing security headers', 'low',
                           f"Missing: {', '.join(missing)}.", url, missing=missing)

    return result


def _tls_state(host: str, port: int = 443) -> Optional[str]:
    """'ok' (a certificate was presented), 'rejected' (TLS refused for this name), 'closed', or None."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return 'ok'
    except ssl.SSLError:
        return 'rejected'
    except ConnectionRefusedError:
        return 'closed'
    except OSError:
        return None   # timeout or network error: inconclusive


def _http_state(host: str) -> Optional[str]:
    """'ok' (content or an error page), 'to_https' (redirects to HTTPS), 'closed', or None."""
    response = http_get(f"http://{host}/")
    if response is None:
        return None
    if response == REFUSED:
        return 'closed'
    status, headers, _ = response
    if 300 <= status < 400 and (headers.get('Location') or '').lower().startswith('https://'):
        return 'to_https'
    return 'ok'


def check_unserved(host: str, ips: List[str]) -> HostResult:
    """
    A hostname whose DNS points to a server that does not serve it: the server
    rejects TLS for the name, or redirects to HTTPS that is not there. If the
    address is ever reassigned, the name serves whatever the new owner hosts.
    Hosts with no web server at all are not reported (mail, SSH-only hosts).
    """
    result = HostResult(host)
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        result.evaluated.add(UNSERVED)    # the record was removed: nothing left to serve
        return result

    tls, http = _tls_state(host), _http_state(host)
    if tls == 'ok' or http == 'ok' or (tls == 'closed' and http == 'closed'):
        result.evaluated.add(UNSERVED)
    elif tls == 'rejected' or (http == 'to_https' and tls == 'closed'):
        result.evaluated.add(UNSERVED)
        reason = ('rejects the TLS connection for this name' if tls == 'rejected'
                  else 'redirects to HTTPS, which is not running')
        where = ', '.join(ips) if ips else 'its current address'
        result.add(UNSERVED, 'Hostname points to a server that does not serve it', 'low',
                   f"DNS points {host} to {where}, but the web server there {reason}. If that address is "
                   f"ever reassigned, this name would serve someone else's content. Remove the DNS record "
                   f"or configure the site.", f"https://{host}/", ips=ips, tls=tls, http=http)
    return result


def _apply_confirmations(results: List[HostResult]) -> None:
    """
    Report an unserved hostname only after UNSERVED_CONFIRMATIONS checks in a
    row agree, so one bad moment does not open a finding. A host that is served
    again starts over.
    """
    import json
    from utils.db_utils import get_setting, set_setting

    try:
        strikes = json.loads(get_setting(UNSERVED_STRIKES_KEY) or '{}')
    except ValueError:
        strikes = {}
    for result in results:
        if UNSERVED in result.findings:
            strikes[result.host] = strikes.get(result.host, 0) + 1
            if strikes[result.host] < UNSERVED_CONFIRMATIONS:
                del result.findings[UNSERVED]
                result.evaluated.discard(UNSERVED)   # not confirmed yet: leave any finding as it is
        elif UNSERVED in result.evaluated:
            strikes.pop(result.host, None)
    set_setting(UNSERVED_STRIKES_KEY, json.dumps(strikes))


def check_ports(ip: str, ports: List[int]) -> HostResult:
    """Re-confirm risky ports recorded by Nmap on a public IP."""
    result = HostResult(ip)
    for port in ports:
        if port not in RISKY_PORTS:
            continue
        state = tcp_open(ip, port)
        if state is None:
            continue
        finding_type = port_finding_type(port)
        result.evaluated.add(finding_type)
        if state:
            service, severity, why = RISKY_PORTS[port]
            result.add(finding_type, f"{service} exposed to the internet (port {port})", severity,
                       f"{service} on port {port} is reachable from the internet: {why}.",
                       f"{ip}:{port}", port=port, service=service)
    return result


def run_misconfig_check(hosts: List[str] = None, ips: List[str] = None, max_workers: int = 10) -> dict:
    """
    Run web checks for hostnames and port checks for public IPs, then update findings.

    Args:
        hosts: hostnames to check (default: every host with an HTTP service)
        ips: IPs to check for risky ports (default: every public non-CDN IP)

    Returns:
        {'hosts_checked', 'open_findings', 'new_findings', 'closed', 'errors'}
        new_findings only includes medium severity and above (used for alerts)
    """
    from utils.db_utils import (
        get_http_services_by_host, get_risky_ports_by_ip, get_unserved_candidates, upsert_finding,
        reconcile_findings, set_setting
    )

    full_run = hosts is None and ips is None
    services = get_http_services_by_host(hosts)
    risky_ports = get_risky_ports_by_ip(list(RISKY_PORTS), ips)
    unserved = get_unserved_candidates(hosts)

    jobs = [(check_web, host, svc) for host, svc in services.items()] + \
           [(check_ports, ip, ports) for ip, ports in risky_ports.items()] + \
           [(check_unserved, host, host_ips) for host, host_ips in unserved.items()]

    logger.info(f"Starting misconfiguration check: {len(services)} hosts, {len(risky_ports)} IPs, "
                f"{len(unserved)} hostnames without a web service")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda job: job[0](job[1], job[2]), jobs))
    _apply_confirmations(results[len(results) - len(unserved):] if unserved else [])

    summary = {'hosts_checked': len(results), 'open_findings': [], 'new_findings': [], 'closed': 0, 'errors': []}

    # DB writes on this thread only (SQLite)
    for result in results:
        summary['errors'].extend(result.errors)
        seen = []
        for finding in result.findings.values():
            finding_id, alert = upsert_finding(finding['finding_type'], result.host, finding['title'],
                                               finding['severity'], finding['evidence'])
            seen.append(finding_id)
            item = {'host': result.host, 'title': finding['title'], 'severity': finding['severity']}
            summary['open_findings'].append(item)
            if alert and finding['severity'] in ALERT_SEVERITIES:
                summary['new_findings'].append(item)
        summary['closed'] += reconcile_findings(result.host, result.evaluated, seen)

    if full_run:
        set_setting('last_misconfig_check', utc_now_str())

    logger.info(f"Misconfiguration check complete: {summary['hosts_checked']} targets, "
                f"{len(summary['open_findings'])} detected, {len(summary['new_findings'])} new, "
                f"{summary['closed']} closed")
    return summary


def check_quietly(hosts: List[str] = None, ips: List[str] = None) -> None:
    """Check assets right after they are scanned and alert on new findings. Never raises."""
    try:
        result = run_misconfig_check(hosts=hosts or [], ips=ips or [])
        if result['new_findings']:
            from utils.phase3_worker import send_misconfig_notification
            send_misconfig_notification(result)
    except Exception as e:
        logger.warning(f"Misconfiguration check after scan failed: {e}")


if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Misconfiguration checks')
    parser.add_argument('host', nargs='?', help='Check one host on 80/443 without touching the DB')
    args = parser.parse_args()

    if args.host:
        r = check_web(args.host, [(80, False), (443, True)])
        print(f"{r.host}: evaluated={sorted(r.evaluated)}")
        for f in r.findings.values():
            print(f"  [{f['severity']}] {f['title']}: {f['evidence']['detail']} {f['evidence']['urls']}")
    else:
        print(run_misconfig_check())
