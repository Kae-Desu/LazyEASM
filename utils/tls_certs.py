"""
Certificates as served: connect to every HTTPS service and record the
certificate it presents.

This is the source for certificate expiry (asset list, alerts) and for
'certificate_changed' events. CT logs are not used for this: they list every
certificate ever issued, including ones a renewal already replaced, so an old
certificate would raise "expires in 7 days" for a site that serves a fresh one.
CT logs are only used to discover subdomains (utils/subdomain_discovery.py).

Exports:
    - fetch_served_certificate(host, port) -> dict
    - refresh_served_certificates(hosts=None) -> summary dict
    - refresh_quietly(hosts) -> None (after an asset scan)
"""

import hashlib
import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import timezone
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

TIMEOUT = 10
WORKERS = 10


def _display_name(name: x509.Name) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        values = name.get_attributes_for_oid(oid)
        if values:
            return str(values[0].value)
    return name.rfc4514_string()


def parse_certificate(der: bytes) -> dict:
    """Fields LazyEASM stores, from a DER-encoded certificate."""
    cert = x509.load_der_x509_certificate(der)
    timestamp = lambda value: value.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    try:
        dns_names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value \
            .get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []
    return {
        'subject': _display_name(cert.subject),
        'issuer': _display_name(cert.issuer),
        'not_before': timestamp(cert.not_valid_before_utc),
        'not_after': timestamp(cert.not_valid_after_utc),
        'serial_number': format(cert.serial_number, 'X'),
        'fingerprint': hashlib.sha256(der).hexdigest(),
        'dns_names': dns_names,
    }


def fetch_served_certificate(host: str, port: int = 443, timeout: float = TIMEOUT) -> dict:
    """
    The certificate the server presents for host (sent as SNI). Invalid
    certificates (expired, self-signed, wrong name) are read too: their
    validity is reported by the misconfiguration check.

    Raises:
        OSError / ssl.SSLError when no certificate could be read
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError('server presented no certificate')
    return {'hostname': host, 'port': port, **parse_certificate(der)}


def refresh_served_certificates(hosts: Optional[List[str]] = None) -> dict:
    """
    Read the certificate of every HTTPS service (or only those of hosts) and
    store it; a different certificate than last time is recorded as a change.

    Returns:
        {'checked': int, 'new': int, 'changed': [{'hostname', 'port', 'summary'}], 'errors': int}
    """
    from utils.db_utils import get_https_services, record_served_certificate, retire_served_certificates

    targets = get_https_services(hosts)
    summary = {'checked': len(targets), 'new': 0, 'changed': [], 'errors': 0}
    if not targets:
        return summary

    def fetch(target):
        host, port = target
        try:
            return target, fetch_served_certificate(host, port), None
        except (OSError, ssl.SSLError, ValueError) as e:
            return target, None, str(e)

    with ThreadPoolExecutor(max_workers=min(WORKERS, len(targets))) as pool:
        results = list(pool.map(fetch, targets))

    for (host, port), cert, error in results:
        if error:
            summary['errors'] += 1
            logger.debug(f"No certificate from {host}:{port}: {error}")
            continue
        status, change = record_served_certificate(cert)
        if status == 'new':
            summary['new'] += 1
        elif status == 'changed':
            summary['changed'].append(change)

    if hosts is None:
        # Services that are no longer HTTPS (or gone) no longer serve a certificate
        retire_served_certificates(targets)

    logger.info(f"Served certificates: {summary['checked']} services, {summary['new']} new, "
                f"{len(summary['changed'])} changed, {summary['errors']} unreachable")
    return summary


def refresh_quietly(hosts: List[str]) -> None:
    """Refresh certificates for a few hosts after a scan; never raises."""
    try:
        refresh_served_certificates(hosts)
    except Exception as e:
        logger.warning(f"Certificate refresh after scan failed: {e}")
