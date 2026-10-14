"""
HTTPS for the dashboard without a reverse proxy.

TLS_MODE in .env:
    self-signed  a certificate generated for this server (in db/tls/, renewed
                 30 days before it expires and when the server's names change).
                 Browsers warn once; compare the fingerprint shown in the
                 startup log and in Settings > Account, then accept it
    custom       your own certificate: TLS_CERT_FILE and TLS_KEY_FILE (PEM),
                 e.g. from Let's Encrypt or a company CA
    off          plain HTTP (default for installs that predate this setting;
                 use it behind a reverse proxy that handles HTTPS)

TLS_HOSTNAMES adds names or IP addresses to the self-signed certificate (the
server's public IP when it cannot be detected, e.g. in Docker).
"""

import hashlib
import ipaddress
import logging
import os
import socket
import ssl
from datetime import timedelta
from typing import List, Optional, Tuple

from utils.config import get_env
from utils.timeutil import utc_now

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLS_DIR = os.path.join(PROJECT_ROOT, 'db', 'tls')
CERT_FILE = os.path.join(TLS_DIR, 'selfsigned.crt')
KEY_FILE = os.path.join(TLS_DIR, 'selfsigned.key')
VALIDITY = timedelta(days=825)
RENEW_BEFORE = timedelta(days=30)
MODES = ('off', 'self-signed', 'custom')


class TLSConfigError(Exception):
    """TLS is enabled but cannot be set up (missing files, bad mode)."""


def tls_mode() -> str:
    mode = (get_env('TLS_MODE', '') or '').strip().lower()
    if not mode:
        return 'custom' if get_env('TLS_CERT_FILE', '') else 'off'
    if mode not in MODES:
        raise TLSConfigError(f"TLS_MODE must be one of: {', '.join(MODES)}")
    return mode


def _primary_ip() -> Optional[str]:
    """Address of the interface used for outbound traffic (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 9))
            return s.getsockname()[0]
    except OSError:
        return None


def server_names() -> Tuple[List[str], List[str]]:
    """(DNS names, IP addresses) the self-signed certificate should cover."""
    names, ips = {'localhost'}, {'127.0.0.1', '::1'}
    for name in (socket.gethostname(), socket.getfqdn()):
        if name:
            names.add(name.lower())
    for candidate in [_primary_ip(), get_env('HOST', ''), get_env('PUBLIC_IP', '')] + \
            [v.strip() for v in (get_env('TLS_HOSTNAMES', '') or '').split(',')]:
        if not candidate or candidate in ('0.0.0.0', '::'):
            continue
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            names.add(candidate.lower())
    return sorted(names), sorted(ips)


def _load_cert(path: str):
    from cryptography import x509
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def _covers(cert, names: List[str], ips: List[str]) -> bool:
    from cryptography import x509
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    return set(names) <= set(san.get_values_for_type(x509.DNSName)) and \
        set(ips) <= {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}


def ensure_self_signed() -> Tuple[str, str, bool]:
    """
    The self-signed certificate, generated when missing, expiring within 30
    days, or no longer covering this server's names.

    Returns:
        (cert path, key path, newly created)
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    names, ips = server_names()
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        try:
            cert = _load_cert(CERT_FILE)
            if cert.not_valid_after_utc.replace(tzinfo=None) - utc_now() > RENEW_BEFORE and _covers(cert, names, ips):
                return CERT_FILE, KEY_FILE, False
        except (OSError, ValueError):
            pass

    key = ec.generate_private_key(ec.SECP256R1())
    now = utc_now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'LazyEASM'),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LazyEASM self-signed')])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + VALIDITY)
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))

    os.makedirs(TLS_DIR, exist_ok=True)
    key_tmp, cert_tmp = KEY_FILE + '.tmp', CERT_FILE + '.tmp'
    fd = os.open(key_tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cert_tmp, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.replace(key_tmp, KEY_FILE)
    os.replace(cert_tmp, CERT_FILE)
    logger.info(f"Generated a self-signed HTTPS certificate for {', '.join(names + ips)}")
    return CERT_FILE, KEY_FILE, True


def certificate_files() -> Optional[Tuple[str, str]]:
    """(cert, key) to serve HTTPS with, or None when TLS is off. Raises TLSConfigError."""
    mode = tls_mode()
    if mode == 'off':
        return None
    if mode == 'self-signed':
        cert, key, _ = ensure_self_signed()
        return cert, key
    cert, key = get_env('TLS_CERT_FILE', ''), get_env('TLS_KEY_FILE', '')
    if not cert or not key or not os.path.exists(cert) or not os.path.exists(key):
        raise TLSConfigError('TLS_MODE=custom needs readable TLS_CERT_FILE and TLS_KEY_FILE')
    return cert, key


def describe(cert_path: str) -> dict:
    """{'fingerprint' (SHA-256, colon-separated), 'not_after', 'names'} for display."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = _load_cert(cert_path)
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    return {'fingerprint': ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2)),
            'not_after': cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S'), 'names': names}


def status() -> dict:
    """What Settings shows: {'mode', 'fingerprint', 'not_after', 'names', 'error'}."""
    try:
        mode = tls_mode()
        if mode == 'off':
            return {'mode': 'off', 'fingerprint': None, 'not_after': None, 'names': [], 'error': None}
        cert = CERT_FILE if mode == 'self-signed' else get_env('TLS_CERT_FILE', '')
        return {'mode': mode, **describe(cert), 'error': None}
    except (TLSConfigError, OSError, ValueError) as e:
        return {'mode': 'error', 'fingerprint': None, 'not_after': None, 'names': [], 'error': str(e)}


def ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """Server context: TLS 1.2 or newer."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    return context
