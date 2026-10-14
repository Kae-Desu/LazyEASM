"""
Web screenshots of HTTP services, for visual triage.

Each HTTP service found by Wappalyzer is opened in headless Chromium
(Playwright) and captured as a JPEG plus a thumbnail. A perceptual hash is
stored so that a page that looks substantially different from the last
capture is recorded in the change history.

Rendering untrusted pages is risky, so every capture is constrained:
    - a fresh browser context per page (no shared cookies or storage)
    - downloads and service workers disabled, short timeouts, size limits
    - every request is checked: private, loopback, link-local (including the
      cloud metadata address 169.254.169.254) and reserved destinations are
      blocked, except the asset's own IPs (internal assets may be scanned on
      purpose)
    - Chromium's sandbox is used whenever the process is not root

Toggle in the dashboard (Settings > Discovery) or SCREENSHOTS_ENABLED=false.
"""

import ipaddress
import logging
import os
import secrets
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urlsplit

from utils.config import get_env
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCREENSHOT_DIR = os.path.join(PROJECT_ROOT, 'db', 'screenshots')

VIEWPORT = {'width': 1280, 'height': 800}
NAVIGATION_TIMEOUT_MS = 15000
SETTLE_MS = 1000
JPEG_QUALITY = 70
THUMB_SIZE = (320, 200)
MAX_IMAGE_BYTES = 5 * 1024 * 1024
KEEP_PER_SERVICE = 5
HASH_SIZE = 16                   # 16x16 average hash = 256 bits
CHANGE_THRESHOLD_BITS = 64       # >25% of bits differ: the page looks different
USER_AGENT = 'Mozilla/5.0 (compatible; LazyEASM screenshot)'


class ScreenshotUnavailable(Exception):
    """Playwright or its Chromium build is not installed."""


@dataclass
class Capture:
    http_id: int
    host: str
    url: str
    ok: bool = False
    image: bytes = b''
    thumbnail: bytes = b''
    phash: str = ''
    final_url: str = ''
    status_code: Optional[int] = None
    title: str = ''
    error: Optional[str] = None
    blocked: List[str] = field(default_factory=list)


def screenshots_enabled() -> bool:
    return (get_env('SCREENSHOTS_ENABLED') or 'true').strip().lower() not in ('0', 'false', 'no', 'off')


# ---------------------------------------------------------------------------
# Request filtering
# ---------------------------------------------------------------------------

def _is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if getattr(addr, 'ipv4_mapped', None):
        addr = addr.ipv4_mapped
    return (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_reserved or addr.is_unspecified)


class RequestFilter:
    """Decides which requests a page may make. Resolution results are cached per capture."""

    def __init__(self, allowed_ips: Iterable[str] = (), resolver=None):
        self.allowed_ips = set(allowed_ips)
        self._resolve = resolver or self._system_resolve
        self._cache: Dict[str, Set[str]] = {}
        self.blocked: List[str] = []

    @staticmethod
    def _system_resolve(host: str) -> Set[str]:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}

    def resolve(self, host: str) -> Set[str]:
        if host not in self._cache:
            try:
                ipaddress.ip_address(host)
                self._cache[host] = {host}
            except ValueError:
                try:
                    self._cache[host] = self._resolve(host)
                except OSError:
                    self._cache[host] = set()
        return self._cache[host]

    def allows(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme in ('data', 'blob', 'about'):
            return True
        if parts.scheme not in ('http', 'https', 'ws', 'wss') or not parts.hostname:
            self.blocked.append(url)
            return False
        ips = self.resolve(parts.hostname.strip('[]'))
        internal = {ip for ip in ips if _is_internal(ip)}
        if internal - self.allowed_ips:
            self.blocked.append(url)
            return False
        return True


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

def average_hash(image_bytes: bytes) -> str:
    from PIL import Image
    image = Image.open(BytesIO(image_bytes)).convert('L').resize((HASH_SIZE, HASH_SIZE))
    pixels = list(image.getdata())
    mean = sum(pixels) / len(pixels)
    bits = ''.join('1' if p > mean else '0' for p in pixels)
    return f'{int(bits, 2):0{HASH_SIZE * HASH_SIZE // 4}x}'


def hash_distance(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count('1')


def make_thumbnail(image_bytes: bytes) -> bytes:
    from PIL import Image
    image = Image.open(BytesIO(image_bytes)).convert('RGB')
    image.thumbnail(THUMB_SIZE)
    out = BytesIO()
    image.save(out, format='JPEG', quality=JPEG_QUALITY)
    return out.getvalue()


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def capture_pages(targets: List[dict], resolver=None) -> List[Capture]:
    """
    Capture each target {'http_id', 'host', 'url', 'allowed_ips'} with one browser.

    Raises:
        ScreenshotUnavailable if Playwright or Chromium is missing
    """
    try:
        from playwright.sync_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeout, sync_playwright
    except ImportError as e:
        raise ScreenshotUnavailable('Playwright is not installed (pip install playwright)') from e

    results = []
    with sync_playwright() as playwright:
        try:
            # Chromium's sandbox cannot run as root (the default in Docker)
            sandbox = not (hasattr(os, 'geteuid') and os.geteuid() == 0)
            browser = playwright.chromium.launch(headless=True, chromium_sandbox=sandbox)
        except PlaywrightError as e:
            if 'No usable sandbox' in str(e):
                # Ubuntu 23.10+ blocks the user namespaces the sandbox needs for
                # binaries without an AppArmor profile; see README > Quick start (Ubuntu 23.10 or newer)
                raise ScreenshotUnavailable(
                    'Chromium sandbox is blocked by the OS (AppArmor user namespace restriction). '
                    'Add an AppArmor profile for the Playwright Chromium binary; see README.') from e
            raise ScreenshotUnavailable(f'Chromium is not available (python -m playwright install chromium): {e}') from e
        try:
            for target in targets:
                results.append(_capture_one(browser, target, resolver, PlaywrightError, PlaywrightTimeout))
        finally:
            browser.close()
    return results


def _capture_one(browser, target: dict, resolver, PlaywrightError, PlaywrightTimeout) -> Capture:
    capture = Capture(http_id=target['http_id'], host=target['host'], url=target['url'])
    request_filter = RequestFilter(target.get('allowed_ips', ()), resolver)
    # the asset's own addresses may be internal; nothing else internal is reachable
    request_filter.allowed_ips |= request_filter.resolve(target['host'])
    context = browser.new_context(
        viewport=VIEWPORT, ignore_https_errors=True, accept_downloads=False,
        service_workers='block', user_agent=USER_AGENT,
    )
    try:
        context.set_default_timeout(NAVIGATION_TIMEOUT_MS)
        context.route('**/*', lambda route: route.continue_() if request_filter.allows(route.request.url)
                      else route.abort('blockedbyclient'))
        page = context.new_page()
        try:
            response = page.goto(target['url'], wait_until='load', timeout=NAVIGATION_TIMEOUT_MS)
            capture.status_code = response.status if response else None
        except PlaywrightTimeout:
            pass  # capture whatever rendered before the timeout
        page.wait_for_timeout(SETTLE_MS)
        capture.final_url = page.url
        capture.title = (page.title() or '')[:200]
        image = page.screenshot(type='jpeg', quality=JPEG_QUALITY, full_page=False)
        if len(image) > MAX_IMAGE_BYTES:
            raise ValueError('screenshot too large')
        capture.image = image
        capture.thumbnail = make_thumbnail(image)
        capture.phash = average_hash(image)
        capture.ok = True
    except (PlaywrightError, ValueError, OSError) as e:
        capture.error = str(e).splitlines()[0][:200]
    finally:
        capture.blocked = request_filter.blocked
        context.close()
    return capture


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def _write(name: str, data: bytes) -> None:
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    with open(os.path.join(SCREENSHOT_DIR, name), 'wb') as f:
        f.write(data)


def run_screenshots(hosts: List[str] = None) -> dict:
    """
    Capture every HTTP service (or those of the given hosts) and store the results.

    Returns:
        {'available': bool, 'captured': int, 'failed': int, 'changed': [host],
         'blocked_requests': int, 'duplicates': int, 'error': str | None}
        duplicates: HTTP services skipped because they redirect to an HTTPS page captured in the same run
    """
    from utils.db_utils import delete_screenshots, get_screenshot_targets, store_screenshot, set_setting

    summary = {'available': True, 'captured': 0, 'failed': 0, 'changed': [], 'blocked_requests': 0, 'duplicates': 0,
               'error': None}
    if not screenshots_enabled():
        summary.update(available=False, error='Screenshots are disabled in settings')
        return summary

    targets = get_screenshot_targets(hosts)
    if not targets:
        return summary

    logger.info(f"Capturing screenshots for {len(targets)} web services")
    try:
        captures = capture_pages(targets)
    except ScreenshotUnavailable as e:
        logger.warning(str(e))
        summary.update(available=False, error=str(e))
        return summary

    # An HTTP service that redirects to the HTTPS page captured in this run
    # would only store the same picture twice
    https_pages = {(c.host, c.final_url) for c in captures if c.ok and c.url.startswith('https://')}

    for capture in captures:
        summary['blocked_requests'] += len(capture.blocked)
        if capture.blocked:
            logger.info(f"Blocked {len(capture.blocked)} internal requests while capturing {capture.url}")
        if not capture.ok:
            summary['failed'] += 1
            logger.info(f"Screenshot failed for {capture.url}: {capture.error}")
            continue
        if capture.url.startswith('http://') and (capture.host, capture.final_url) in https_pages:
            for name in delete_screenshots(capture.http_id):   # earlier copies of the same page
                _remove(name)
            summary['duplicates'] += 1
            continue
        token = secrets.token_hex(16)
        image_name, thumb_name = f'{token}.jpg', f'{token}_thumb.jpg'
        _write(image_name, capture.image)
        _write(thumb_name, capture.thumbnail)
        changed = store_screenshot(capture, image_name, thumb_name,
                                   change_threshold=CHANGE_THRESHOLD_BITS, keep=KEEP_PER_SERVICE,
                                   delete_file=lambda name: _remove(name))
        summary['captured'] += 1
        if changed:
            summary['changed'].append(capture.host)

    if hosts is None:
        set_setting('last_screenshot_check', utc_now_str())
    logger.info(f"Screenshots: {summary['captured']} captured, {summary['duplicates']} HTTP redirects to an "
                f"HTTPS page already captured, {summary['failed']} failed, "
                f"{len(summary['changed'])} changed, {summary['blocked_requests']} internal requests blocked")
    return summary


def _remove(name: str) -> None:
    try:
        os.remove(os.path.join(SCREENSHOT_DIR, name))
    except OSError:
        pass


def capture_quietly(hosts: List[str]) -> None:
    """Capture right after an asset is scanned. Never raises."""
    try:
        if hosts:
            run_screenshots(hosts)
    except Exception as e:
        logger.warning(f"Screenshot capture after scan failed: {e}")


if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Capture a screenshot (no DB changes)')
    parser.add_argument('url')
    parser.add_argument('--out', default='screenshot.jpg')
    args = parser.parse_args()

    host = urlsplit(args.url).hostname
    result = capture_pages([{'http_id': 0, 'host': host, 'url': args.url,
                             'allowed_ips': RequestFilter().resolve(host)}])[0]
    print(f"ok={result.ok} status={result.status_code} title={result.title!r} error={result.error} blocked={result.blocked}")
    if result.ok:
        with open(args.out, 'wb') as f:
            f.write(result.image)
        print(f"saved {args.out}")
