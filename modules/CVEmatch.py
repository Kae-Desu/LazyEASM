"""
Module: CVEmatch.py
Purpose: CVE vulnerability matching for detected technologies
Flow:
    1. Map the Wappalyzer technology name to its CPE (vendor:product)
    2. Query the NVD API with a versioned CPE match string
    3. Keep only CVEs whose vulnerable configuration covers that exact version
    4. Return structured CVE data plus an 'ok' flag so callers can tell
       "no CVEs" apart from "lookup failed"

Technologies without a CPE in the Wappalyzer data are not matched. Keyword
search was removed because it matched CVEs by name only and produced many
false positives.
"""

import os
import re
import sys
import json
import time
import logging
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from utils.config import get_env

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000
NVD_RETRY_DELAY = 6.0  # NVD allows 5 requests / 30s without an API key

# NVD renamed some products; Wappalyzer still uses the old CPE.
CPE_ALIASES = {
    ('nginx', 'nginx'): [('f5', 'nginx')],
    ('microsoft', 'internet_information_server'): [('microsoft', 'internet_information_services')],
}


class CVELookupError(Exception):
    """NVD lookup failed (network, rate limit, bad response)."""


@lru_cache(maxsize=1)
def _load_wappalyzer_cpes() -> Dict[str, Tuple[str, str, str]]:
    """Map Wappalyzer technology name -> (part, vendor, product)."""
    try:
        import Wappalyzer
    except ImportError:
        return {}

    path = os.path.join(os.path.dirname(Wappalyzer.__file__), 'data', 'technologies.json')
    try:
        with open(path, encoding='utf8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}

    cpes = {}
    for name, tech in data.get('technologies', data).items():
        parsed = parse_cpe(tech.get('cpe') or '')
        if parsed:
            cpes[name.lower()] = parsed
    return cpes


def parse_cpe(cpe: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse a CPE 2.2 URI or CPE 2.3 string into (part, vendor, product).

    Examples:
        'cpe:/a:nginx:nginx' -> ('a', 'nginx', 'nginx')
        'cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*' -> ('a', 'f5', 'nginx')
    """
    if cpe.startswith('cpe:2.3:'):
        fields = cpe.split(':')[2:5]
    elif cpe.startswith('cpe:/'):
        fields = cpe[len('cpe:/'):].split(':')[:3]
    else:
        return None
    if len(fields) != 3 or not all(fields):
        return None
    return fields[0], fields[1].lower(), fields[2].lower()


def get_cpe_for_technology(tech_name: str) -> Optional[Tuple[str, str, str]]:
    """Return (part, vendor, product) for a Wappalyzer technology name, or None."""
    return _load_wappalyzer_cpes().get((tech_name or '').lower())


def parse_version(version: str) -> Tuple[int, ...]:
    """
    Turn a version string into a comparable tuple of ints.

    '1.20.1' -> (1, 20, 1); '2.4.7-ubuntu' -> (2, 4, 7)
    """
    match = re.match(r'\d+(?:\.\d+)*', (version or '').strip().lstrip('vV'))
    if not match:
        return ()
    return tuple(int(p) for p in match.group(0).split('.'))


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def version_matches(version: str, cpe_match: dict) -> bool:
    """
    Check whether a version is covered by one NVD cpeMatch entry.

    Handles an exact version in the criteria string and the
    versionStart/End Including/Excluding range fields.
    """
    ours = parse_version(version)
    if not ours:
        return False

    criteria_version = cpe_match.get('criteria', '').split(':')[5:6]
    criteria_version = criteria_version[0] if criteria_version else '*'

    if criteria_version == '-':
        # "not applicable" - no version information to match against
        return False
    if criteria_version != '*':
        return _cmp(ours, parse_version(criteria_version)) == 0

    bounds = {
        'versionStartIncluding': lambda c: c >= 0,
        'versionStartExcluding': lambda c: c > 0,
        'versionEndIncluding': lambda c: c <= 0,
        'versionEndExcluding': lambda c: c < 0,
    }
    for key, accept in bounds.items():
        if key in cpe_match:
            bound = parse_version(cpe_match[key])
            if not bound or not accept(_cmp(ours, bound)):
                return False

    # '*' with no range means NVD lists every version as affected
    return True


def cve_affects(cve: dict, products: List[Tuple[str, str]], version: str) -> bool:
    """True if any vulnerable cpeMatch for one of the products covers the version."""
    for config in cve.get('configurations', []):
        for node in config.get('nodes', []):
            if node.get('negate'):
                continue
            for cpe_match in node.get('cpeMatch', []):
                if not cpe_match.get('vulnerable'):
                    continue
                parsed = parse_cpe(cpe_match.get('criteria', ''))
                if not parsed or (parsed[1], parsed[2]) not in products:
                    continue
                if version_matches(version, cpe_match):
                    return True
    return False


def get_cvss_score(cve: dict) -> float:
    """Extract the best available CVSS base score from an NVD CVE dict."""
    metrics = cve.get('metrics', {})
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2'):
        entries = metrics.get(key) or []
        primary = [m for m in entries if m.get('type') == 'Primary'] or entries
        if primary:
            try:
                return float(primary[0]['cvssData']['baseScore'])
            except (KeyError, TypeError, ValueError):
                continue
    return 0.0


def _get_description(cve: dict) -> str:
    for desc in cve.get('descriptions', []):
        if desc.get('lang') == 'en':
            return desc.get('value') or 'No description available'
    return 'No description available'


def fetch_nvd(match_string: str) -> List[dict]:
    """
    Fetch all CVEs for a CPE match string from NVD.

    Raises:
        CVELookupError: on network errors, rate limiting, or bad responses
    """
    headers = {}
    api_key = get_env('NVD_API_KEY', '')
    if api_key:
        headers['apiKey'] = api_key

    cves = []
    start = 0
    while True:
        params = {
            'virtualMatchString': match_string,
            'resultsPerPage': NVD_PAGE_SIZE,
            'startIndex': start,
            'noRejected': '',
        }
        response = None
        for attempt in range(2):
            try:
                response = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
            except requests.RequestException as e:
                raise CVELookupError(f"NVD request failed: {e}") from e
            if response.status_code in (403, 429, 503) and attempt == 0:
                time.sleep(NVD_RETRY_DELAY)
                continue
            break

        if response.status_code != 200:
            raise CVELookupError(f"NVD returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as e:
            raise CVELookupError("NVD returned invalid JSON") from e

        cves.extend(item['cve'] for item in data.get('vulnerabilities', []) if 'cve' in item)
        start += data.get('resultsPerPage', 0) or NVD_PAGE_SIZE
        if start >= data.get('totalResults', 0):
            return cves


def find_cve(tech_name: str, version: str, min_cvss: float = 0.0, use_cache: bool = True) -> dict:
    """
    Find CVEs affecting a specific technology version.

    Args:
        tech_name: Wappalyzer technology name (e.g., 'Nginx')
        version: Detected version (e.g., '1.20.1')
        min_cvss: Minimum CVSS score to include
        use_cache: Use the cve_cache table (24h TTL)

    Returns:
        Dict: {
            'technology': 'Nginx 1.20.1',
            'ok': bool,          # False if the NVD lookup failed
            'method': 'cpe' | 'no_cpe' | 'no_version',
            'error': str | None,
            'cves': [{'cve_id', 'cvss', 'description', 'tech_name'}, ...]
        }
    """
    result = {
        'technology': f"{tech_name} {version or ''}".strip(),
        'ok': True,
        'method': 'cpe',
        'error': None,
        'cves': [],
    }

    if not version or not parse_version(version):
        result['method'] = 'no_version'
        return result

    cpe = get_cpe_for_technology(tech_name)
    if not cpe:
        result['method'] = 'no_cpe'
        return result

    part, vendor, product = cpe
    products = [(vendor, product)] + CPE_ALIASES.get((vendor, product), [])

    matches = {}
    for v, p in products:
        match_string = f"cpe:2.3:{part}:{v}:{p}:{version}"

        cached = None
        if use_cache:
            from utils.db_utils import get_cached_cves
            cached = get_cached_cves(match_string)

        if cached is None:
            try:
                raw = fetch_nvd(match_string)
            except CVELookupError as e:
                logger.warning(f"CVE lookup failed for {match_string}: {e}")
                result['ok'] = False
                result['error'] = str(e)
                result['cves'] = []
                return result

            cached = [
                {'cve_id': cve['id'], 'cvss': get_cvss_score(cve), 'description': _get_description(cve)}
                for cve in raw
                if cve.get('id') and cve_affects(cve, products, version)
            ]
            if use_cache:
                from utils.db_utils import set_cached_cves
                set_cached_cves(match_string, cached)

        for cve in cached:
            matches.setdefault(cve['cve_id'], cve)

    result['cves'] = sorted(
        (
            {**cve, 'tech_name': tech_name}
            for cve in matches.values()
            if cve['cvss'] >= min_cvss
        ),
        key=lambda c: c['cvss'],
        reverse=True,
    )
    return result


if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Look up CVEs for a technology version')
    parser.add_argument('tech_name', help="Wappalyzer technology name, e.g. 'Nginx'")
    parser.add_argument('version', help="Version, e.g. '1.20.1'")
    parser.add_argument('--min-cvss', type=float, default=0.0)
    args = parser.parse_args()

    found = find_cve(args.tech_name, args.version, min_cvss=args.min_cvss, use_cache=False)
    print(f"{found['technology']}: method={found['method']} ok={found['ok']} error={found['error']}")
    for cve in found['cves']:
        print(f"  {cve['cve_id']} (CVSS {cve['cvss']}) {cve['description'][:90]}")
