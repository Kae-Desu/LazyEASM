"""
Fingerprint data for technology detection and JavaScript library vulnerabilities.

    - Technologies: enthec/webappanalyzer, the community-maintained
      continuation of the Wappalyzer fingerprints (GPL-3.0)
    - JavaScript library vulnerabilities: Retire.js jsrepository (Apache-2.0)

A snapshot ships in data/fingerprints/. The maintenance check downloads a
fresh copy weekly into db/fingerprints/ (validated, written atomically), so
detection keeps up without upgrading LazyEASM; the bundled snapshot is used
when no valid download exists (offline installs, failed refresh).

    python -m utils.fingerprints --refresh          download now
    python -m utils.fingerprints --bundle DIR       write a bundled snapshot
"""

import json
import logging
import os
from datetime import timedelta
from functools import lru_cache
from typing import Dict, Optional, Tuple

import requests

from utils.timeutil import parse_utc, utc_now, utc_now_str

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLED_DIR = os.path.join(PROJECT_ROOT, 'data', 'fingerprints')
LIVE_DIR = os.path.join(PROJECT_ROOT, 'db', 'fingerprints')

TECH_BASE_URL = 'https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/'
TECH_FILES = ['_'] + [chr(c) for c in range(ord('a'), ord('z') + 1)]
RETIRE_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json'

FILES = ('technologies.json', 'categories.json', 'jsrepository.json')
# Fields the matcher uses; the rest (descriptions, icons, pricing...) is dropped
KEEP_FIELDS = ('cats', 'cpe', 'headers', 'cookies', 'meta', 'scriptSrc', 'scripts', 'html', 'url', 'text',
               'implies', 'requires', 'requiresCategory', 'excludes')
MIN_TECHNOLOGIES = 3000      # a download with fewer is treated as broken
MIN_JS_LIBRARIES = 40
REFRESH_AFTER = timedelta(days=7)
UPDATED_KEY = 'fingerprints_updated_at'
HTTP_TIMEOUT = 60

# Technologies renamed since the fingerprints python-Wappalyzer bundled (used
# by earlier versions); stored technologies are renamed once (modules/InitDB.py)
RENAMED_TECHNOLOGIES = {
    'Amazon Cloudfront': 'Amazon CloudFront', 'Apache': 'Apache HTTP Server', 'Bigcommerce': 'BigCommerce',
    'Bolt': 'Bolt CMS', 'Concrete5': 'Concrete CMS', 'Crownpeak': 'CrownPeak', 'Datadome': 'DataDome',
    'EPages': 'ePages', 'EPiServer': 'Optimizely Content Management', 'Fingerprintjs': 'FingerprintJS',
    'HERE': 'Here', 'Iubenda': 'iubenda', 'Lotus Domino': 'HCL Domino', 'Onshop': 'OnShop',
    'SilverStripe': 'Silverstripe', 'Webdev': 'WEBDEV', 'Webzi': 'WebZi', 'animate.css': 'Animate.css',
    'borderfree': 'Borderfree', 'three.js': 'Three.js', 'webpack': 'Webpack',
}


class FingerprintError(Exception):
    """Fingerprint data could not be downloaded or failed validation."""


def _strip(technologies: dict) -> dict:
    return {name: {k: t[k] for k in KEEP_FIELDS if k in t} for name, t in technologies.items()}


def validate(technologies: dict, categories: dict, jsrepository: dict) -> None:
    if not isinstance(technologies, dict) or len(technologies) < MIN_TECHNOLOGIES:
        raise FingerprintError(f'only {len(technologies or {})} technologies')
    if not isinstance(categories, dict) or not categories:
        raise FingerprintError('no categories')
    if not isinstance(jsrepository, dict) or len(jsrepository) < MIN_JS_LIBRARIES:
        raise FingerprintError(f'only {len(jsrepository or {})} JavaScript libraries')
    if not any('cpe' in t for t in technologies.values()) or not all('vulnerabilities' in lib for lib in jsrepository.values()):
        raise FingerprintError('unexpected format')


def _read(directory: str) -> Optional[Tuple[dict, dict, dict]]:
    try:
        data = []
        for name in FILES:
            with open(os.path.join(directory, name), encoding='utf8') as f:
                data.append(json.load(f))
        validate(*data)
        return tuple(data)
    except (OSError, ValueError, FingerprintError):
        return None


def _signature() -> tuple:
    """Changes when the downloaded files change, so other processes pick up a refresh."""
    stamps = []
    for name in FILES:
        try:
            stamps.append(os.path.getmtime(os.path.join(LIVE_DIR, name)))
        except OSError:
            stamps.append(None)
    return tuple(stamps)


@lru_cache(maxsize=2)
def _load(signature: tuple) -> dict:
    data = _read(LIVE_DIR)
    source = 'downloaded'
    if data is None:
        data, source = _read(BUNDLED_DIR), 'bundled'
    if data is None:
        raise FingerprintError(f'no valid fingerprint data in {LIVE_DIR} or {BUNDLED_DIR}')
    technologies, categories, jsrepository = data
    return {'technologies': technologies, 'categories': {int(k): v.get('name', k) for k, v in categories.items()},
            'jsrepository': jsrepository, 'source': source}


def load() -> dict:
    """{'technologies', 'categories' {id: name}, 'jsrepository', 'source' ('downloaded' | 'bundled')}"""
    return _load(_signature())


def cpe_map() -> Dict[str, str]:
    """Technology name -> CPE string, for CVE matching."""
    return {name: t['cpe'] for name, t in load()['technologies'].items() if t.get('cpe')}


def download() -> Tuple[dict, dict, dict]:
    """Fetch and validate the current fingerprints. Raises FingerprintError."""
    session = requests.Session()
    session.headers['User-Agent'] = 'LazyEASM fingerprint update'

    def get_json(url):
        try:
            response = session.get(url, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as e:
            raise FingerprintError(f'{url}: {e}') from e

    technologies = {}
    for letter in TECH_FILES:
        technologies.update(get_json(f'{TECH_BASE_URL}technologies/{letter}.json'))
    categories = get_json(f'{TECH_BASE_URL}categories.json')
    jsrepository = get_json(RETIRE_URL)
    technologies = _strip(technologies)
    validate(technologies, categories, jsrepository)
    return technologies, categories, jsrepository


def _write(directory: str, technologies: dict, categories: dict, jsrepository: dict) -> None:
    os.makedirs(directory, exist_ok=True)
    for name, data in zip(FILES, (technologies, categories, jsrepository)):
        tmp = os.path.join(directory, name + '.tmp')
        with open(tmp, 'w', encoding='utf8') as f:
            json.dump(data, f, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
        os.replace(tmp, os.path.join(directory, name))


def refresh(force: bool = False) -> dict:
    """
    Download fresh fingerprints when the last download is older than a week.
    A failed download keeps the data in use.

    Returns:
        {'updated': bool, 'technologies': int, 'js_libraries': int, 'error': str | None}
    """
    from utils.db_utils import get_setting, set_setting

    last = get_setting(UPDATED_KEY)
    if not force and last and _read(LIVE_DIR) is not None:
        try:
            if utc_now() - parse_utc(last) < REFRESH_AFTER:
                return {'updated': False, 'technologies': 0, 'js_libraries': 0, 'error': None}
        except ValueError:
            pass
    try:
        technologies, categories, jsrepository = download()
    except FingerprintError as e:
        logger.warning(f"Fingerprint update failed, keeping the current data: {e}")
        return {'updated': False, 'technologies': 0, 'js_libraries': 0, 'error': str(e)}
    _write(LIVE_DIR, technologies, categories, jsrepository)
    set_setting(UPDATED_KEY, utc_now_str())
    _load.cache_clear()
    logger.info(f"Fingerprints updated: {len(technologies)} technologies, {len(jsrepository)} JavaScript libraries")
    return {'updated': True, 'technologies': len(technologies), 'js_libraries': len(jsrepository), 'error': None}


def write_bundle(directory: str = BUNDLED_DIR) -> dict:
    """Download the current data into the bundled snapshot (release task)."""
    technologies, categories, jsrepository = download()
    _write(directory, technologies, categories, jsrepository)
    return {'technologies': len(technologies), 'js_libraries': len(jsrepository)}


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Fingerprint data')
    parser.add_argument('--refresh', action='store_true', help='download into db/fingerprints now')
    parser.add_argument('--bundle', metavar='DIR', help='write a snapshot (e.g. data/fingerprints)')
    args = parser.parse_args()
    if args.bundle:
        print(write_bundle(args.bundle))
    elif args.refresh:
        print(refresh(force=True))
    else:
        parser.print_help()
