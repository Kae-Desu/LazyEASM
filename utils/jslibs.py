"""
JavaScript libraries and their known vulnerabilities (Retire.js repository).

Libraries are found the way Retire.js finds them: script URLs and file names,
then the content of inline scripts and of a few script files the page loads
(fetched through the same internal-address filter as screenshots), and SHA-1
hashes of that content. Vulnerabilities come with exact affected version
ranges, which is more precise for JavaScript libraries than CPE matching.

Exports:
    - scan_page(page, allowed_ips) -> {library: version}
    - vulnerabilities(library, version) -> [vulnerability dicts]
    - library_for_technology(name) / technology_for_library(library)
"""

import hashlib
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import Dict, Iterable, List, Optional

import requests

logger = logging.getLogger(__name__)

VERSION_PATTERN = r'[0-9][0-9.a-z_\\\-]+'     # Retire.js's §§version§§
SKIP_LIBRARIES = {'retire-example', 'dont check'}
MAX_SCRIPTS = 8
MAX_SCRIPT_BYTES = 1536 * 1024
FETCH_TIMEOUT = 10
USER_AGENT = 'Mozilla/5.0 (compatible; LazyEASM)'
# Score used when the CVSS of a Retire.js finding cannot be looked up
SEVERITY_SCORES = {'critical': 9.0, 'high': 7.5, 'medium': 5.0, 'low': 3.0}


def _compile_patterns(patterns: Iterable[str]) -> List[re.Pattern]:
    compiled = []
    for pattern in patterns or []:
        try:
            compiled.append(re.compile(pattern.replace('§§version§§', VERSION_PATTERN)))
        except re.error:
            continue
    return compiled


@lru_cache(maxsize=2)
def _repository(signature) -> Dict[str, dict]:
    from utils import fingerprints
    repo = {}
    for name, lib in fingerprints.load()['jsrepository'].items():
        if name in SKIP_LIBRARIES:
            continue
        extractors = lib.get('extractors', {})
        repo[name] = {
            'uri': _compile_patterns(extractors.get('uri')),
            'filename': _compile_patterns(extractors.get('filename')),
            'filecontent': _compile_patterns(extractors.get('filecontent')),
            'hashes': extractors.get('hashes') or {},
            'vulnerabilities': lib.get('vulnerabilities', []),
            'aliases': [name] + list(lib.get('bowername') or []) + ([lib['npmname']] if lib.get('npmname') else []),
        }
    return repo


def _repo() -> Dict[str, dict]:
    from utils import fingerprints
    return _repository(fingerprints._signature())


def _clean_version(version: str) -> str:
    """The loose version pattern also takes file suffixes: '1.12.4.min' -> '1.12.4'."""
    return re.sub(r'([.\-]min|[.\-]slim|[.\-]js)+$', '', version).rstrip('.-_')


def _first_version(patterns: List[re.Pattern], subject: str) -> Optional[str]:
    for pattern in patterns:
        m = pattern.search(subject)
        if m and m.groups() and m.group(1):
            return _clean_version(m.group(1)) or None
    return None


def detect_in_url(url: str) -> Dict[str, str]:
    filename = url.split('?')[0].split('#')[0].rsplit('/', 1)[-1]
    found = {}
    for name, lib in _repo().items():
        version = _first_version(lib['uri'], url) or _first_version(lib['filename'], filename)
        if version:
            found[name] = version
    return found


def detect_in_content(content) -> Dict[str, str]:
    if isinstance(content, bytes):
        digest = hashlib.sha1(content).hexdigest()
        content = content.decode('utf8', errors='replace')
    else:
        digest = hashlib.sha1(content.encode('utf8')).hexdigest()
    found = {}
    for name, lib in _repo().items():
        version = lib['hashes'].get(digest) or _first_version(lib['filecontent'], content)
        if version:
            found[name] = version
    return found


def _fetch(url: str) -> Optional[bytes]:
    try:
        with requests.get(url, timeout=FETCH_TIMEOUT, stream=True, verify=False, allow_redirects=False,
                          headers={'User-Agent': USER_AGENT}) as response:
            if response.status_code != 200:
                return None
            return response.raw.read(MAX_SCRIPT_BYTES, decode_content=True)
    except (requests.RequestException, OSError):
        return None


def scan_page(page, allowed_ips: Iterable[str] = ()) -> Dict[str, str]:
    """
    JavaScript libraries on a page (utils.techdetect.Page) -> {library: version}.

    Script files not identified by URL are fetched (up to MAX_SCRIPTS) when the
    request filter allows them: public addresses, or the asset's own IPs.
    """
    import warnings
    from urllib3.exceptions import InsecureRequestWarning
    from utils.screenshots import RequestFilter

    found = {}
    unidentified = []
    for src in page.script_src:
        libs = detect_in_url(src)
        found.update(libs)
        if not libs and src.startswith(('http://', 'https://')):
            unidentified.append(src)
    for script in page.inline_scripts:
        found.update(detect_in_content(script))

    request_filter = RequestFilter(set(allowed_ips))
    to_fetch = [src for src in dict.fromkeys(unidentified) if request_filter.allows(src)][:MAX_SCRIPTS]
    if to_fetch:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            with ThreadPoolExecutor(max_workers=4) as pool:
                for content in pool.map(_fetch, to_fetch):
                    if content:
                        found.update(detect_in_content(content))
    return found


def _comparable(part: str):
    return int(part) if part.isdigit() else part


def is_at_or_above(version: str, other: str) -> bool:
    """Retire.js version comparison (numbers above text parts such as 'b1', 'rc')."""
    v1, v2 = re.split(r'[.\-]', version), re.split(r'[.\-]', other)
    for i in range(max(len(v1), len(v2))):
        a = _comparable(v1[i]) if i < len(v1) and v1[i] else 0
        b = _comparable(v2[i]) if i < len(v2) and v2[i] else 0
        if type(a) is not type(b):
            return isinstance(a, int)
        if a > b:
            return True
        if a < b:
            return False
    return True


def vulnerabilities(library: str, version: str) -> List[dict]:
    """
    Known vulnerabilities of this library version.

    Returns:
        [{'ids': [CVE-... or GHSA-...], 'severity', 'summary', 'info': [url]}]
    """
    lib = _repo().get(library)
    if not lib or not version:
        return []
    result = []
    for vuln in lib['vulnerabilities']:
        below, at_or_above = vuln.get('below'), vuln.get('atOrAbove')
        if below and is_at_or_above(version, below):
            continue
        if at_or_above and not is_at_or_above(version, at_or_above):
            continue
        identifiers = vuln.get('identifiers', {})
        ids = list(identifiers.get('CVE') or []) or ([identifiers['githubID']] if identifiers.get('githubID') else [])
        if not ids:
            continue
        result.append({'ids': ids, 'severity': (vuln.get('severity') or 'medium').lower(),
                       'summary': identifiers.get('summary') or '', 'info': vuln.get('info') or []})
    return result


def _normalize(name: str) -> str:
    name = name.lower()
    name = re.sub(r'^@[^/]+/', '', name) if name.startswith('@angular') is False else name
    return re.sub(r'[^a-z0-9]', '', re.sub(r'\.?js$', '', name))


@lru_cache(maxsize=2)
def _name_maps(signature) -> tuple:
    from utils import fingerprints
    techs = {}
    for tech in fingerprints.load()['technologies']:
        techs.setdefault(_normalize(tech), tech)
    lib_to_tech, tech_to_lib = {}, {}
    special = {'@angular/core': 'Angular', 'angularjs': 'AngularJS', 'react-dom': 'React', 'tinyMCE': 'TinyMCE'}
    for name, lib in _repository(signature).items():
        tech = special.get(name) if special.get(name) in fingerprints.load()['technologies'] else None
        for alias in lib['aliases']:
            tech = tech or techs.get(_normalize(alias))
        if tech:
            lib_to_tech[name] = tech
            tech_to_lib.setdefault(tech, name)
    return lib_to_tech, tech_to_lib


def technology_for_library(library: str) -> str:
    """The fingerprint technology name for a Retire.js library (or the library name)."""
    from utils import fingerprints
    return _name_maps(fingerprints._signature())[0].get(library, library)


def library_for_technology(technology: str) -> Optional[str]:
    """The Retire.js library for a detected technology, if Retire.js tracks it."""
    from utils import fingerprints
    return _name_maps(fingerprints._signature())[1].get(technology)
