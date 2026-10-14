"""
Technology detection from an HTTP response, using the fingerprints in
utils/fingerprints.py (Wappalyzer format).

Matches what a single response shows: headers, cookies, meta tags, script
URLs, inline scripts, HTML, visible text and the URL. Fingerprints that need a
running browser (js, dom, xhr) or other lookups (dns, css, robots, certIssuer)
are not evaluated.

Exports:
    - parse_page(url, headers, cookies, html) -> Page
    - detect(page) -> {name: {'version', 'versions', 'confidence', 'categories', 'cpe'}}
"""

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from html.parser import HTMLParser
from typing import Dict, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

MAX_HTML = 1024 * 1024          # bytes of HTML matched (Wappalyzer regexes can be slow on huge pages)
MAX_TEXT = 256 * 1024
MAX_VERSION_LENGTH = 32
STRING_FIELDS = ('html', 'text', 'url', 'scriptSrc', 'scripts')
KEYED_FIELDS = ('headers', 'cookies', 'meta')


@dataclass
class Page:
    url: str
    headers: Dict[str, str] = field(default_factory=dict)     # lower-case names
    cookies: Dict[str, str] = field(default_factory=dict)     # lower-case names
    html: str = ''
    meta: Dict[str, List[str]] = field(default_factory=dict)  # lower-case name/property -> contents
    script_src: List[str] = field(default_factory=list)       # absolute URLs
    inline_scripts: List[str] = field(default_factory=list)
    text: str = ''


class _PageParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.page = Page(url=base_url)
        self._in = None            # 'script' or 'style' while inside one
        self._script = []
        self._text = []
        self._text_len = 0

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or '') for k, v in attrs}
        if tag == 'script':
            if attrs.get('src'):
                self.page.script_src.append(urljoin(self.base_url, attrs['src'].strip()))
            else:
                self._in, self._script = 'script', []
        elif tag == 'style':
            self._in = 'style'
        elif tag == 'meta':
            name = (attrs.get('name') or attrs.get('property') or attrs.get('http-equiv') or '').lower()
            if name:
                self.page.meta.setdefault(name, []).append(attrs.get('content', ''))

    def handle_endtag(self, tag):
        if tag == 'script' and self._in == 'script':
            self.page.inline_scripts.append(''.join(self._script))
        if tag in ('script', 'style'):
            self._in = None

    def handle_data(self, data):
        if self._in == 'script':
            self._script.append(data)
        elif self._in is None and self._text_len < MAX_TEXT and data.strip():
            self._text.append(data)
            self._text_len += len(data)


def parse_page(url: str, headers: Dict[str, str], cookies: Dict[str, str], html: str) -> Page:
    html = (html or '')[:MAX_HTML]
    parser = _PageParser(url)
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:                      # malformed HTML: keep what was parsed
        logger.debug(f"HTML parse stopped for {url}: {e}")
    page = parser.page
    page.html = html
    page.text = ' '.join(parser._text)[:MAX_TEXT]
    page.headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
    page.cookies = {k.lower(): str(v) for k, v in (cookies or {}).items()}
    return page


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

@dataclass
class Pattern:
    regex: Optional[re.Pattern]     # None: the key's presence is enough (e.g. a header with "")
    version: str = ''
    confidence: int = 100


_NAMED_GROUP = re.compile(r'\(\?<(?![=!])')     # JS (?<name>...) -> Python (?P<name>...)


def parse_pattern(value) -> Optional[Pattern]:
    """'regex\\;version:\\1\\;confidence:50' -> Pattern, or None if Python cannot compile it."""
    parts = str(value).split('\\;')
    attrs = {}
    for part in parts[1:]:
        key, _, val = part.partition(':')
        attrs[key.strip()] = val
    try:
        confidence = int(attrs.get('confidence', 100))
    except ValueError:
        confidence = 100
    source = _NAMED_GROUP.sub('(?P<', parts[0])
    if source == '':
        return Pattern(None, attrs.get('version', ''), confidence)
    try:
        return Pattern(re.compile(source, re.IGNORECASE), attrs.get('version', ''), confidence)
    except re.error:
        return None


def resolve_version(template: str, groups: List[Optional[str]]) -> str:
    """Wappalyzer version template: \\1 back-references and \\1?yes:no ternaries."""
    resolved = template
    for index, value in enumerate(groups):
        ternary = re.search(r'\\' + str(index) + r'\?([^:]+):(.*)$', template)
        if ternary:
            resolved = template.replace(ternary.group(0), ternary.group(1) if value else ternary.group(2))
        resolved = resolved.strip().replace('\\' + str(index), value or '')
    return resolved


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@lru_cache(maxsize=2)
def _compile(signature) -> dict:
    """Compiled patterns per technology (rebuilt when the fingerprint data changes)."""
    from utils import fingerprints
    data = fingerprints.load()
    compiled, skipped = {}, 0
    for name, tech in data['technologies'].items():
        entry = {}
        for field_name in STRING_FIELDS:
            patterns = [parse_pattern(p) for p in _as_list(tech.get(field_name))]
            skipped += patterns.count(None)
            if any(patterns):
                entry[field_name] = [p for p in patterns if p]
        for field_name in KEYED_FIELDS:
            keyed = {}
            for key, values in (tech.get(field_name) or {}).items():
                patterns = [parse_pattern(v) for v in _as_list(values)]
                skipped += patterns.count(None)
                if any(patterns):
                    keyed[key.lower()] = [p for p in patterns if p]
            if keyed:
                entry[field_name] = keyed
        if entry:
            compiled[name] = entry
    if skipped:
        logger.debug(f"{skipped} fingerprint patterns use regex syntax Python does not support; skipped")
    return compiled


def _match(pattern: Pattern, subject: str):
    """(matched, version or None)"""
    if pattern.regex is None:
        return True, None
    m = pattern.regex.search(subject)
    if not m:
        return False, None
    if not pattern.version:
        return True, None
    version = resolve_version(pattern.version, [m.group(0)] + list(m.groups()))
    version = version.strip()
    return True, (version if 0 < len(version) <= MAX_VERSION_LENGTH else None)


def _version_key(version: str):
    parts = re.split(r'[.\-]', version)
    return (len(parts), [int(p) if p.isdigit() else -1 for p in parts])


def detect(page: Page) -> Dict[str, dict]:
    """
    Technologies on the page.

    Returns:
        {name: {'version': str | None, 'versions': [str], 'confidence': int (1-100),
                'categories': [str], 'cpe': str | None}}
    """
    from utils import fingerprints
    data = fingerprints.load()
    compiled = _compile(fingerprints._signature())
    subjects = {'html': [page.html], 'text': [page.text], 'url': [page.url], 'scriptSrc': page.script_src,
                'scripts': page.inline_scripts}
    keyed_subjects = {'headers': {k: [v] for k, v in page.headers.items()},
                      'cookies': {k: [v] for k, v in page.cookies.items()}, 'meta': page.meta}

    found: Dict[str, dict] = {}

    def hit(name, confidence, version):
        entry = found.setdefault(name, {'confidence': 0, 'versions': set()})
        entry['confidence'] = min(100, entry['confidence'] + confidence)
        if version:
            entry['versions'].add(version)

    def check(name, pattern, candidates):
        """A pattern counts once; versions are collected from every matching subject."""
        versions = [version for matched, version in (_match(pattern, s) for s in candidates) if matched]
        if versions:
            hit(name, pattern.confidence, None)
            for version in filter(None, versions):
                found[name]['versions'].add(version)

    for name, entry in compiled.items():
        for field_name, patterns in entry.items():
            if field_name in STRING_FIELDS:
                for pattern in patterns:
                    check(name, pattern, subjects[field_name])
            else:
                available = keyed_subjects[field_name]
                for key, key_patterns in patterns.items():
                    if key in available:
                        for pattern in key_patterns:
                            check(name, pattern, available[key])

    technologies = data['technologies']

    # implies (repeated: implied technologies can imply others)
    for _ in range(5):
        added = False
        for name in list(found):
            for implied in _as_list(technologies.get(name, {}).get('implies')):
                implied_pattern = parse_pattern(implied)
                implied_name = str(implied).split('\\;')[0]
                if implied_name in technologies and implied_name not in found:
                    hit(implied_name, implied_pattern.confidence if implied_pattern else 100, None)
                    added = True
        if not added:
            break

    # requires / requiresCategory / excludes
    def categories_of(name):
        return set(technologies.get(name, {}).get('cats', []))

    for _ in range(3):
        present_categories = set().union(*(categories_of(n) for n in found)) if found else set()
        for name in list(found):
            tech = technologies.get(name, {})
            if any(req not in found for req in _as_list(tech.get('requires'))):
                found.pop(name)
            elif tech.get('requiresCategory') is not None and \
                    not (set(_as_list(tech['requiresCategory'])) & (present_categories - categories_of(name))):
                found.pop(name)
    for name in list(found):
        for excluded in _as_list(technologies.get(name, {}).get('excludes')):
            found.pop(excluded, None)

    result = {}
    for name, entry in found.items():
        versions = sorted(entry['versions'], key=_version_key, reverse=True)
        tech = technologies.get(name, {})
        result[name] = {
            'version': versions[0] if versions else None,
            'versions': versions,
            'confidence': entry['confidence'],
            'categories': [data['categories'].get(c, str(c)) for c in tech.get('cats', [])],
            'cpe': tech.get('cpe'),
        }
    return result
