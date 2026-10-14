import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from modules import InitDB
from utils import db_utils, fingerprints, jslibs, techdetect

PAGE = """<html><head>
<meta name="generator" content="Ghost 6.8">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="/assets/app.js"></script>
<script>window.dataLayer = [];</script>
</head><body><p>Welcome</p></body></html>"""


def page(html=PAGE, headers=None, cookies=None, url='https://shop.example.com/'):
    return techdetect.parse_page(url, headers if headers is not None else {'Server': 'nginx/1.22.1'}, cookies or {}, html)


class PatternTests(unittest.TestCase):
    def test_parse(self):
        p = techdetect.parse_pattern('nginx(?:/([\\d.]+))?\\;version:\\1\\;confidence:50')
        self.assertEqual((p.version, p.confidence), ('\\1', 50))
        self.assertTrue(p.regex.search('NGINX/1.2'))                     # case-insensitive
        self.assertIsNone(techdetect.parse_pattern('').regex)            # presence only
        self.assertIsNotNone(techdetect.parse_pattern('(?<ver>[\\d.]+)').regex)   # JS named group
        self.assertIsNone(techdetect.parse_pattern('(unclosed'))

    def test_version_templates(self):
        self.assertEqual(techdetect.resolve_version('\\1', ['x', '2.4.7']), '2.4.7')
        self.assertEqual(techdetect.resolve_version('\\1?5:4', ['x', 'yes']), '5')
        self.assertEqual(techdetect.resolve_version('\\1?5:4', ['x', None]), '4')
        self.assertEqual(techdetect.resolve_version('v\\1.\\2', ['x', '1', '3']), 'v1.3')

    def test_page_parsing(self):
        p = page()
        self.assertEqual(p.script_src, ['https://code.jquery.com/jquery-1.12.4.min.js', 'https://shop.example.com/assets/app.js'])
        self.assertEqual(p.meta['generator'], ['Ghost 6.8'])
        self.assertIn('dataLayer', p.inline_scripts[0])
        self.assertEqual(p.text.strip(), 'Welcome')
        self.assertEqual(p.headers['server'], 'nginx/1.22.1')


class DetectTests(unittest.TestCase):
    def test_real_fingerprints(self):
        found = techdetect.detect(page())
        self.assertEqual(found['Nginx']['version'], '1.22.1')                 # header
        self.assertEqual(found['Ghost']['version'], '6.8')                    # meta
        self.assertEqual(found['jQuery']['version'], '1.12.4')                # script URL
        self.assertIn('Node.js', found)                                      # implied by Ghost
        self.assertIn('Web servers', found['Nginx']['categories'])
        self.assertTrue(found['Nginx']['cpe'].startswith('cpe:2.3:a:f5:nginx'))

    def test_nothing_on_a_blank_page(self):
        self.assertEqual(techdetect.detect(page('<html></html>', headers={})), {})

    def test_rules(self):
        data = {
            'technologies': {
                'Base': {'cats': [1], 'headers': {'X-Base': ''}, 'implies': 'Implied\\;confidence:50',
                         'excludes': 'Excluded'},
                'Implied': {'cats': [2]},
                'Excluded': {'cats': [1], 'headers': {'X-Base': ''}},
                'NeedsBase': {'cats': [3], 'html': 'hello', 'requires': 'Base'},
                'NeedsMissing': {'cats': [3], 'html': 'hello', 'requires': 'Absent'},
                'NeedsCategory': {'cats': [3], 'html': 'hello', 'requiresCategory': 1},
                'Versions': {'cats': [4], 'scriptSrc': ['lib-([\\d.]+)\\.js\\;version:\\1']},
            },
            'categories': {1: 'One', 2: 'Two', 3: 'Three', 4: 'Four'}, 'jsrepository': {}, 'source': 'test'}
        with patch.object(fingerprints, 'load', return_value=data), \
                patch.object(fingerprints, '_signature', return_value=('rules-test',)):
            techdetect._compile.cache_clear()
            found = techdetect.detect(page('<p>hello</p><script src="/lib-1.2.js"></script><script src="/lib-1.10.0.js"></script>',
                                           headers={'X-Base': '1'}))
            techdetect._compile.cache_clear()
        self.assertEqual(sorted(found), ['Base', 'Implied', 'NeedsBase', 'NeedsCategory', 'Versions'])
        self.assertEqual(found['Implied']['confidence'], 50)
        self.assertEqual(found['Versions']['versions'], ['1.10.0', '1.2'])     # most specific first


class RetireTests(unittest.TestCase):
    def test_versions_from_urls_and_content(self):
        self.assertEqual(jslibs.detect_in_url('https://code.jquery.com/jquery-1.12.4.min.js'), {'jquery': '1.12.4'})
        self.assertEqual(jslibs.detect_in_url('https://x/jquery-3.6.0.slim.min.js'), {'jquery': '3.6.0'})
        self.assertEqual(jslibs.detect_in_url('https://cdn/ajax/libs/jquery/3.5.1/jquery.min.js'), {'jquery': '3.5.1'})
        self.assertEqual(jslibs.detect_in_content('/*! jQuery v3.4.1 | (c) JS Foundation */'), {'jquery': '3.4.1'})
        self.assertEqual(jslibs.detect_in_url('https://x/app.js'), {})

    def test_hashes(self):
        content = b'console.log("pinned build")'
        with patch.dict(jslibs._repo()['jquery']['hashes'], {hashlib.sha1(content).hexdigest(): '2.2.4'}):
            self.assertEqual(jslibs.detect_in_content(content)['jquery'], '2.2.4')

    def test_version_comparison(self):
        self.assertTrue(jslibs.is_at_or_above('3.5.0', '3.5.0'))
        self.assertTrue(jslibs.is_at_or_above('1.10.0', '1.9.1'))
        self.assertFalse(jslibs.is_at_or_above('1.9.0b1', '1.9.0'))         # pre-release is below
        self.assertTrue(jslibs.is_at_or_above('1.9.0', '1.9.0b1'))

    def test_vulnerability_ranges(self):
        old = {i for v in jslibs.vulnerabilities('jquery', '1.12.4') for i in v['ids']}
        self.assertTrue({'CVE-2020-11022', 'CVE-2019-11358', 'CVE-2015-9251'} <= old)
        self.assertNotIn('CVE-2011-4969', old)                              # fixed in 1.6.3
        self.assertEqual(jslibs.vulnerabilities('jquery', '3.7.1'), [])
        self.assertEqual(jslibs.vulnerabilities('not-a-library', '1.0'), [])

    def test_name_mapping(self):
        self.assertEqual(jslibs.technology_for_library('jquery'), 'jQuery')
        self.assertEqual(jslibs.library_for_technology('jQuery'), 'jquery')
        self.assertEqual(jslibs.technology_for_library('DOMPurify'), 'DOMPurify')   # kept as is
        self.assertIsNone(jslibs.library_for_technology('Nginx'))

    def test_fetches_unidentified_scripts_through_the_filter(self):
        p = page('<script src="/app.js"></script><script src="http://10.1.2.3/internal.js"></script>'
                 '<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>')
        fetched = []

        def fetch(url):
            fetched.append(url)
            return b'/*! jQuery v1.8.3 */' if url.endswith('/app.js') else None
        with patch.object(jslibs, '_fetch', side_effect=fetch), \
                patch('utils.screenshots.RequestFilter.resolve', side_effect=lambda host: {'93.184.216.34'}
                      if host == 'shop.example.com' else {host}):
            found = jslibs.scan_page(p, allowed_ips=set())
        self.assertEqual(fetched, ['https://shop.example.com/app.js'])      # internal script not fetched,
        self.assertEqual(found, {'jquery': '1.8.3'})                         # identified one not re-fetched


class DataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.live = os.path.join(self.tmp, 'live')
        patcher = patch.object(fingerprints, 'LIVE_DIR', self.live)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(fingerprints._load.cache_clear)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        fingerprints._load.cache_clear()
        bundled = fingerprints._read(fingerprints.BUNDLED_DIR)
        self.bundled = bundled
        self.settings = {}
        for name, value in (('get_setting', lambda key: self.settings.get(key)),
                            ('set_setting', lambda key, value: self.settings.__setitem__(key, value))):
            p = patch(f'utils.db_utils.{name}', side_effect=value)
            p.start()
            self.addCleanup(p.stop)

    def test_bundled_snapshot_is_valid_and_used_without_a_download(self):
        self.assertIsNotNone(self.bundled)
        self.assertEqual(fingerprints.load()['source'], 'bundled')

    def test_refresh_writes_validated_data_and_waits_a_week(self):
        technologies, categories, jsrepository = self.bundled
        with patch.object(fingerprints, 'download', return_value=(technologies, categories, jsrepository)) as download:
            self.assertTrue(fingerprints.refresh()['updated'])
            self.assertEqual(fingerprints.load()['source'], 'downloaded')
            self.assertFalse(fingerprints.refresh()['updated'])            # fresh: not again this week
            self.assertEqual(download.call_count, 1)
            self.settings[fingerprints.UPDATED_KEY] = '2020-01-01 00:00:00'
            self.assertTrue(fingerprints.refresh()['updated'])

    def test_failed_download_keeps_current_data(self):
        with patch.object(fingerprints, 'download', side_effect=fingerprints.FingerprintError('HTTP 502')):
            result = fingerprints.refresh()
        self.assertEqual((result['updated'], result['error']), (False, 'HTTP 502'))
        self.assertEqual(fingerprints.load()['source'], 'bundled')

    def test_broken_data_is_rejected(self):
        with self.assertRaises(fingerprints.FingerprintError):
            fingerprints.validate({'Only': {}}, {'1': {}}, {})
        os.makedirs(self.live)
        for name in fingerprints.FILES:
            open(os.path.join(self.live, name), 'w').write('{}')            # a truncated download
        fingerprints._load.cache_clear()
        self.assertEqual(fingerprints.load()['source'], 'bundled')


class ScannerTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def test_scan_uses_retirejs_for_js_libraries_and_cpe_for_the_rest(self):
        from modules import Wappalyzer
        scanner = Wappalyzer.WappalyzerScanner(enable_cve=True, cvss_min=5.0, cve_delay=0)
        nvd_scores = {'CVE-2020-11022': {'cvss': 6.9, 'description': 'XSS in htmlPrefilter'}}
        with patch.object(scanner, 'fetch_page', return_value=page()), \
                patch.object(scanner, 'scan_js_libraries', return_value={}), \
                patch.object(Wappalyzer, 'find_cve', return_value={'ok': True, 'cves': [
                    {'cve_id': 'CVE-2021-23017', 'cvss': 7.7, 'description': 'resolver'}]}) as find_cve, \
                patch.object(Wappalyzer, 'lookup_cve_scores', return_value=nvd_scores):
            result = scanner.scan_target('shop.example.com', 443, is_https=1)

        self.assertTrue(result['success'])
        self.assertNotIn('jQuery', [c.args[0] for c in find_cve.call_args_list])     # no CPE lookup for jQuery
        self.assertIn('Nginx', [c.args[0] for c in find_cve.call_args_list])
        conn = db_utils.get_db_connection()
        rows = {r['cve_id']: (r['cve_score'], r['match_method'], r['description'])
                for r in conn.execute('SELECT cve_id, cve_score, match_method, description FROM vulnerabilities')}
        techs = {r[0]: r[1] for r in conn.execute('SELECT tech_name, tech_version FROM technologies')}
        conn.close()
        self.assertEqual(techs['jQuery'], '1.12.4')
        self.assertEqual(rows['CVE-2020-11022'], (6.9, 'retirejs', 'XSS in htmlPrefilter'))   # NVD score
        self.assertEqual(rows['CVE-2019-11358'][:2], (5.0, 'retirejs'))     # no NVD data: Retire.js severity
        self.assertEqual(rows['CVE-2021-23017'][1], 'cpe')

    def test_library_found_only_by_retirejs_is_added(self):
        from modules import Wappalyzer
        scanner = Wappalyzer.WappalyzerScanner(enable_cve=False)
        with patch.object(scanner, 'fetch_page', return_value=page('<html></html>', headers={})), \
                patch.object(scanner, 'scan_js_libraries', return_value={'lodash': '4.17.4'}):
            result = scanner.scan_target('shop.example.com', 443, is_https=1)
        self.assertEqual([(t['name'], t['version']) for t in result['technologies']], [('Lodash', '4.17.4')])


class RenameMigrationTests(ScannerTests):
    def test_old_names_are_renamed(self):
        conn = db_utils.get_db_connection()
        conn.executescript("""
            INSERT INTO http_services (http_id, host, port_num, is_https) VALUES (1, 'a.example.com', 80, 0), (2, 'b.example.com', 80, 0);
            INSERT INTO technologies (http_id, tech_name, tech_version) VALUES
                (1, 'Apache', '2.4.7'), (2, 'Apache', '2.4.7'), (2, 'Apache HTTP Server', '2.4.7');
        """)
        conn.commit()
        conn.close()
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        conn = db_utils.get_db_connection()
        rows = sorted((r[0], r[1]) for r in conn.execute('SELECT http_id, tech_name FROM technologies'))
        conn.close()
        self.assertEqual(rows, [(1, 'Apache HTTP Server'), (2, 'Apache'), (2, 'Apache HTTP Server')])


if __name__ == '__main__':
    unittest.main()
