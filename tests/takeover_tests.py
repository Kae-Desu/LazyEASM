import contextlib
import io
import os
import re
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import dns.exception
import dns.resolver

from modules import InitDB
from utils import db_utils, takeover_checker as tc


class FakeResolver:
    """CNAME map: name -> target, name -> exception class, or missing (NoAnswer)."""

    def __init__(self, records):
        self.records = records

    def resolve(self, name, rtype):
        assert rtype == 'CNAME'
        value = self.records.get(name)
        if value is None:
            raise dns.resolver.NoAnswer()
        if isinstance(value, type) and issubclass(value, Exception):
            raise value()
        return [SimpleNamespace(target=value + '.')]


AZURE = tc.Service('Microsoft Azure', ['azurewebsites.net'], nxdomain=True)
S3 = tc.Service('AWS/S3', ['s3.amazonaws.com'], fingerprint=re.compile('The specified bucket does not exist'))
HELPRACE = tc.Service('Helprace', ['helprace.com'], http_status=301)
SERVICES = [AZURE, S3, HELPRACE]


class LoadServicesTests(unittest.TestCase):
    def test_bundled_fingerprints(self):
        services = {s.name: s for s in tc.load_services()}
        self.assertTrue(services['Microsoft Azure'].nxdomain)
        self.assertTrue(services['AWS/S3'].fingerprint.search('The specified bucket does not exist'))
        self.assertEqual(services['Helprace'].http_status, 301)
        # Pipe-escaped upstream regex is usable
        self.assertTrue(services['Ghost'].fingerprint.search('Failed to resolve DNS path for this host'))
        # Services without a CNAME pattern are excluded; so are non-vulnerable ones
        self.assertNotIn('Pantheon', services)
        self.assertNotIn('Github', services)
        for service in services.values():
            self.assertTrue(service.cname_suffixes)
            self.assertFalse(any(re.fullmatch(r'[\d.]+', c) for c in service.cname_suffixes))

    def test_suffix_matching_respects_label_boundary(self):
        self.assertTrue(AZURE.matches('app.azurewebsites.net'))
        self.assertTrue(AZURE.matches('azurewebsites.net'))
        self.assertFalse(AZURE.matches('evilazurewebsites.net'))


class ResolveChainTests(unittest.TestCase):
    def test_follows_chain_and_detects_missing_target(self):
        r = FakeResolver({'a.example.com': 'b.example.net', 'b.example.net': 'gone.azurewebsites.net',
                          'gone.azurewebsites.net': dns.resolver.NXDOMAIN})
        self.assertEqual(tc.resolve_cname_chain('a.example.com', r),
                         (['b.example.net', 'gone.azurewebsites.net'], True))

    def test_existing_target(self):
        r = FakeResolver({'a.example.com': 'live.example.net'})
        self.assertEqual(tc.resolve_cname_chain('a.example.com', r), (['live.example.net'], False))

    def test_missing_host_is_not_dangling(self):
        r = FakeResolver({'a.example.com': dns.resolver.NXDOMAIN})
        self.assertEqual(tc.resolve_cname_chain('a.example.com', r), ([], False))

    def test_timeout_raises(self):
        r = FakeResolver({'a.example.com': dns.exception.Timeout})
        with self.assertRaises(tc.DNSLookupError):
            tc.resolve_cname_chain('a.example.com', r)

    def test_cname_loop_stops(self):
        r = FakeResolver({'a.example.com': 'b.example.com', 'b.example.com': 'a.example.com'})
        self.assertEqual(tc.resolve_cname_chain('a.example.com', r), (['b.example.com'], False))


class CheckHostTests(unittest.TestCase):
    def check(self, records, fetched=None):
        with patch.object(tc, '_fetch', return_value=fetched) as fetch:
            result = tc.check_host('shop.example.com', SERVICES, FakeResolver(records))
        return result, fetch

    def test_nxdomain_service_with_missing_target(self):
        result, fetch = self.check({'shop.example.com': 'old.azurewebsites.net',
                                    'old.azurewebsites.net': dns.resolver.NXDOMAIN})
        self.assertTrue(result.conclusive)
        self.assertEqual([(f['finding_type'], f['severity']) for f in result.findings], [(tc.TAKEOVER, 'high')])
        self.assertEqual(result.findings[0]['evidence']['service'], 'Microsoft Azure')
        fetch.assert_not_called()

    def test_nxdomain_service_with_existing_target(self):
        result, _ = self.check({'shop.example.com': 'live.azurewebsites.net'})
        self.assertTrue(result.conclusive)
        self.assertEqual(result.findings, [])

    def test_unknown_service_with_missing_target_is_dangling(self):
        result, _ = self.check({'shop.example.com': 'old.unknown-cdn.net',
                                'old.unknown-cdn.net': dns.resolver.NXDOMAIN})
        self.assertEqual([(f['finding_type'], f['severity']) for f in result.findings], [(tc.DANGLING, 'medium')])

    def test_http_fingerprint_match(self):
        result, fetch = self.check({'shop.example.com': 'bucket.s3.amazonaws.com'},
                                   fetched=(404, '<Error>The specified bucket does not exist</Error>', 'https://shop.example.com/'))
        self.assertEqual(result.findings[0]['finding_type'], tc.TAKEOVER)
        self.assertEqual(result.findings[0]['evidence']['signal'], 'The specified bucket does not exist')
        fetch.assert_called_once_with('shop.example.com', allow_redirects=True)

    def test_http_fingerprint_no_match(self):
        result, _ = self.check({'shop.example.com': 'bucket.s3.amazonaws.com'},
                               fetched=(200, '<html>shop</html>', 'https://shop.example.com/'))
        self.assertTrue(result.conclusive)
        self.assertEqual(result.findings, [])

    def test_http_status_fingerprint_does_not_follow_redirects(self):
        result, fetch = self.check({'shop.example.com': 'x.helprace.com'},
                                   fetched=(301, '', 'https://shop.example.com/'))
        self.assertEqual(result.findings[0]['evidence']['service'], 'Helprace')
        fetch.assert_called_once_with('shop.example.com', allow_redirects=False)

    def test_unreachable_http_is_inconclusive(self):
        result, _ = self.check({'shop.example.com': 'bucket.s3.amazonaws.com'}, fetched=None)
        self.assertFalse(result.conclusive)

    def test_dns_failure_is_inconclusive(self):
        result, _ = self.check({'shop.example.com': dns.resolver.NoNameservers})
        self.assertFalse(result.conclusive)

    def test_no_cname_is_clean(self):
        result, fetch = self.check({})
        self.assertTrue(result.conclusive)
        self.assertEqual(result.findings, [])
        fetch.assert_not_called()


class RunTakeoverCheckTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()

        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO domain_asset (dom_id, domain_name) VALUES (1, 'example.com')")
        conn.execute("INSERT INTO subdomain_asset (sub_id, dom_id, subdomain_name, status) VALUES (1, 1, 'shop.example.com', 'down')")
        conn.commit()
        conn.close()

    def tearDown(self):
        os.remove(self.db_path)

    def run_with(self, results):
        def fake_check(host, services, resolver):
            return results.get(host, tc.CheckResult(host, conclusive=True))
        with patch.object(tc, 'check_host', side_effect=fake_check):
            return tc.run_takeover_check()

    def finding_status(self):
        conn = db_utils.get_db_connection()
        try:
            return [tuple(r) for r in conn.execute('SELECT host, finding_type, status FROM findings')]
        finally:
            conn.close()

    def test_lifecycle_across_runs(self):
        vulnerable = tc.CheckResult('shop.example.com', conclusive=True, findings=[{
            'finding_type': tc.TAKEOVER, 'title': 'Possible subdomain takeover (Microsoft Azure)',
            'severity': 'high', 'evidence': {'cname_chain': ['old.azurewebsites.net']},
        }])

        first = self.run_with({'shop.example.com': vulnerable})
        self.assertEqual(first['hosts_checked'], 2)  # down subdomains are still checked
        self.assertEqual([f['host'] for f in first['new_findings']], ['shop.example.com'])
        self.assertEqual(self.finding_status(), [('shop.example.com', tc.TAKEOVER, 'open')])

        again = self.run_with({'shop.example.com': vulnerable})
        self.assertEqual(again['new_findings'], [])  # already open, no repeat alert

        inconclusive = self.run_with({'shop.example.com': tc.CheckResult('shop.example.com', conclusive=False, error='timeout')})
        self.assertEqual(inconclusive['inconclusive'], 1)
        self.assertEqual(self.finding_status(), [('shop.example.com', tc.TAKEOVER, 'open')])

        fixed = self.run_with({})
        self.assertEqual(fixed['closed'], 1)
        self.assertEqual(self.finding_status(), [('shop.example.com', tc.TAKEOVER, 'fixed')])

        reopened = self.run_with({'shop.example.com': vulnerable})
        self.assertEqual(len(reopened['new_findings']), 1)
        self.assertEqual(self.finding_status(), [('shop.example.com', tc.TAKEOVER, 'open')])

        self.assertIsNotNone(db_utils.get_setting('last_takeover_check'))

    def test_accepted_finding_does_not_realert(self):
        finding_id, _ = db_utils.upsert_finding(tc.TAKEOVER, 'shop.example.com', 't', 'high', {})
        db_utils.set_finding_status(finding_id, 'accepted', 'Owned by vendor')
        result = self.run_with({'shop.example.com': tc.CheckResult('shop.example.com', conclusive=True, findings=[{
            'finding_type': tc.TAKEOVER, 'title': 't', 'severity': 'high', 'evidence': {},
        }])})
        self.assertEqual(result['new_findings'], [])
        self.assertEqual(self.finding_status(), [('shop.example.com', tc.TAKEOVER, 'accepted')])

    def test_findings_shown_on_asset(self):
        db_utils.upsert_finding(tc.DANGLING, 'shop.example.com', 'Dangling CNAME to x', 'medium', {'cname_chain': ['x']})
        conn = db_utils.get_db_connection()
        try:
            findings = db_utils._get_findings_for_host(conn.cursor(), 'shop.example.com')
        finally:
            conn.close()
        self.assertEqual(findings[0]['evidence'], {'cname_chain': ['x']})
        self.assertEqual(findings[0]['status'], 'open')


if __name__ == '__main__':
    unittest.main()
