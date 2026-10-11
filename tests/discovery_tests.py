import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from modules import InitDB
from utils import db_utils, subdomain_discovery as sd


def response(status=200, json_data=None, text=''):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_data
    r.text = text
    return r


class FakeResolver:
    """Names in `existing` resolve; `errors` raise a timeout; anything else is NXDOMAIN."""

    def __init__(self, existing=(), errors=(), wildcard=False):
        self.existing, self.errors, self.wildcard = set(existing), set(errors), wildcard

    def resolve(self, name, rtype):
        if name in self.errors:
            raise dns.exception.Timeout()
        if self.wildcard or name in self.existing:
            return ['192.0.2.1']
        raise dns.resolver.NXDOMAIN()


class ScopeTests(unittest.TestCase):
    def test_label_boundary_and_normalization(self):
        self.assertEqual(sd.in_scope('API.Example.com.', 'example.com'), 'api.example.com')
        self.assertEqual(sd.in_scope('*.dev.example.com', 'example.com'), 'dev.example.com')
        self.assertIsNone(sd.in_scope('notexample.com', 'example.com'))
        self.assertIsNone(sd.in_scope('example.com', 'example.com'))      # the root itself
        self.assertIsNone(sd.in_scope('*.example.com', 'example.com'))
        self.assertIsNone(sd.in_scope('bad_name!.example.com', 'example.com'))


class PassiveSourceTests(unittest.TestCase):
    def test_certspotter_paginates(self):
        pages = [[{'id': '1', 'dns_names': ['a.example.com', 'example.com']}],
                 [{'id': '2', 'dns_names': ['b.example.com']}], []]
        with patch.object(sd.requests, 'get', side_effect=[response(json_data=p) for p in pages]) as get:
            self.assertEqual(sd.from_certspotter('example.com'), {'a.example.com', 'example.com', 'b.example.com'})
        self.assertEqual(get.call_args_list[1].kwargs['params']['after'], '1')

    def test_hackertarget_parses_and_detects_quota(self):
        with patch.object(sd.requests, 'get', return_value=response(text='a.example.com,1.2.3.4\nb.example.com,5.6.7.8')):
            self.assertEqual(sd.from_hackertarget('example.com'), {'a.example.com', 'b.example.com'})
        with patch.object(sd.requests, 'get', return_value=response(text='API count exceeded - Increase Quota')):
            with self.assertRaises(sd.SourceError):
                sd.from_hackertarget('example.com')

    def test_wayback_extracts_hosts(self):
        rows = [['original'], ['http://a.example.com:80/x'], ['https://b.example.com/y?z'], ['c.example.com/path']]
        with patch.object(sd.requests, 'get', return_value=response(json_data=rows)):
            self.assertEqual(sd.from_wayback('example.com'), {'a.example.com', 'b.example.com', 'c.example.com'})

    def test_failing_source_does_not_stop_others(self):
        sources = {'good': lambda d: {'a.example.com', 'evil.com'},
                   'bad': MagicMock(side_effect=sd.SourceError('rate limited'))}
        with patch.object(sd, 'PASSIVE_SOURCES', sources):
            found, stats = sd.passive_subdomains('example.com')
        self.assertEqual(found, {'a.example.com'})
        self.assertEqual(stats, {'good': 1, 'bad': 'error: rate limited'})

    def test_otx_skipped_without_key(self):
        with patch.object(sd, 'PASSIVE_SOURCES', {'otx': sd.from_otx}), \
             patch.object(sd, 'get_env', return_value=None):
            found, stats = sd.passive_subdomains('example.com')
        self.assertEqual(found, set())
        self.assertIn('skipped', stats['otx'])


class ActiveDiscoveryTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(sd, 'get_env', return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_active(self, resolver, known=()):
        with patch.object(sd, 'make_resolver', return_value=resolver), \
             patch.object(sd, 'load_wordlist', return_value=['www', 'dev', 'vpn']):
            return sd.active_subdomains('example.com', known)

    def test_bruteforce_and_permutations(self):
        resolver = FakeResolver(existing={'dev.example.com', 'api-staging.example.com', 'api.example.com'})
        found, stats = self.run_active(resolver, known={'api.example.com'})
        self.assertEqual(found, {'dev.example.com', 'api-staging.example.com'})
        self.assertEqual((stats['bruteforce'], stats['permutations']), (1, 1))

    def test_wildcard_dns_skips_active_discovery(self):
        found, stats = self.run_active(FakeResolver(wildcard=True))
        self.assertEqual(found, set())
        self.assertEqual(stats, {'active': 'skipped (wildcard DNS)'})

    def test_dns_errors_during_wildcard_check_count_as_wildcard(self):
        resolver = FakeResolver()
        resolver.resolve = MagicMock(side_effect=dns.exception.Timeout())
        self.assertTrue(sd.has_wildcard_dns('example.com', resolver))

    def test_disabled_by_setting(self):
        with patch.object(sd, 'get_env', side_effect=lambda k, d=None: 'false' if k == 'DNS_BRUTEFORCE' else None):
            found, stats = sd.active_subdomains('example.com')
        self.assertEqual(found, set())
        self.assertIn('disabled', stats['active'])

    def test_permutations_are_bounded(self):
        known = {f'host{i}.example.com' for i in range(500)}
        self.assertLessEqual(len(sd.permutation_candidates('example.com', known)), sd.MAX_PERMUTATIONS)

    def test_bundled_wordlist(self):
        words = sd.load_wordlist()
        self.assertGreater(len(words), 200)
        self.assertEqual(len(words), len(set(words)))


class DiscoveryMonitorTests(unittest.TestCase):
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
        conn.execute("INSERT INTO subdomain_asset (sub_id, dom_id, subdomain_name) VALUES (1, 1, 'known.example.com')")
        conn.commit()
        conn.close()

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def test_queues_only_new_subdomains(self):
        found = {'known.example.com', 'new.example.com'}
        with patch.object(sd, 'discover', return_value=(found, {'certspotter': 2})) as discover:
            result = sd.run_discovery_monitor()

        self.assertEqual(result['new_subdomains'], [('example.com', 'new.example.com')])
        self.assertEqual(discover.call_args.args, ('example.com', {'known.example.com'}))
        conn = db_utils.get_db_connection()
        try:
            queued = [r['target'] for r in conn.execute(
                "SELECT target FROM scan_queue WHERE scan_type = 'phase0_discovery'")]
        finally:
            conn.close()
        self.assertEqual(queued, ['new.example.com'])
        self.assertTrue(db_utils.get_setting('last_discovery_check'))


if __name__ == '__main__':
    unittest.main()
