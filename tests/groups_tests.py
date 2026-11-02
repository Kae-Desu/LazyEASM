"""Asset groups: membership rules and filtered pages."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from modules import InitDB
from utils import activity_repository, asset_repository, db_utils, findings_repository, groups
from utils.timeutil import utc_now_str


class GroupsTestCase(unittest.TestCase):
    """
    example.com (www on 203.0.113.10 and the CDN address 198.51.100.23),
    example.org (blog, also behind the CDN), example.net (not scanned; only
    shop.example.net was submitted), lost.example.info (its domain was
    deleted), and the IPs 203.0.113.40 and 192.0.2.5 submitted on their own.
    """

    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db_path = os.path.join(tmp, 'test.db')
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            p = patch.object(target, attr, db_path)
            p.start()
            self.addCleanup(p.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        conn = db_utils.get_db_connection()
        try:
            c = conn.cursor()
            ids = {}
            for name, expand in (('example.com', 1), ('example.org', 1), ('example.net', 0)):
                c.execute('INSERT INTO domain_asset (domain_name, expand) VALUES (?, ?)', (name, expand))
                ids[name] = c.lastrowid
            for ip, shared in (('203.0.113.10', 0), ('198.51.100.23', 1), ('203.0.113.40', 0), ('192.0.2.5', 0)):
                c.execute('INSERT INTO ip_asset (ip_value, is_shared, shared_provider) VALUES (?, ?, ?)',
                          (ip, shared, 'CDN' if shared else None))
                ids[ip] = c.lastrowid
            for name, domain, ips in (('www.example.com', 'example.com', ['203.0.113.10', '198.51.100.23']),
                                      ('blog.example.org', 'example.org', ['198.51.100.23']),
                                      ('shop.example.net', 'example.net', []),
                                      ('lost.example.info', None, [])):
                c.execute('INSERT INTO subdomain_asset (dom_id, subdomain_name) VALUES (?, ?)', (ids.get(domain), name))
                sub_id = c.lastrowid
                for ip in ips:
                    c.execute('INSERT INTO subdomain_ip (sub_id, ip_id) VALUES (?, ?)', (sub_id, ids[ip]))
            now = utc_now_str()
            for host in ('www.example.com', 'blog.example.org', '203.0.113.40', 'lost.example.info'):
                c.execute("INSERT INTO findings (finding_type, host, title, severity, evidence, status, first_seen) "
                          "VALUES ('exposed_git', ?, 'Git repository exposed', 'high', '{}', 'open', ?)", (host, now))
                c.execute("INSERT INTO asset_changes (host, change_type, summary, detected_at) "
                          "VALUES (?, 'asset_added', 'New', ?)", (host, now))
                c.execute("INSERT INTO scan_queue (scan_type, cycle, target, status) VALUES ('phase1', 'standard', ?, 'completed')",
                          (host,))
            c.execute("INSERT INTO scan_queue (scan_type, cycle, target, status) VALUES "
                      "('input_discovery', 'standard', ?, 'completed')", (json.dumps({'domains': ['example.org']}),))
            conn.commit()
        finally:
            conn.close()
        self.corp = groups.create_group('Example Corp')
        groups.add_member(self.corp, 'domain', 'example.com')
        groups.add_member(self.corp, 'cidr', '203.0.113.32/27')

    def resolve(self, key):
        conn = db_utils.get_db_connection()
        try:
            return groups.Inventory(conn).resolve(key)
        finally:
            conn.close()

    def groups_of(self, host):
        conn = db_utils.get_db_connection()
        try:
            return groups.Inventory(conn).groups_of(host)
        finally:
            conn.close()


class MembershipTests(GroupsTestCase):
    def test_named_group_hosts_cidr_and_linked_ips_but_not_cdn(self):
        self.assertEqual(self.resolve(f'g:{self.corp}'),
                         {'example.com', 'www.example.com', '203.0.113.10', '203.0.113.40'})

    def test_root_domains_not_in_a_named_group_are_automatic_groups(self):
        menu = groups.menu()
        self.assertEqual([r['name'] for r in menu['roots']], ['example.net', 'example.org'])
        self.assertEqual(self.resolve('d:example.org'), {'example.org', 'blog.example.org'})
        self.assertEqual(self.resolve('d:example.net'), {'example.net', 'shop.example.net'})   # never scanned

    def test_ungrouped_and_all(self):
        self.assertEqual(self.resolve(groups.UNGROUPED), {'lost.example.info', '192.0.2.5', '198.51.100.23'})
        self.assertIsNone(self.resolve(groups.ALL))

    def test_overlapping_ranges_are_both_kept(self):
        other = groups.create_group('Small block')
        groups.add_member(other, 'cidr', '203.0.113.32/28')
        self.assertEqual(self.groups_of('203.0.113.40'), ['Example Corp', 'Small block'])
        self.assertEqual(self.groups_of('blog.example.org'), ['example.org'])

    def test_menu_counts_match_the_assets_list(self):
        menu = groups.menu()
        self.assertEqual(menu['named'], [{'key': f'g:{self.corp}', 'name': 'Example Corp', 'count': 3}])
        self.assertEqual(menu['all'], asset_repository.list_assets()['pagination']['total'])
        self.assertEqual(menu['named'][0]['count'],
                         asset_repository.list_assets(group=f'g:{self.corp}')['pagination']['total'])

    def test_deleting_a_group_returns_its_domains_to_automatic_groups(self):
        groups.delete_group(self.corp)
        self.assertIn('example.com', [r['name'] for r in groups.menu()['roots']])


class ValidationTests(GroupsTestCase):
    def test_members(self):
        self.assertEqual(groups.normalize_cidr('203.0.113.40'), '203.0.113.40/32')
        self.assertEqual(groups.normalize_cidr('203.0.113.45/27'), '203.0.113.32/27')
        self.assertEqual(groups.normalize_domain('https://Example.ORG/login'), 'example.org')
        for bad in ('0.0.0.0/0', '::/0', '300.1.1.1'):
            with self.assertRaises(groups.GroupError):
                groups.normalize_cidr(bad)
        for bad in ('not a domain', 'example', ''):
            with self.assertRaises(groups.GroupError):
                groups.normalize_domain(bad)
        self.assertEqual(groups.member_kind('198.51.100.0/24'), 'cidr')
        self.assertEqual(groups.member_kind('example.com'), 'domain')

    def test_names(self):
        with self.assertRaises(groups.GroupError):
            groups.create_group('example corp')               # names are unique, ignoring case
        for bad in ('', 'All', 'ungrouped', 'x' * 61):
            with self.assertRaises(groups.GroupError):
                groups.create_group(bad)
        groups.rename_group(self.corp, 'Client A')
        self.assertEqual(groups.label(f'g:{self.corp}'), 'Client A')

    def test_keys(self):
        for key in ('all', 'ungrouped', f'g:{self.corp}', 'd:example.org'):
            self.assertTrue(groups.is_valid_key(key), key)
        for key in ('g:999', 'd:example.edu', 'x', 'g:abc'):
            self.assertFalse(groups.is_valid_key(key), key)
        with self.assertRaises(groups.GroupError):
            findings_repository.list_findings(group='g:999')


class FilteredPagesTests(GroupsTestCase):
    def test_every_page_shows_only_the_group(self):
        corp = f'g:{self.corp}'
        hosts = lambda items: sorted(item['host'] for item in items)

        self.assertEqual(hosts(findings_repository.list_findings(group=corp)['items']),
                         ['203.0.113.40', 'www.example.com'])
        self.assertEqual(hosts(findings_repository.list_findings(group='d:example.org')['items']), ['blog.example.org'])
        self.assertEqual(len(findings_repository.list_findings()['items']), 4)

        overview = findings_repository.get_overview(group='d:example.org')
        self.assertEqual(overview['issues']['open_total'], 1)
        self.assertEqual(overview['assets']['total'], 2)
        self.assertEqual(overview['changes_this_week'], 1)
        self.assertEqual(findings_repository.get_overview()['changes_this_week'], 4)
        self.assertEqual([a['name'] for a in overview['riskiest_assets']], ['blog.example.org'])

        self.assertEqual(hosts(activity_repository.list_changes(group=corp)['items']),
                         ['203.0.113.40', 'www.example.com'])
        self.assertEqual(hosts(db_utils.get_changes(group=groups.UNGROUPED)), ['lost.example.info'])

        scans = [item['target'] for item in activity_repository.list_scans(group='d:example.org')['items']]
        self.assertEqual(len(scans), 2)                         # its phase1 job and the submission naming it

        self.assertEqual(sorted(a['name'] for a in asset_repository.export_assets(group=corp)),
                         ['203.0.113.40', 'example.com', 'www.example.com'])
        self.assertEqual(hosts(db_utils.get_findings_for_export(group=corp)), ['203.0.113.40', 'www.example.com'])


if __name__ == '__main__':
    unittest.main()
