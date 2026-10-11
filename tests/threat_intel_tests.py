import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests

from modules import InitDB
from utils import db_utils, threat_intel as ti


def http_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


KEV_ENTRY = {'date_added': '2026-10-01', 'due_date': '2026-10-22',
             'required_action': 'Apply mitigations per vendor instructions.', 'ransomware': True}


class PriorityTests(unittest.TestCase):
    def test_priority_order(self):
        self.assertEqual(ti.compute_priority(4.0, 0.01, True)['priority'], 'P1')   # KEV beats low CVSS
        self.assertEqual(ti.compute_priority(5.0, 0.25, False)['priority'], 'P2')
        self.assertEqual(ti.compute_priority(9.8, 0.02, False)['priority'], 'P3')
        self.assertEqual(ti.compute_priority(9.8, None, False)['priority'], 'P3')
        self.assertEqual(ti.compute_priority(5.0, 0.01, False)['priority'], 'P4')
        self.assertEqual(ti.compute_priority(None, None, False)['priority'], 'P4')
        self.assertIn('25%', ti.compute_priority(5.0, 0.25, False)['reason'])


class FetchTests(unittest.TestCase):
    def setUp(self):
        ti._kev_cache.update(fetched_at=0.0, data=None)

    def test_kev_parsed_and_cached(self):
        payload = {'vulnerabilities': [
            {'cveID': 'CVE-2021-44228', 'dateAdded': '2021-12-10', 'dueDate': '2021-12-24',
             'requiredAction': 'Apply updates', 'knownRansomwareCampaignUse': 'Known'},
            {'cveID': 'cve-2015-5477', 'dateAdded': '2026-10-08', 'dueDate': '2026-10-11',
             'requiredAction': 'Patch', 'knownRansomwareCampaignUse': 'Unknown'},
        ]}
        with patch.object(ti.requests, 'get', return_value=http_response(payload)) as get:
            kev = ti.fetch_kev()
            ti.fetch_kev()
        get.assert_called_once()
        self.assertTrue(kev['CVE-2021-44228']['ransomware'])
        self.assertFalse(kev['CVE-2015-5477']['ransomware'])
        self.assertEqual(kev['CVE-2015-5477']['due_date'], '2026-10-11')

    def test_kev_failure_raises(self):
        with patch.object(ti.requests, 'get', side_effect=requests.ConnectionError('down')):
            with self.assertRaises(ti.IntelFetchError):
                ti.fetch_kev()

    def test_empty_kev_is_an_error_not_an_empty_catalog(self):
        with patch.object(ti.requests, 'get', return_value=http_response({'vulnerabilities': []})):
            with self.assertRaises(ti.IntelFetchError):
                ti.fetch_kev()

    def test_epss_batches_and_parses(self):
        ids = [f'CVE-2026-{i:04d}' for i in range(150)]

        def fake_get(url, params, timeout):
            batch = params['cve'].split(',')
            data = [{'cve': c, 'epss': '0.5', 'percentile': '0.9', 'date': '2026-10-11'} for c in batch[:2]]
            data.append({'cve': 'CVE-BAD', 'epss': 'not-a-number', 'percentile': '1'})
            return http_response({'data': data})

        with patch.object(ti.requests, 'get', side_effect=fake_get) as get:
            scores = ti.fetch_epss(ids + ['cve-2026-0000'])
        self.assertEqual(get.call_count, 2)
        self.assertEqual(len(scores), 4)
        self.assertEqual(scores['CVE-2026-0000'], {'epss': 0.5, 'percentile': 0.9, 'date': '2026-10-11'})


class RefreshTests(unittest.TestCase):
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
        conn.executescript("""
            INSERT INTO http_services (http_id, host, port_num, is_https) VALUES (1, 'shop.example.com', 443, 1);
            INSERT INTO technologies (tech_id, http_id, tech_name, tech_version) VALUES (1, 1, 'Nginx', '1.20.1');
        """)
        conn.commit()
        conn.close()
        self.exploited = db_utils.upsert_vulnerability(1, 'CVE-A', 5.3, 'exploited, low cvss')
        self.severe = db_utils.upsert_vulnerability(1, 'CVE-B', 9.8, 'severe, no signal')
        self.fixed = db_utils.upsert_vulnerability(1, 'CVE-C', 7.0, 'fixed already')
        db_utils.set_vulnerability_status(self.fixed, 'fixed')

    def tearDown(self):
        os.remove(self.db_path)

    def refresh(self, kev=None, epss=None, kev_error=False, epss_error=False, cve_ids=None):
        kev_patch = patch.object(ti, 'fetch_kev', side_effect=ti.IntelFetchError('kev down')) if kev_error \
            else patch.object(ti, 'fetch_kev', return_value=kev or {})
        epss_patch = patch.object(ti, 'fetch_epss', side_effect=ti.IntelFetchError('epss down')) if epss_error \
            else patch.object(ti, 'fetch_epss', return_value=epss or {})
        with kev_patch, epss_patch:
            return ti.refresh_threat_intel(cve_ids)

    def intel(self, cve_id):
        return db_utils.get_cve_intel([cve_id]).get(cve_id, {})

    def test_newly_exploited_open_cves_are_reported_once(self):
        kev = {'CVE-A': KEV_ENTRY, 'CVE-C': KEV_ENTRY}
        first = self.refresh(kev=kev, epss={'CVE-A': {'epss': 0.4, 'percentile': 0.98, 'date': 'd'}})

        self.assertEqual(first['cves_checked'], 3)
        self.assertEqual(first['kev_count'], 2)
        # CVE-C is in KEV but its only finding is fixed, so no alert
        self.assertEqual([(n['cve_id'], n['hosts']) for n in first['newly_kev']], [('CVE-A', ['shop.example.com'])])
        self.assertTrue(first['newly_kev'][0]['ransomware'])
        self.assertEqual(self.intel('CVE-A')['epss'], 0.4)
        self.assertIsNotNone(db_utils.get_setting('last_intel_check'))

        second = self.refresh(kev=kev)
        self.assertEqual(second['newly_kev'], [])

    def test_failed_source_keeps_previous_values(self):
        self.refresh(kev={'CVE-A': KEV_ENTRY}, epss={'CVE-A': {'epss': 0.4, 'percentile': 0.98, 'date': 'd'}})

        result = self.refresh(kev_error=True, epss_error=True)

        self.assertEqual(len(result['errors']), 2)
        self.assertEqual(self.intel('CVE-A')['in_kev'], 1)
        self.assertEqual(self.intel('CVE-A')['epss'], 0.4)

    def test_cve_removed_from_kev_is_cleared(self):
        self.refresh(kev={'CVE-A': KEV_ENTRY})
        self.refresh(kev={'CVE-OTHER': KEV_ENTRY})
        self.assertEqual(self.intel('CVE-A')['in_kev'], 0)
        self.assertIsNone(self.intel('CVE-A')['kev_required_action'])

    def test_targeted_refresh_does_not_mark_full_check(self):
        self.refresh(cve_ids=['cve-a'])
        self.assertFalse(db_utils.get_setting('last_intel_check'))
        self.assertIn('CVE-A', db_utils.get_cve_intel(['CVE-A']))

    def test_findings_sorted_by_exploitation_then_severity(self):
        self.refresh(kev={'CVE-A': KEV_ENTRY})
        conn = db_utils.get_db_connection()
        try:
            cves = db_utils._get_cves_for_host(conn.cursor(), 'shop.example.com')
        finally:
            conn.close()
        self.assertEqual([(c['cve_id'], c['priority']) for c in cves],
                         [('CVE-A', 'P1'), ('CVE-B', 'P3'), ('CVE-C', 'P3')])
        self.assertTrue(cves[0]['in_kev'])
        self.assertEqual(cves[0]['kev_required_action'], KEV_ENTRY['required_action'])

    def test_refresh_quietly_alerts_and_never_raises(self):
        with patch.object(ti, 'refresh_threat_intel', return_value={'newly_kev': [{'cve_id': 'CVE-A'}]}), \
             patch('utils.phase3_worker.send_kev_notification') as notify:
            ti.refresh_quietly(['CVE-A'])
        notify.assert_called_once()
        with patch.object(ti, 'refresh_threat_intel', side_effect=RuntimeError('boom')):
            ti.refresh_quietly(['CVE-A'])


if __name__ == '__main__':
    unittest.main()
