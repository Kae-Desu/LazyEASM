import contextlib
import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from modules import InitDB
from utils import db_utils


class VulnLifecycleTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        for target, attr in ((InitDB, "DB_NAME"), (db_utils, "DB_PATH")):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()

        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            INSERT INTO http_services (http_id, host, port_num, is_https) VALUES
                (1, 'api.example.com', 443, 1),
                (2, 'api.example.com', 8443, 1);
            INSERT INTO technologies (tech_id, http_id, tech_name, tech_version) VALUES
                (1, 1, 'Nginx', '1.20.1'),
                (2, 2, 'Nginx', '1.20.1');
        """)
        conn.commit()
        conn.close()

    def tearDown(self):
        os.remove(self.db_path)

    def status_of(self, vuln_id):
        conn = db_utils.get_db_connection()
        try:
            return dict(conn.execute(
                "SELECT status, status_note, match_method FROM vulnerabilities WHERE vuln_id = ?", (vuln_id,)
            ).fetchone())
        finally:
            conn.close()

    def test_unseen_finding_is_fixed_and_reopened_when_seen_again(self):
        kept = db_utils.upsert_vulnerability(1, "CVE-A", 7.5, "a")
        gone = db_utils.upsert_vulnerability(1, "CVE-B", 8.0, "b")

        counts = db_utils.reconcile_vulnerabilities(1, [kept])

        self.assertEqual(counts, {"fixed": 1, "false_positive": 0})
        self.assertEqual(self.status_of(kept)["status"], "open")
        self.assertEqual(self.status_of(gone)["status"], "fixed")

        self.assertEqual(db_utils.upsert_vulnerability(1, "CVE-B", 8.0, "b"), gone)
        self.assertEqual(self.status_of(gone)["status"], "open")
        self.assertEqual(self.status_of(gone)["status_note"], "Detected again on rescan")

    def test_reconcile_is_scoped_to_service_and_cvss_filter(self):
        other_service = db_utils.upsert_vulnerability(2, "CVE-A", 7.5, "a")
        below_filter = db_utils.upsert_vulnerability(1, "CVE-LOW", 3.0, "low")

        db_utils.reconcile_vulnerabilities(1, [], min_cvss=5.0)

        self.assertEqual(self.status_of(other_service)["status"], "open")
        self.assertEqual(self.status_of(below_filter)["status"], "open")

    def test_user_decisions_survive_rescans(self):
        vuln = db_utils.upsert_vulnerability(1, "CVE-A", 7.5, "a")
        db_utils.set_vulnerability_status(vuln, "accepted", "Behind WAF")

        db_utils.upsert_vulnerability(1, "CVE-A", 7.5, "a")
        db_utils.reconcile_vulnerabilities(1, [])

        self.assertEqual(self.status_of(vuln), {"status": "accepted", "status_note": "Behind WAF", "match_method": "cpe"})

    def test_legacy_keyword_findings_become_false_positive(self):
        vuln = db_utils.upsert_vulnerability(1, "CVE-OLD", 9.0, "old")
        conn = db_utils.get_db_connection()
        conn.execute("UPDATE vulnerabilities SET match_method = 'keyword' WHERE vuln_id = ?", (vuln,))
        conn.commit()
        conn.close()

        self.assertEqual(db_utils.reconcile_vulnerabilities(1, []), {"fixed": 0, "false_positive": 1})
        self.assertEqual(self.status_of(vuln)["status"], "false_positive")

    def test_status_change_applies_to_same_cve_on_same_host(self):
        a = db_utils.upsert_vulnerability(1, "CVE-A", 7.5, "a")
        b = db_utils.upsert_vulnerability(2, "CVE-A", 7.5, "a")

        self.assertEqual(db_utils.set_vulnerability_status(a, "false_positive"), 2)
        self.assertEqual(self.status_of(b)["status"], "false_positive")
        self.assertEqual(db_utils.set_vulnerability_status(999, "fixed"), 0)
        with self.assertRaises(ValueError):
            db_utils.set_vulnerability_status(a, "deleted")

    def test_display_and_alerts_reflect_status(self):
        open_vuln = db_utils.upsert_vulnerability(1, "CVE-OPEN", 5.0, "open one")
        fixed_vuln = db_utils.upsert_vulnerability(1, "CVE-FIXED", 9.0, "fixed one")
        db_utils.set_vulnerability_status(fixed_vuln, "fixed")

        conn = db_utils.get_db_connection()
        try:
            cves = db_utils._get_cves_for_host(conn.cursor(), "api.example.com")
        finally:
            conn.close()
        self.assertEqual([(c["cve_id"], c["status"]) for c in cves], [("CVE-OPEN", "open"), ("CVE-FIXED", "fixed")])

        alerts = db_utils.get_new_cves_for_alert(min_cvss=0)
        self.assertEqual([c["cve_id"] for c in alerts["api.example.com"]["cves"]], ["CVE-OPEN"])

    def test_cve_cache_round_trip_and_expiry(self):
        db_utils.set_cached_cves("cpe:2.3:a:f5:nginx:1.20.1", [{"cve_id": "CVE-A"}])
        self.assertEqual(db_utils.get_cached_cves("cpe:2.3:a:f5:nginx:1.20.1"), [{"cve_id": "CVE-A"}])
        self.assertIsNone(db_utils.get_cached_cves("cpe:2.3:a:f5:nginx:1.20.1", max_age_hours=-1))
        self.assertIsNone(db_utils.get_cached_cves("cpe:2.3:a:other:thing:1"))


class LegacyMigrationTests(unittest.TestCase):
    def test_existing_findings_are_tagged_keyword(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, db_path)

        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE vulnerabilities (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT, tech_id INTEGER, cve_id TEXT NOT NULL,
                cve_score REAL, description TEXT, recommendation TEXT,
                status TEXT DEFAULT 'open', first_seen TEXT, last_seen TEXT
            );
            INSERT INTO vulnerabilities (tech_id, cve_id, cve_score) VALUES (1, 'CVE-OLD', 9.0);
        """)
        conn.commit()
        conn.close()

        with patch.object(InitDB, "DB_NAME", db_path), contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()

        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute("SELECT match_method, status FROM vulnerabilities").fetchone()
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        self.assertEqual(row, ("keyword", "open"))
        self.assertIn("cve_cache", tables)


if __name__ == "__main__":
    unittest.main()
