import contextlib
import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from modules import InitDB
from utils import asset_repository


class AssetRepositoryTests(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        # Real schema, so the fixture cannot drift from InitDB
        with patch.object(InitDB, "DB_NAME", self.db_path), contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            INSERT INTO domain_asset (dom_id, domain_name, first_seen, last_scanned, status)
                VALUES (1, 'example.com', '2026-01-01', '2026-01-02', 'up');
            INSERT INTO subdomain_asset (sub_id, dom_id, subdomain_name, first_seen, last_scanned, status)
                VALUES (1, 1, 'api.example.com', '2026-01-01', '2026-01-02', 'up');
            INSERT INTO ip_asset (ip_id, ip_value, first_seen, last_scanned, status) VALUES
                (1, '203.0.113.10', '2026-01-01', '2026-01-02', 'up'),
                (2, '198.51.100.20', '2026-01-01', NULL, 'down');
            INSERT INTO domain_ip (dom_id, ip_id) VALUES (1, 1);
            INSERT INTO subdomain_ip (sub_id, ip_id) VALUES (1, 1);
            INSERT INTO ports (port_id, ip_id, port_num, protocol, service_name) VALUES
                (1, 1, 443, 'tcp', 'https'),
                (2, 2, 8080, 'tcp', 'http-proxy');
            INSERT INTO http_services (http_id, host, ip_id, port_num, is_https, title, web_server) VALUES
                (1, 'api.example.com', 1, 443, 1, 'API', 'nginx'),
                (2, '198.51.100.20', 2, 8080, 0, 'App', 'gunicorn');
            INSERT INTO technologies (tech_id, http_id, tech_name, tech_version, removed_at) VALUES
                (1, 1, 'nginx', '1.24', NULL),
                (2, 2, 'Flask', '3.0', NULL),
                (3, 1, 'nginx', '1.18', '2026-01-01 00:00:00');
            INSERT INTO vulnerabilities (vuln_id, tech_id, cve_id, cve_score, description, recommendation) VALUES
                (1, 1, 'CVE-2026-0001', 9.8, 'Example issue', NULL);
            INSERT INTO cve_intel (cve_id, epss, epss_percentile, in_kev, kev_required_action)
                VALUES ('CVE-2026-0001', 0.42, 0.97, 1, 'Apply updates');
            INSERT INTO certificates (cert_id, hostname, port, issuer, not_after, source)
                VALUES (1, 'api.example.com', 443, 'Example CA', datetime('now', '+10 days'), 'tls');
            INSERT INTO directories (dir_id, http_id, path, status_code, content_length) VALUES (1, 1, '/admin', 403, 0);
            INSERT INTO scan_queue (queue_id, scan_type, cycle, target, status, queued_at) VALUES
                (1, 'phase2_deep_scan', 'standard', 'api.example.com', 'pending', '2026-01-03');
            INSERT INTO findings (finding_type, host, title, severity, status) VALUES
                ('exposed_env', 'api.example.com', 'Environment file exposed', 'high', 'open'),
                ('missing_security_headers', 'api.example.com', 'Missing security headers', 'low', 'open'),
                ('directory_listing', 'example.com', 'Directory listing enabled', 'medium', 'fixed');
            INSERT INTO asset_changes (host, change_type, summary, detected_at)
                VALUES ('api.example.com', 'port_opened', 'Port 443/tcp opened', '2026-01-02 00:00:00');
        """)
        conn.commit()
        conn.close()

        def connection_factory():
            connection = sqlite3.connect(self.db_path)
            connection.row_factory = sqlite3.Row
            return connection

        self.connection_patch = patch.object(
            asset_repository, "get_db_connection", side_effect=connection_factory
        )
        self.connection_patch.start()

    def tearDown(self):
        self.connection_patch.stop()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def test_list_is_paginated_and_excludes_linked_ips(self):
        result = asset_repository.list_assets(page=1, page_size=2)

        self.assertEqual(result["pagination"]["total"], 3)
        self.assertEqual(result["pagination"]["total_pages"], 2)
        self.assertEqual(len(result["items"]), 2)
        self.assertTrue(result["pagination"]["has_next"])

    def test_search_and_cloud_oriented_filters(self):
        result = asset_repository.list_assets(
            query="api",
            root_domain="example.com",
            technology="NGINX",
            port=443,
            min_cvss=9,
            cert_state="expiring",
            scan_state="pending",
        )

        self.assertEqual(result["pagination"]["total"], 1)
        asset = result["items"][0]
        self.assertEqual(asset["name"], "api.example.com")
        self.assertEqual(asset["technology_count"], 1)
        self.assertEqual(asset["vulnerability_count"], 1)
        self.assertEqual(asset["kev_count"], 1)
        # open security findings only; the fixed one on example.com is not counted
        self.assertEqual((asset["finding_count"], asset["max_finding_severity"]), (2, "high"))
        self.assertEqual(asset["max_epss"], 0.42)
        self.assertEqual(asset["certificate"]["state"], "expiring")

    def test_kev_filter_and_epss_sort(self):
        result = asset_repository.list_assets(kev_only="true")
        self.assertEqual([item["name"] for item in result["items"]], ["api.example.com"])

        ranked = asset_repository.list_assets(sort="max_epss", order="desc")
        self.assertEqual(ranked["items"][0]["name"], "api.example.com")

    def test_ip_port_filter_includes_standalone_ip(self):
        result = asset_repository.list_assets(port=8080, asset_types=["ip"])

        self.assertEqual(result["pagination"]["total"], 1)
        self.assertEqual(result["items"][0]["name"], "198.51.100.20")

    def test_detail_loads_expensive_collections_for_one_asset(self):
        detail = asset_repository.get_asset_detail("subdomain", 1)

        self.assertEqual(detail["name"], "api.example.com")
        self.assertEqual(detail["root_domain"], "example.com")
        self.assertEqual(detail["ips"], ["203.0.113.10"])
        self.assertEqual(detail["technologies"][0]["name"], "nginx")
        # technologies removed by a later scan are not listed
        self.assertEqual([t["version"] for t in detail["technologies"]], ["1.24"])
        self.assertEqual(detail["vulnerabilities"][0]["cve_id"], "CVE-2026-0001")
        self.assertEqual(detail["vulnerabilities"][0]["priority"], "P1")
        self.assertTrue(detail["vulnerabilities"][0]["in_kev"])
        self.assertEqual(detail["directories"][0]["path"], "/admin")
        self.assertEqual([f["finding_type"] for f in detail["security_findings"]], ["exposed_env", "missing_security_headers"])
        self.assertEqual(detail["history"][0]["summary"], "Port 443/tcp opened")
        self.assertEqual(detail["phase2_status"], "pending")

    def test_invalid_query_values_are_rejected(self):
        with self.assertRaises(asset_repository.AssetQueryError):
            asset_repository.list_assets(asset_types=["bucket"])
        with self.assertRaises(asset_repository.AssetQueryError):
            asset_repository.list_assets(port=70000)
        with self.assertRaises(asset_repository.AssetQueryError):
            asset_repository.list_assets(sort="drop table")


if __name__ == "__main__":
    unittest.main()
