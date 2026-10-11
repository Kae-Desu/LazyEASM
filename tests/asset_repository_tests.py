import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from utils import asset_repository


SCHEMA = """
CREATE TABLE domain_asset (
    dom_id INTEGER PRIMARY KEY, domain_name TEXT UNIQUE, first_seen TEXT,
    last_seen TEXT, last_scanned TEXT, last_deep_scan TEXT,
    last_wappalyzer_scan TEXT, status TEXT
);
CREATE TABLE subdomain_asset (
    sub_id INTEGER PRIMARY KEY, dom_id INTEGER, subdomain_name TEXT UNIQUE,
    first_seen TEXT, last_seen TEXT, last_scanned TEXT, last_deep_scan TEXT,
    last_wappalyzer_scan TEXT, status TEXT
);
CREATE TABLE ip_asset (
    ip_id INTEGER PRIMARY KEY, ip_value TEXT UNIQUE, first_seen TEXT,
    last_seen TEXT, last_scanned TEXT, status TEXT
);
CREATE TABLE domain_ip (dom_id INTEGER, ip_id INTEGER);
CREATE TABLE subdomain_ip (sub_id INTEGER, ip_id INTEGER);
CREATE TABLE ports (
    port_id INTEGER PRIMARY KEY, ip_id INTEGER, port_num INTEGER,
    protocol TEXT, service_name TEXT
);
CREATE TABLE http_services (
    http_id INTEGER PRIMARY KEY, host TEXT, ip_id INTEGER, port_num INTEGER,
    is_https INTEGER, title TEXT, web_server TEXT
);
CREATE TABLE technologies (
    tech_id INTEGER PRIMARY KEY, http_id INTEGER, tech_name TEXT, tech_version TEXT
);
CREATE TABLE vulnerabilities (
    vuln_id INTEGER PRIMARY KEY, tech_id INTEGER, cve_id TEXT,
    cve_score REAL, description TEXT, recommendation TEXT
);
CREATE TABLE certificates (
    cert_id INTEGER PRIMARY KEY, hostname TEXT, issuer TEXT, not_after TEXT
);
CREATE TABLE directories (
    dir_id INTEGER PRIMARY KEY, http_id INTEGER, path TEXT,
    status_code INTEGER, content_length INTEGER
);
CREATE TABLE scan_queue (
    queue_id INTEGER PRIMARY KEY, scan_type TEXT, target TEXT,
    status TEXT, queued_at TEXT
);
"""


class AssetRepositoryTests(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(SCHEMA)
        conn.executescript("""
            INSERT INTO domain_asset VALUES
                (1, 'example.com', '2026-01-01', NULL, '2026-01-02', NULL, NULL, 'up');
            INSERT INTO subdomain_asset VALUES
                (1, 1, 'api.example.com', '2026-01-01', NULL, '2026-01-02', NULL, NULL, 'up');
            INSERT INTO ip_asset VALUES
                (1, '203.0.113.10', '2026-01-01', NULL, '2026-01-02', 'up'),
                (2, '198.51.100.20', '2026-01-01', NULL, NULL, 'down');
            INSERT INTO domain_ip VALUES (1, 1);
            INSERT INTO subdomain_ip VALUES (1, 1);
            INSERT INTO ports VALUES
                (1, 1, 443, 'tcp', 'https'),
                (2, 2, 8080, 'tcp', 'http-proxy');
            INSERT INTO http_services VALUES
                (1, 'api.example.com', 1, 443, 1, 'API', 'nginx'),
                (2, '198.51.100.20', 2, 8080, 0, 'App', 'gunicorn');
            INSERT INTO technologies VALUES
                (1, 1, 'nginx', '1.24'),
                (2, 2, 'Flask', '3.0');
            INSERT INTO vulnerabilities VALUES
                (1, 1, 'CVE-2026-0001', 9.8, 'Example issue', NULL);
            INSERT INTO certificates
                VALUES (1, 'api.example.com', 'Example CA', datetime('now', '+10 days'));
            INSERT INTO directories VALUES (1, 1, '/admin', 403, 0);
            INSERT INTO scan_queue VALUES
                (1, 'phase2_deep_scan', 'api.example.com', 'pending', '2026-01-03');
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
        os.remove(self.db_path)

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
        self.assertEqual(asset["certificate"]["state"], "expiring")

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
        self.assertEqual(detail["vulnerabilities"][0]["cve_id"], "CVE-2026-0001")
        self.assertEqual(detail["directories"][0]["path"], "/admin")

    def test_invalid_query_values_are_rejected(self):
        with self.assertRaises(asset_repository.AssetQueryError):
            asset_repository.list_assets(asset_types=["bucket"])
        with self.assertRaises(asset_repository.AssetQueryError):
            asset_repository.list_assets(port=70000)
        with self.assertRaises(asset_repository.AssetQueryError):
            asset_repository.list_assets(sort="drop table")


if __name__ == "__main__":
    unittest.main()
