import unittest
from unittest.mock import patch

from modules import CVEmatch


def make_cve(cve_id, score, cpe_matches):
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"{cve_id} description"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score}}]},
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": cpe_matches}]}],
    }


def match(criteria, vulnerable=True, **ranges):
    return {"vulnerable": vulnerable, "criteria": criteria, **ranges}


class ParseTests(unittest.TestCase):
    def test_parse_cpe(self):
        self.assertEqual(CVEmatch.parse_cpe("cpe:/a:nginx:nginx"), ("a", "nginx", "nginx"))
        self.assertEqual(CVEmatch.parse_cpe("cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*"), ("a", "f5", "nginx"))
        self.assertIsNone(CVEmatch.parse_cpe("nginx"))
        self.assertIsNone(CVEmatch.parse_cpe(""))

    def test_parse_version(self):
        self.assertEqual(CVEmatch.parse_version("1.20.1"), (1, 20, 1))
        self.assertEqual(CVEmatch.parse_version("2.4.7-ubuntu"), (2, 4, 7))
        self.assertEqual(CVEmatch.parse_version("v3.0"), (3, 0))
        self.assertEqual(CVEmatch.parse_version("unknown"), ())

    def test_wappalyzer_cpe_lookup(self):
        self.assertEqual(CVEmatch.get_cpe_for_technology("jQuery"), ("a", "jquery", "jquery"))
        self.assertEqual(CVEmatch.get_cpe_for_technology("nginx"), ("a", "f5", "nginx"))
        # older nginx CVEs are listed under the previous vendor, so both are queried
        self.assertIn(("nginx", "nginx"), CVEmatch.CPE_ALIASES[("f5", "nginx")])
        self.assertIsNone(CVEmatch.get_cpe_for_technology("NotARealTechnology"))


class VersionMatchTests(unittest.TestCase):
    def test_exact_version(self):
        m = match("cpe:2.3:a:jquery:jquery:1.12.4:*:*:*:*:*:*:*")
        self.assertTrue(CVEmatch.version_matches("1.12.4", m))
        self.assertFalse(CVEmatch.version_matches("1.12.5", m))

    def test_ranges(self):
        m = match("cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
                  versionStartIncluding="1.2", versionEndExcluding="3.5.0")
        self.assertTrue(CVEmatch.version_matches("1.2", m))
        self.assertTrue(CVEmatch.version_matches("3.4.1", m))
        self.assertFalse(CVEmatch.version_matches("3.5.0", m))
        self.assertFalse(CVEmatch.version_matches("1.1.9", m))

        m = match("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                  versionStartExcluding="1.0", versionEndIncluding="1.22.1")
        self.assertFalse(CVEmatch.version_matches("1.0", m))
        self.assertTrue(CVEmatch.version_matches("1.22.1", m))
        self.assertTrue(CVEmatch.version_matches("1.20", m))  # 1.20 == 1.20.0

    def test_not_applicable_version_never_matches(self):
        self.assertFalse(CVEmatch.version_matches("1.0", match("cpe:2.3:a:jquery:jquery:-:*:*:*:*:*:*:*")))

    def test_unparseable_version_never_matches(self):
        self.assertFalse(CVEmatch.version_matches("latest", match("cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*")))


class CveAffectsTests(unittest.TestCase):
    def test_ignores_non_vulnerable_platform_entries(self):
        cve = make_cve("CVE-1", 9.0, [match("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", vulnerable=False)])
        self.assertFalse(CVEmatch.cve_affects(cve, [("f5", "nginx")], "1.20.1"))

    def test_ignores_other_products(self):
        cve = make_cve("CVE-1", 9.0, [match("cpe:2.3:a:netapp:snapcenter:*:*:*:*:*:*:*:*")])
        self.assertFalse(CVEmatch.cve_affects(cve, [("jquery", "jquery")], "1.12.4"))

    def test_matches_alias_product(self):
        cve = make_cve("CVE-1", 9.0, [match("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionEndExcluding="1.23.2")])
        self.assertTrue(CVEmatch.cve_affects(cve, [("nginx", "nginx"), ("f5", "nginx")], "1.20.1"))


class FindCveTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(CVEmatch, "get_cpe_for_technology", return_value=("a", "nginx", "nginx"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_queries_aliases_filters_and_dedupes(self):
        shared = make_cve("CVE-SHARED", 7.5, [match("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")])
        low = make_cve("CVE-LOW", 3.0, [match("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")])
        wrong_version = make_cve("CVE-NEWER", 9.8, [match("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                                         versionStartIncluding="1.25.0")])
        calls = []

        def fake_fetch(match_string):
            calls.append(match_string)
            return [shared] if "nginx:nginx" in match_string else [shared, low, wrong_version]

        with patch.object(CVEmatch, "fetch_nvd", side_effect=fake_fetch):
            result = CVEmatch.find_cve("Nginx", "1.20.1", min_cvss=5.0, use_cache=False)

        self.assertEqual(calls, ["cpe:2.3:a:nginx:nginx:1.20.1", "cpe:2.3:a:f5:nginx:1.20.1"])
        self.assertTrue(result["ok"])
        self.assertEqual([c["cve_id"] for c in result["cves"]], ["CVE-SHARED"])
        self.assertEqual(result["cves"][0]["tech_name"], "Nginx")

    def test_lookup_failure_is_reported_not_empty_success(self):
        with patch.object(CVEmatch, "fetch_nvd", side_effect=CVEmatch.CVELookupError("HTTP 403")):
            result = CVEmatch.find_cve("Nginx", "1.20.1", use_cache=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["cves"], [])
        self.assertIn("403", result["error"])

    def test_no_version_and_no_cpe_skip_lookup(self):
        with patch.object(CVEmatch, "fetch_nvd") as fetch:
            self.assertEqual(CVEmatch.find_cve("Nginx", None, use_cache=False)["method"], "no_version")
            with patch.object(CVEmatch, "get_cpe_for_technology", return_value=None):
                self.assertEqual(CVEmatch.find_cve("Custom", "1.0", use_cache=False)["method"], "no_cpe")
            fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
