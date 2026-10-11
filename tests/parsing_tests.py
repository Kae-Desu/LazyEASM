import unittest

from utils import parsing


class NormalizeHostnameTests(unittest.TestCase):
    def test_strips_protocol_path_port_and_case(self):
        self.assertEqual(parsing.normalize_hostname("https://Example.com/api"), "example.com")
        self.assertEqual(parsing.normalize_hostname("example.com:8080"), "example.com")
        self.assertEqual(parsing.normalize_hostname("  EXAMPLE.COM  "), "example.com")
        self.assertEqual(parsing.normalize_hostname(""), "")

    def test_keeps_cidr_prefix(self):
        self.assertEqual(parsing.normalize_hostname("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(parsing.normalize_hostname("2001:db8::/32"), "2001:db8::/32")

    def test_keeps_bare_ipv6(self):
        self.assertEqual(parsing.normalize_hostname("2001:db8::1"), "2001:db8::1")
        self.assertEqual(parsing.normalize_hostname("::1"), "::1")

    def test_bracketed_ipv6_with_port_and_url(self):
        self.assertEqual(parsing.normalize_hostname("[2001:db8::1]:8443"), "2001:db8::1")
        self.assertEqual(parsing.normalize_hostname("http://[2001:db8::1]:8080/x"), "2001:db8::1")

    def test_ipv4_with_port(self):
        self.assertEqual(parsing.normalize_hostname("192.168.1.1:443"), "192.168.1.1")


class ValidateCidrTests(unittest.TestCase):
    def test_accepts_cidr(self):
        self.assertTrue(parsing.validate_cidr("10.0.0.0/24"))
        self.assertTrue(parsing.validate_cidr("2001:db8::/32"))
        # Host bits set is still accepted (strict=False semantics)
        self.assertTrue(parsing.validate_cidr("10.0.0.5/24"))

    def test_rejects_plain_ip(self):
        self.assertFalse(parsing.validate_cidr("192.168.1.1"))
        self.assertFalse(parsing.validate_cidr("2001:db8::1"))

    def test_rejects_garbage(self):
        self.assertFalse(parsing.validate_cidr("10.0.0.0/33"))
        self.assertFalse(parsing.validate_cidr("example.com/24"))


class CategorizeTargetsTests(unittest.TestCase):
    def test_cidr_is_categorized_as_cidr(self):
        result = parsing.categorize_targets(["10.0.0.0/24"])
        self.assertEqual(result["cidrs"], ["10.0.0.0/24"])
        self.assertEqual(result["ips"], [])

    def test_plain_ip_is_categorized_as_ip(self):
        result = parsing.categorize_targets(["192.168.1.1"])
        self.assertEqual(result["ips"], ["192.168.1.1"])
        self.assertEqual(result["cidrs"], [])

    def test_ipv6_is_categorized_as_ip(self):
        result = parsing.categorize_targets(["2001:db8::1", "[::1]:80"])
        self.assertEqual(sorted(result["ips"]), ["2001:db8::1", "::1"])
        self.assertEqual(result["invalid"], [])

    def test_ipv6_cidr(self):
        result = parsing.categorize_targets(["2001:db8::/120", "2001:db8::/32"])
        self.assertEqual(result["cidrs"], ["2001:db8::/120"])
        self.assertEqual(result["invalid"], ["2001:db8::/32"])

    def test_domains_and_subdomains(self):
        result = parsing.categorize_targets(["https://example.com/", "api.example.com:8080"])
        self.assertEqual(result["domains"], ["example.com"])
        self.assertEqual(result["subdomains"], ["api.example.com"])


class ParseInputTests(unittest.TestCase):
    def test_mixed_input(self):
        text = """
        # comment
        example.com
        api.test.com
        192.168.1.1, 10.0.0.0/24
        2001:db8::1
        """
        result = parsing.parse_input(text)
        self.assertEqual(result["domains"], ["example.com"])
        self.assertEqual(result["subdomains"], ["api.test.com"])
        self.assertEqual(sorted(result["ips"]), ["192.168.1.1", "2001:db8::1"])
        self.assertEqual(result["cidrs"], ["10.0.0.0/24"])
        self.assertEqual(result["invalid"], [])


class ExpandCidrTests(unittest.TestCase):
    def test_expand(self):
        self.assertEqual(parsing.expand_cidr("192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(parsing.expand_cidr("10.0.0.0/31"), ["10.0.0.0", "10.0.0.1"])
        self.assertEqual(parsing.expand_cidr("192.168.1.1/32"), ["192.168.1.1"])
        self.assertEqual(parsing.expand_cidr("nope"), [])

    def test_oversized_cidr_is_rejected(self):
        self.assertEqual(len(parsing.expand_cidr("10.0.0.0/20")), 4094)
        self.assertEqual(parsing.expand_cidr("10.0.0.0/19"), [])
        self.assertEqual(parsing.expand_cidr("2001:db8::/64"), [])

    def test_oversized_cidr_is_categorized_invalid(self):
        result = parsing.categorize_targets(["10.0.0.0/8", "10.1.0.0/20"])
        self.assertEqual(result["invalid"], ["10.0.0.0/8"])
        self.assertEqual(result["cidrs"], ["10.1.0.0/20"])


if __name__ == "__main__":
    unittest.main()
