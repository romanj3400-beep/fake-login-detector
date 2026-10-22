
import unittest
from unittest.mock import patch

from main import get_url, analyze_url


class TestGetUrl(unittest.TestCase):

    def test_valid_url(self):
        with patch("builtins.input", return_value="https://example.com"):
            url = get_url()

        self.assertEqual(url, "https://example.com")

    def test_empty_url(self):
        with patch("builtins.input", return_value=""):
            with self.assertRaises(SystemExit):
                get_url()

    def test_url_with_spaces(self):
        with patch("builtins.input", return_value="https://example .com"):
            with self.assertRaises(SystemExit):
                get_url()


class TestAnalyzeUrl(unittest.TestCase):

    def test_official_brand_has_no_warnings(self):
        result = analyze_url("https://google.com")

        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_factors"], [])

    def test_official_brand_domain(self):
        result = analyze_url("https://google.com")

        self.assertEqual(result["score"], 0)
        self.assertFalse(
            any("Suspicious domain" in warning
                for warning in result["warnings"])
        )

    def test_official_brand_subdomain(self):
        result = analyze_url("https://accounts.google.com")

        self.assertEqual(result["score"], 0)
        self.assertFalse(
            any("Suspicious domain" in warning
                for warning in result["warnings"])
        )

    def test_misleading_brand_domain(self):
        result = analyze_url("https://fake-google.com")

        self.assertEqual(result["score"], 1)
        self.assertTrue(
            any("Suspicious domain" in warning
                for warning in result["warnings"])
        )


    def test_normal_url(self):
        result = analyze_url("https://example.com")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["warnings"], [])

    def test_ip_address(self):
        result = analyze_url("https://192.168.1.100")

        self.assertEqual(result["score"], 1)
        self.assertTrue(
            any("IP address" in warning for warning in result["warnings"])
        )

    def test_at_symbol(self):
        result = analyze_url("https://example.com@google.com")

        self.assertEqual(result["score"], 1)

    def test_brand_impersonation(self):
        result = analyze_url("https://google.com.fake-site.com")

        self.assertEqual(result["score"], 1)
        self.assertTrue(
            any("Suspicious domain" in warning
                for warning in result["warnings"])
        )

    def test_keyword_does_not_increase_score(self):
        result = analyze_url("https://example.com/login")

        self.assertEqual(result["score"], 0)
        self.assertTrue(
            any("Informational keyword" in warning
                for warning in result["warnings"])
        )

    def test_consecutive_dots(self):
        result = analyze_url("https://example..com")

        self.assertEqual(result["score"], 1)

    
    def test_risk_factors_match_score(self):
        result = analyze_url("https://192.168.1.100")

        self.assertEqual(result["score"], 1)
        self.assertEqual(len(result["risk_factors"]), 1)
        self.assertTrue(
            any("Hostname is an IP address" in factor
                for factor in result["risk_factors"])
        )

    def test_keyword_is_not_a_risk_factor(self):
        result = analyze_url("https://example.com/login")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_factors"], [])
        self.assertTrue(
            any(
                "Informational keyword" in warning
                for warning in result["warnings"]
            )
        )


if __name__ == "__main__":
    unittest.main()
