"""Tests for 5-stage cross-source verification pipeline."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from guardian.intel.cross_verify import (
    classify,
    parse_alert,
    route_sources,
    verify_alert_dict,
    verify_alerts,
    CheckResult,
    ParsedAlert,
)


class TestParseAlert(unittest.TestCase):
    def test_parse_url_alert(self):
        alert = {
            "id": "a1",
            "title": "URLhaus: malware_download",
            "description": "Harmful website",
            "evidence": "http://evil.example/bin.sh",
            "timestamp": 1_700_000_000.0,
            "metadata": {
                "ioc_type": "url",
                "ioc_value": "http://evil.example/bin.sh",
                "global_source": "URLhaus",
                "plain_summary": "A harmful website was reported",
            },
        }
        p = parse_alert(alert)
        self.assertEqual(p.ioc_type, "url")
        self.assertEqual(p.ioc_value, "http://evil.example/bin.sh")
        self.assertEqual(p.source_raised, "URLhaus")
        self.assertIn("URLhaus", p.claim)

    def test_infer_cve(self):
        p = parse_alert({"id": "c1", "evidence": "CVE-2024-1234", "metadata": {}})
        self.assertEqual(p.ioc_type, "cve")
        self.assertEqual(p.ioc_value, "CVE-2024-1234")


class TestRouteSources(unittest.TestCase):
    def test_ip_routes_abuseipdb_and_threatfox(self):
        p = ParsedAlert("x", "ip", "203.0.113.1", "c", None, None, "", {}, "", "")
        names = [r.name for r in route_sources(p)]
        self.assertIn("AbuseIPDB", names)
        self.assertIn("ThreatFox", names)

    def test_cve_routes_kev_and_nvd(self):
        p = ParsedAlert("x", "cve", "CVE-2024-9999", "c", None, None, "", {}, "", "")
        names = [r.name for r in route_sources(p)]
        self.assertIn("CISA KEV", names)
        self.assertIn("NVD", names)


class TestClassify(unittest.TestCase):
    def test_cisa_kev_critical_override(self):
        p = ParsedAlert("x", "cve", "CVE-2024-1", "c", None, None, "", {}, "", "")
        checks = [
            CheckResult(
                "CISA KEV", "GET kev", "GET", "hit",
                "cveID=CVE-2024-1", "in KEV", reference="https://cisa.gov",
                is_authoritative_hit=True,
            )
        ]
        cls, conf, _, rationale, refs = classify(p, checks)
        self.assertEqual(cls, "GENUINE")
        self.assertEqual(conf, "Critical")
        self.assertTrue(refs)

    def test_false_positive_on_refute_only(self):
        p = ParsedAlert("x", "hash", "a" * 64, "c", None, None, "", {}, "", "")
        checks = [
            CheckResult(
                "MalwareBazaar", "POST mb", "POST", "refute",
                "query_status=hash_not_found", "not found", is_refute=True,
            )
        ]
        cls, _, _, _, refs = classify(p, checks)
        self.assertEqual(cls, "FALSE POSITIVE")
        self.assertEqual(refs, [])

    def test_genuine_requires_reference(self):
        p = ParsedAlert("x", "url", "http://x", "c", None, None, "", {}, "", "")
        checks = [
            CheckResult(
                "URLhaus", "POST uh", "POST", "hit",
                "", "hit without dp", is_authoritative_hit=True,
            )
        ]
        cls, _, _, _, refs = classify(p, checks)
        self.assertEqual(cls, "UNVERIFIED")
        self.assertEqual(refs, [])


class TestVerifyPipeline(unittest.TestCase):
    @patch("guardian.intel.cross_verify.http_post_json")
    @patch("guardian.intel.cross_verify._abuse_ch_key", return_value="test-key")
    def test_urlhaus_genuine_with_reference(self, _key, mock_post):
        mock_post.return_value = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
        }
        alert = {
            "id": "u1",
            "evidence": "http://evil.example/x",
            "metadata": {"ioc_type": "url", "ioc_value": "http://evil.example/x"},
        }
        result = verify_alert_dict(alert)
        self.assertEqual(result.classification, "GENUINE")
        self.assertTrue(result.references)
        self.assertFalse(result.checklist.get("21_genuine_without_reference"))

    @patch("guardian.intel.cross_verify._cisa_kev_data")
    def test_cve_in_kev(self, mock_kev):
        mock_kev.return_value = {
            "vulnerabilities": [{"cveID": "CVE-2024-7777", "vendorProject": "Acme", "notes": "https://x"}]
        }
        alert = {"id": "c1", "evidence": "CVE-2024-7777", "metadata": {"ioc_type": "cve"}}
        result = verify_alert_dict(alert)
        self.assertEqual(result.classification, "GENUINE")
        self.assertEqual(result.confidence, "Critical")

    @patch("guardian.intel.cross_verify._urlhaus_csv_text")
    def test_urlhaus_csv_genuine_without_api_key(self, mock_csv):
        mock_csv.return_value = (
            '"1","2026-06-18","http://evil.example/x","online","2026-06-18",'
            '"malware_download","elf","https://urlhaus.abuse.ch/url/1/","test"\n'
        )
        alert = {
            "id": "u1",
            "evidence": "http://evil.example/x",
            "metadata": {"ioc_type": "url", "ioc_value": "http://evil.example/x"},
        }
        with patch("guardian.intel.cross_verify._usable_abuse_ch_key", return_value=""):
            result = verify_alert_dict(alert)
        self.assertEqual(result.classification, "GENUINE")
        self.assertTrue(result.references)

    @patch("guardian.intel.cross_verify._usable_abuse_ch_key", return_value="")
    def test_placeholder_key_uses_csv_not_skip(self, _key):
        with patch("guardian.intel.cross_verify._check_urlhaus_url_csv") as mock_csv:
            from guardian.intel.cross_verify import CheckResult, _check_urlhaus_url
            mock_csv.return_value = CheckResult(
                "URLhaus", "GET csv", "GET", "hit", "url_status=online", "ok",
                reference="https://urlhaus.abuse.ch/", is_authoritative_hit=True,
            )
            r = _check_urlhaus_url("http://x")
            self.assertEqual(r.status, "hit")

    def test_openphish_not_false_positive_when_urlhaus_misses(self):
        from guardian.intel.cross_verify import classify, ParsedAlert, CheckResult

        p = ParsedAlert("x", "url", "https://phish.example/", "OpenPhish", None, None, "OpenPhish", {}, "", "")
        checks = [
            CheckResult("URLhaus", "GET csv", "GET", "refute", "not_in_csv", "miss", is_refute=True),
            CheckResult(
                "OpenPhish", "GET feed", "GET", "hit", "on_active_phishing_feed", "ok",
                reference="https://phish.example/", is_authoritative_hit=True,
            ),
        ]
        cls, conf, _, _, refs = classify(p, checks)
        self.assertEqual(cls, "GENUINE")
        self.assertTrue(refs)

    @patch("guardian.intel.cross_verify._openphish_urls")
    def test_openphish_alert_genuine(self, mock_feed):
        mock_feed.return_value = {"https://www.instagramincreasefollowers.blogspot.com/"}
        alert = {
            "id": "op1",
            "evidence": "https://www.instagramincreasefollowers.blogspot.com/",
            "title": "OpenPhish: active phishing URL",
            "metadata": {
                "ioc_type": "url",
                "ioc_value": "https://www.instagramincreasefollowers.blogspot.com/",
                "global_source": "OpenPhish",
            },
        }
        result = verify_alert_dict(alert)
        self.assertEqual(result.classification, "GENUINE")
        self.assertIn("OpenPhish", result.row.get("reference", ""))
        from guardian.intel.cross_verify import key_status_message
        import os
        old = os.environ.get("ABUSE_CH_AUTH_KEY")
        os.environ["ABUSE_CH_AUTH_KEY"] = "your-real-key"
        try:
            self.assertIn("placeholder", (key_status_message() or "").lower())
        finally:
            if old is None:
                os.environ.pop("ABUSE_CH_AUTH_KEY", None)
            else:
                os.environ["ABUSE_CH_AUTH_KEY"] = old

    def test_batch_summary_counts(self):
        with patch("guardian.intel.cross_verify.verify_alert_dict") as mock_v:
            from guardian.intel.cross_verify import AlertVerification

            def fake(alert):
                cls = alert.get("_cls", "UNVERIFIED")
                return AlertVerification(
                    parsed=parse_alert(alert),
                    routes=[],
                    checks=[],
                    classification=cls,
                    confidence="Low",
                    references=[],
                    skipped_sources=[],
                    corroboration_count=0,
                    rationale="",
                    checklist={},
                    row={"classification": cls},
                )

            mock_v.side_effect = fake
            summary = verify_alerts([
                {"id": "1", "_cls": "GENUINE"},
                {"id": "2", "_cls": "UNVERIFIED"},
                {"id": "3", "_cls": "FALSE POSITIVE"},
            ])
            self.assertEqual(summary.total, 3)
            self.assertEqual(summary.genuine, 1)
            self.assertEqual(summary.unverified, 1)
            self.assertEqual(summary.false_positive, 1)


if __name__ == "__main__":
    unittest.main()
