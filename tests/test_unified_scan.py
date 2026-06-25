"""Tests for unified free IOC scan."""

from guardian.intel.unified_scan import classify_ioc, scan_ioc


def test_classify_ioc_types():
    assert classify_ioc("1.2.3.4") == "ip"
    assert classify_ioc("https://evil.example/path") == "url"
    assert classify_ioc("a" * 64) == "hash"
    assert classify_ioc("evil.example") == "domain"


def test_scan_ioc_clean_local(monkeypatch):
    class _Idx:
        total_iocs = 1000

        def lookup(self, value):
            return []

    class _Susp:
        category = "test"
        reason = "r"
        confidence = 50
        example_abuse = "x"

    monkeypatch.setattr("guardian.intel.unified_scan._scan_local", lambda v: ([], None))
    monkeypatch.setattr("guardian.intel.unified_scan._scan_threatfox", lambda v: {"source": "ThreatFox", "hit": False})
    monkeypatch.setattr("guardian.intel.feeds.get_index", lambda: _Idx())
    out = scan_ioc("127.0.0.1")
    assert out["verdict"] == "CLEAN"
    assert out["engine"] == "guardian_unified_free"
