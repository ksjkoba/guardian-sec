"""Tests for the IOC enrichment layer — no network required."""

import pytest
from guardian.engine.alert import Alert, Severity
from guardian.intel.feeds import FeedIndex, IOCMatch
from guardian.intel.enricher import enrich_alert, AlertEnricher, _extract_iocs_from_alert


def _make_index(*matches: IOCMatch) -> FeedIndex:
    idx = FeedIndex()
    for m in matches:
        idx._add(m.ioc, m)
    return idx


def _make_alert(**kwargs) -> Alert:
    defaults = dict(
        module="network_monitor",
        title="Test",
        description="test",
        severity=Severity.LOW,
    )
    defaults.update(kwargs)
    return Alert(**defaults)


# ─── IOC extraction ───────────────────────────────────────────────────────────

def test_extracts_ip_from_description():
    a = _make_alert(description="Connection from 1.2.3.4 blocked")
    iocs = _extract_iocs_from_alert(a)
    assert "1.2.3.4" in iocs["ip"]


def test_extracts_ip_from_evidence():
    a = _make_alert(evidence="SYN flood from 9.8.7.6")
    iocs = _extract_iocs_from_alert(a)
    assert "9.8.7.6" in iocs["ip"]


def test_extracts_hash_from_evidence():
    h = "a" * 64
    a = _make_alert(evidence=f"MD5: {h}")
    iocs = _extract_iocs_from_alert(a)
    assert h in iocs["hash"]


def test_extracts_url():
    a = _make_alert(description="Beacon to http://evil.com/c2")
    iocs = _extract_iocs_from_alert(a)
    assert any("evil.com" in u for u in iocs["url"])


def test_extracts_ip_from_metadata():
    a = _make_alert(metadata={"src_ip": "5.5.5.5"})
    iocs = _extract_iocs_from_alert(a)
    assert "5.5.5.5" in iocs["ip"]


# ─── Enrichment ──────────────────────────────────────────────────────────────

def test_no_match_returns_empty():
    idx = FeedIndex()
    a = _make_alert(description="Normal login from 192.168.1.1")
    matches = enrich_alert(a, idx)
    assert matches == []
    assert "ioc_matches" not in a.metadata


def test_match_annotates_metadata():
    m = IOCMatch(ioc="1.2.3.4", ioc_type="ip", feed="Feodo", confidence=90)
    idx = _make_index(m)
    a = _make_alert(description="Connection from 1.2.3.4")
    matches = enrich_alert(a, idx)
    assert len(matches) == 1
    assert "ioc_matches" in a.metadata
    assert a.metadata["ioc_matches"][0]["feed"] == "Feodo"


def test_match_sets_ioc_tag():
    m = IOCMatch(ioc="6.6.6.6", ioc_type="ip", feed="Feodo-C2-IPs", confidence=90)
    idx = _make_index(m)
    a = _make_alert(description="Traffic to 6.6.6.6")
    enrich_alert(a, idx)
    assert "IOC:Feodo-C2-IPs" in a.metadata.get("ioc_tag", "")


def test_high_confidence_upgrades_severity():
    m = IOCMatch(ioc="7.7.7.7", ioc_type="ip", feed="Feodo", confidence=95)
    idx = _make_index(m)
    a = _make_alert(severity=Severity.LOW, description="Traffic to 7.7.7.7")
    enrich_alert(a, idx)
    assert a.severity == Severity.MEDIUM
    assert a.metadata.get("severity_upgraded") is True


def test_low_confidence_does_not_upgrade():
    m = IOCMatch(ioc="8.8.8.8", ioc_type="ip", feed="TestFeed", confidence=50)
    idx = _make_index(m)
    a = _make_alert(severity=Severity.LOW, description="Traffic to 8.8.8.8")
    enrich_alert(a, idx)
    assert a.severity == Severity.LOW
    assert not a.metadata.get("severity_upgraded")


def test_critical_does_not_upgrade_further():
    m = IOCMatch(ioc="9.9.9.9", ioc_type="ip", feed="Feodo", confidence=99)
    idx = _make_index(m)
    a = _make_alert(severity=Severity.CRITICAL, description="Traffic to 9.9.9.9")
    enrich_alert(a, idx)
    assert a.severity == Severity.CRITICAL


def test_malware_family_in_tag():
    m = IOCMatch(ioc="1.1.1.2", ioc_type="ip", feed="ThreatFox", malware_family="Emotet", confidence=92)
    idx = _make_index(m)
    a = _make_alert(description="Beacon to 1.1.1.2")
    enrich_alert(a, idx)
    assert "Emotet" in a.metadata.get("ioc_tag", "")


def test_multiple_matches_all_annotated():
    m1 = IOCMatch(ioc="2.2.2.2", ioc_type="ip", feed="Feodo", confidence=90)
    m2 = IOCMatch(ioc="2.2.2.2", ioc_type="ip", feed="ThreatFox", malware_family="QakBot", confidence=88)
    idx = _make_index(m1, m2)
    a = _make_alert(description="Traffic to 2.2.2.2")
    matches = enrich_alert(a, idx)
    assert len(matches) == 2
    feeds = {m["feed"] for m in a.metadata["ioc_matches"]}
    assert "Feodo" in feeds
    assert "ThreatFox" in feeds


# ─── AlertEnricher wrapper ───────────────────────────────────────────────────

def test_alert_enricher_callable():
    m = IOCMatch(ioc="3.3.3.3", ioc_type="ip", feed="Test", confidence=85)
    idx = _make_index(m)
    enricher = AlertEnricher(idx)
    a = _make_alert(description="Hit from 3.3.3.3")
    matches = enricher(a)
    assert len(matches) == 1


def test_alert_enricher_total_iocs():
    m1 = IOCMatch(ioc="a.com", ioc_type="domain", feed="X", confidence=80)
    m2 = IOCMatch(ioc="b.com", ioc_type="domain", feed="Y", confidence=80)
    idx = _make_index(m1, m2)
    enricher = AlertEnricher(idx)
    assert enricher.total_iocs == 2
