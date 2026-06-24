"""Tests for global threat ticker."""

from unittest.mock import patch

from guardian.engine.alert import Severity
from guardian.intel.global_ticker import (
    GlobalThreatItem,
    GlobalThreatTicker,
    classify_severity,
    fetch_blocklist_de,
    fetch_sslbl,
    fetch_tor_exits,
    item_to_alert,
    normalize_ioc,
    push_payload_to_alert,
)


def test_item_to_alert():
    item = GlobalThreatItem(
        source="ThreatFox",
        ioc_type="ip",
        value="203.0.113.1",
        title="Test global",
        description="desc",
        malware_family="Emotet",
    )
    alert = item_to_alert(item)
    assert alert.module == "global_feed"
    assert alert.severity == Severity.MEDIUM
    assert alert.metadata["global_source"] == "ThreatFox"


def test_push_payload():
    alert = push_payload_to_alert({
        "source": "my-siem",
        "title": "Brute force",
        "severity": "HIGH",
        "ioc_type": "ip",
        "ioc_value": "198.51.100.1",
    })
    assert alert.title == "Brute force"
    assert alert.severity == Severity.HIGH


def test_ticker_dedup():
    seen = []

    def cb(a):
        seen.append(a)

    t = GlobalThreatTicker(cb, interval_secs=9999, bootstrap=False)
    item = GlobalThreatItem(
        source="X", ioc_type="ip", value="1.2.3.4",
        title="t", description="d", external_id="x:1",
    )
    t._remember(item.dedup_key)
    assert not t._remember(item.dedup_key)


def test_classify_severity_distribution():
    assert classify_severity("OpenPhish") == Severity.LOW
    assert classify_severity("MalwareBazaar", "", "hash", "abuse_ch") == Severity.LOW
    assert classify_severity("MalwareBazaar", "", "hash", "emotet") == Severity.HIGH
    assert classify_severity("URLhaus", "malware_download", "url", "ua-wget", ("ua-wget", "elf")) == Severity.LOW
    assert classify_severity("URLhaus", "malware_download", "url", "stealer", ("stealer",)) == Severity.HIGH
    assert classify_severity("ThreatFox", "phishing", "url", "", (), 40) == Severity.LOW
    assert classify_severity("CISA-KEV") == Severity.CRITICAL


def test_new_open_feed_severity():
    assert classify_severity("PhishTank", "phishing", "url", "PayPal") == Severity.LOW
    assert classify_severity("Feodo Tracker", "botnet_cc", "ip", "Emotet", ("online",)) == Severity.HIGH
    assert classify_severity("Spamhaus DROP", "hijacked_network", "cidr", "SBL123") == Severity.MEDIUM
    assert classify_severity("URLhaus-Hosts", "malware_host", "domain", "evil.example") == Severity.LOW
    assert classify_severity("SSLBL", "malicious_ssl", "ip", "Dridex") == Severity.MEDIUM
    assert classify_severity("blocklist.de", "brute_force", "ip", "") == Severity.LOW
    assert classify_severity("Tor Exit Nodes", "tor_exit", "ip", "") == Severity.LOW


def test_normalize_ioc():
    assert normalize_ioc("url", "https://Evil.COM/path/") == "url:https://evil.com/path"
    assert normalize_ioc("phishing", "https://Evil.COM/path/") == "url:https://evil.com/path"
    assert normalize_ioc("ip", " 1.2.3.4 ") == "ip:1.2.3.4"
    assert normalize_ioc("hash", "ABC") == "hash:abc"
    assert normalize_ioc("cve", "cve-2024-1234") == "cve:CVE-2024-1234"


def test_cross_source_ioc_dedup():
    seen = []

    def cb(a):
        seen.append(a)

    t = GlobalThreatTicker(cb, interval_secs=9999, bootstrap=False)
    a = GlobalThreatItem(
        source="OpenPhish", ioc_type="phishing", value="https://evil.test/x",
        title="a", description="d", external_id="op:1",
    )
    b = GlobalThreatItem(
        source="PhishTank", ioc_type="url", value="https://evil.test/x/",
        title="b", description="d", external_id="pt:2",
    )
    assert t._remember(a.dedup_key)
    assert t._remember_ioc(a)
    assert t._remember(b.dedup_key)
    assert not t._remember_ioc(b)


def test_fetch_all_global_threats_tracks_failures():
    from guardian.intel import global_ticker as gt

    def boom(*_args, **_kwargs):
        raise ConnectionError("reset")

    with patch.object(gt, "fetch_threatfox_export", side_effect=boom), patch.object(
        gt, "fetch_urlhaus_export", return_value=[]
    ), patch.object(gt, "fetch_malwarebazaar_export", return_value=[]), patch.object(
        gt, "fetch_cisa_kev", return_value=[]
    ), patch.object(gt, "fetch_openphish", return_value=[]), patch.object(
        gt, "fetch_feodo_tracker", return_value=[]
    ), patch.object(gt, "fetch_phishtank", return_value=[]), patch.object(
        gt, "fetch_spamhaus_drop", return_value=[]
    ), patch.object(gt, "fetch_urlhaus_hosts", return_value=[]), patch.object(
        gt, "fetch_sslbl", return_value=[]
    ), patch.object(gt, "fetch_blocklist_de", return_value=[]), patch.object(
        gt, "fetch_tor_exits", return_value=[]
    ):
        items, ok, failed = gt.fetch_all_global_threats(per_source_quota=1)
    assert items == []
    assert "ThreatFox" in failed
    assert "URLhaus" in ok


def test_fetch_sslbl_parses_csv():
    csv_text = (
        "# comment\n"
        "First Seen UTC,DstIP,DstPort,Listing Reason\n"
        "2024-01-01 00:00:00,203.0.113.50,443,Dridex\n"
    )
    with patch("guardian.intel.global_ticker.http_get", return_value=csv_text.encode()):
        items = fetch_sslbl(limit=5)
    assert len(items) == 1
    assert items[0].source == "SSLBL"
    assert items[0].value == "203.0.113.50"
    assert items[0].severity == Severity.MEDIUM


def test_fetch_blocklist_de_parses_ips():
    text = "# comment\n1.2.3.4\n5.6.7.8\n"
    with patch("guardian.intel.global_ticker.http_get", return_value=text.encode()):
        items = fetch_blocklist_de(limit=5)
    assert len(items) == 2
    assert items[0].source == "blocklist.de"
    assert items[0].severity == Severity.LOW


def test_fetch_tor_exits_parses_ips():
    text = "# Tor exits\n9.9.9.9\n"
    with patch("guardian.intel.global_ticker.http_get", return_value=text.encode()):
        items = fetch_tor_exits(limit=5)
    assert len(items) == 1
    assert items[0].source == "Tor Exit Nodes"
    assert items[0].severity == Severity.LOW
