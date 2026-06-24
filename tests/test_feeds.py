"""Tests for the TI feed engine — no network required (uses fixture data)."""

import ipaddress
import time
from pathlib import Path

import pytest

from guardian.intel.feeds import (
    FeedDefinition,
    FeedIndex,
    IOCMatch,
    _parse_line,
    _parse_csv_threatfox,
    _parse_into_index,
    _is_fresh,
    feed_status,
)


# ─── Parse helpers ────────────────────────────────────────────────────────────

def test_parse_line_strips_comments():
    raw = b"# header comment\n1.2.3.4\n5.6.7.8\n"
    result = list(_parse_line(raw, comment="#"))
    assert result == ["1.2.3.4", "5.6.7.8"]


def test_parse_line_skips_blank():
    raw = b"1.2.3.4\n\n  \n9.9.9.9\n"
    result = list(_parse_line(raw))
    assert "1.2.3.4" in result
    assert "9.9.9.9" in result
    assert "" not in result


def test_parse_line_inline_comment():
    raw = b"1.2.3.4 # Emotet C2\n"
    result = list(_parse_line(raw, comment="#"))
    assert result == ["1.2.3.4"]


def test_parse_csv_threatfox():
    # Simulate ThreatFox CSV with 9 header rows then data
    header = ("# comment\n" * 9).encode()
    data = b'"2024-01-01","Emotet","1.2.3.4:443","ip:port","malware"\n'
    raw = header + data
    rows = list(_parse_csv_threatfox(raw, skip_rows=9))
    assert len(rows) == 1
    ioc, family = rows[0]
    assert ioc == "1.2.3.4"
    assert family == "Emotet"


def test_parse_csv_threatfox_domain():
    header = ("# x\n" * 9).encode()
    data = b'"2024-01-01","QakBot","evil.example.com","domain","malware"\n'
    raw = header + data
    rows = list(_parse_csv_threatfox(raw, skip_rows=9))
    assert rows[0] == ("evil.example.com", "QakBot")


# ─── FeedIndex lookup ─────────────────────────────────────────────────────────

def _make_index_with(*matches: IOCMatch) -> FeedIndex:
    idx = FeedIndex()
    for m in matches:
        idx._add(m.ioc, m)
    return idx


def test_lookup_ip_exact():
    m = IOCMatch(ioc="1.2.3.4", ioc_type="ip", feed="TestFeed", confidence=90)
    idx = _make_index_with(m)
    results = idx.lookup_ip("1.2.3.4")
    assert len(results) == 1
    assert results[0].feed == "TestFeed"


def test_lookup_ip_not_found():
    idx = FeedIndex()
    assert idx.lookup_ip("9.9.9.9") == []


def test_lookup_domain_exact():
    m = IOCMatch(ioc="evil.com", ioc_type="domain", feed="URLhaus", confidence=88)
    idx = _make_index_with(m)
    assert len(idx.lookup_domain("evil.com")) == 1


def test_lookup_domain_subdomain_matches_parent():
    m = IOCMatch(ioc="evil.com", ioc_type="domain", feed="URLhaus", confidence=88)
    idx = _make_index_with(m)
    # sub.evil.com should match evil.com
    results = idx.lookup_domain("sub.evil.com")
    assert len(results) == 1


def test_lookup_domain_case_insensitive():
    m = IOCMatch(ioc="evil.com", ioc_type="domain", feed="TestFeed", confidence=80)
    idx = _make_index_with(m)
    assert len(idx.lookup_domain("EVIL.COM")) == 1


def test_lookup_hash():
    h = "a" * 64
    m = IOCMatch(ioc=h, ioc_type="hash", feed="MalwareBazaar", confidence=95)
    idx = _make_index_with(m)
    assert len(idx.lookup_hash(h)) == 1
    assert idx.lookup_hash("b" * 64) == []


def test_lookup_url_extracts_domain():
    m = IOCMatch(ioc="evil.com", ioc_type="domain", feed="URLhaus", confidence=88)
    idx = _make_index_with(m)
    results = idx.lookup_url("http://evil.com/payload.exe")
    assert len(results) == 1


def test_lookup_auto_detects_ip():
    m = IOCMatch(ioc="5.5.5.5", ioc_type="ip", feed="Feodo", confidence=92)
    idx = _make_index_with(m)
    assert len(idx.lookup("5.5.5.5")) == 1


def test_lookup_auto_detects_hash():
    h = "f" * 64
    m = IOCMatch(ioc=h, ioc_type="hash", feed="MalwareBazaar", confidence=95)
    idx = _make_index_with(m)
    assert len(idx.lookup(h)) == 1


def test_lookup_cidr_membership():
    idx = FeedIndex()
    net = ipaddress.ip_network("10.0.0.0/8", strict=False)
    idx.networks.append(net)
    m = IOCMatch(ioc="10.0.0.0/8", ioc_type="ip", feed="Spamhaus", confidence=85)
    idx._add("10.0.0.0/8", m)
    results = idx.lookup_ip("10.1.2.3")
    assert len(results) == 1
    assert results[0].feed == "Spamhaus"


def test_total_iocs_count():
    m1 = IOCMatch(ioc="1.1.1.1", ioc_type="ip", feed="A", confidence=80)
    m2 = IOCMatch(ioc="2.2.2.2", ioc_type="ip", feed="B", confidence=80)
    idx = _make_index_with(m1, m2)
    assert idx.total_iocs == 2


# ─── Feed parser integration ──────────────────────────────────────────────────

def test_parse_into_index_line_feed():
    feed = FeedDefinition(
        name="TestFeed",
        url="http://example.com",
        ioc_type="ip",
        parser="line",
        parser_kwargs={"comment": "#"},
    )
    raw = b"# header\n1.2.3.4\n5.6.7.8\n"
    idx = FeedIndex()
    _parse_into_index(feed, raw, idx)
    assert len(idx.lookup_ip("1.2.3.4")) == 1
    assert len(idx.lookup_ip("5.6.7.8")) == 1


def test_parse_into_index_threatfox():
    feed = FeedDefinition(
        name="ThreatFox-IPs",
        url="http://example.com",
        ioc_type="ip",
        parser="csv_threatfox",
        parser_kwargs={"skip_rows": 2},
    )
    raw = b"# h1\n# h2\n\"2024\",\"Emotet\",\"3.3.3.3:443\",\"ip:port\",\"mal\"\n"
    idx = FeedIndex()
    _parse_into_index(feed, raw, idx)
    results = idx.lookup_ip("3.3.3.3")
    assert len(results) == 1
    assert results[0].malware_family == "Emotet"


# ─── Cache freshness ──────────────────────────────────────────────────────────

def test_is_fresh_new_file(tmp_path):
    f = tmp_path / "test.cache"
    f.write_bytes(b"data")
    assert _is_fresh(f, ttl=3600)


def test_is_fresh_old_file(tmp_path):
    f = tmp_path / "test.cache"
    f.write_bytes(b"data")
    # Make it look old
    old_time = time.time() - 7200
    import os
    os.utime(f, (old_time, old_time))
    assert not _is_fresh(f, ttl=3600)


def test_is_fresh_missing_file(tmp_path):
    assert not _is_fresh(tmp_path / "nonexistent.cache", ttl=3600)
